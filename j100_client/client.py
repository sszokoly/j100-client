"""Synchronous and asynchronous J100 Web UI clients."""

import asyncio
import base64
import hashlib
import re
import time
from pathlib import Path
from typing import Any, Optional
from xml.etree import ElementTree

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import (
    AuthenticationError,
    ConfirmationRequiredError,
    PasswordValidationError,
    PhoneBusyError,
    ProtocolError,
    RestartTimeoutError,
    TransportError,
)
from .models import (
    J100Config,
    PacketCapture,
    PhoneReport,
    RestartResult,
    SipAccountStatus,
)
from .transport import AsyncTransport, SyncTransport

LOGIN_PATH = "/cgi-bin/J100WebServer.cgi?Operation=0"
LOGIN_POST_PATH = "/cgi-bin/J100WebServer.cgi?Operation=1"
SESSION_CHECK_PATH = "/cgi-bin/J100WebServer.cgi?Operation=33"
PHONE_STATUS_PATH = "/cgi-bin/J100WebServer.cgi?Operation=34"
RESTART_PATH = "/cgi-bin/J100WebServer.cgi?Operation=4"
FACTORY_RESET_PATH = "/cgi-bin/J100WebServer.cgi?Operation=5"
PHONE_REPORT_PATH = "/cgi-bin/J100WebServer.cgi?Operation=3"
PACKET_CAPTURE_PATH = "/GetPcap/"
STOP_PACKET_CAPTURE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=222"
PASSWORD_CHANGE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=212"
CONFIGURATION_SAVE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=3213"
SIP_GLOBAL_CONFIGURATION_SAVE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=3217"
SIP_CONFIGURATION_READ_PATH = "/cgi-bin/J100WebServer.cgi?Operation=6&pageId=7"
SIP_ACCOUNT_PATH = "/cgi-bin/J100WebServer.cgi?Operation=171"
SIP_LOGOUT_PATH = "/cgi-bin/J100WebServer.cgi?Operation=172"
TRUST_CERTIFICATE_UPLOAD_PATH = "/cgi-bin/J100WebServer.cgi?Operation=232"
TRUSTED_CERTIFICATES_READ_PATH = (
    "/cgi-bin/J100WebServer.cgi?Operation=6&pageId=13"
)
SNMP_CONFIGURATION_SAVE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=3222"
SNMP_CONFIGURATION_READ_PATH = (
    "/cgi-bin/J100WebServer.cgi?Operation=6&pageId=12"
)
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "27238"
PASSWORD_PATTERN = re.compile(
    r"^[A-Za-z0-9~!@#$%^&*_=+`|\\(){}\[\]:;'<>.,?/]{6,31}$"
)
PASSWORD_SPECIAL_CHARACTERS = "~!@#$%^&*_-+=`|\\(){}[]:;'<>.,?/"
PASSWORD_CHANGE_IV = bytes(
    [185, 81, 2, 73, 200, 160, 146, 101, 228, 36, 138, 96, 102, 0, 129, 7]
)
SERVER_CONFIGURATION_FIELDS = {
    "HTTPSRVR": "FileServerHttpDownloadList",
    "TLSSRVR": "FileServerTlsDownloadList",
    "HTTPDIR": "DirectoryForHttpDownload",
    "TLSDIR": "DirectoryForTlsDownload",
    "HTTPPORT": "PortForHttpDownload",
    "TLSPORT": "PortForTlsDownload",
    "DNSSRVR": "DnsServerList",
    "SNTPSRVR": "SntpServerList",
}
SNMP_CONFIGURATION_FIELDS = {
    "SNMPSTRING": "SnmpCommunityNameString",
    "SNMPADD": "AllowableSourceIpAddressesForSnmpQueries",
}
SIP_GLOBAL_FIELDS = {
    "SIPDOMAIN": "SipDomain",
    "ENABLE_PPM_SOURCED_SIPPROXYSRVR": "EnablePpmSipProxy",
    "SIP_CONTROLLER_LIST": "SipControllerList",
}
DEBUG_CONFIGURATION_FIELDS = {
    "SYSLOG_ENABLED": "SysLogEnabled",
    "LOGSRVR": "SysLogServerAddress",
    "LOGSRVR_SECURE": "LogServerSecure",
    "SYSLOG_LEVEL": "SysLogLevel",
    "LOG_CATEGORY": "LogCategoryList",
}
SNMP_COMMUNITY_PATTERN = re.compile(
    r"^[A-Za-z0-9~!@#$%^&*_=+`|\\(){}\[\]:;'<>.,?/]{0,32}$"
)


class _Protocol:
    def __init__(self, config: J100Config):
        self.config = config

    @property
    def login_headers(self) -> dict:
        return {
            "Origin": self.config.base_url,
            "Referer": self.config.base_url + LOGIN_PATH,
        }

    @property
    def request_headers(self) -> dict:
        return {
            "Cache-Control": "no-cache",
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url
            + "/cgi-bin/J100WebServer.cgi?Operation=10",
        }

    @property
    def password_change_headers(self) -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url
            + "/cgi-bin/J100WebServer.cgi?Operation=211",
        }

    def configuration_save_headers(self, page_operation: str) -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url
            + "/cgi-bin/J100WebServer.cgi?Operation="
            + page_operation,
        }

    @property
    def sip_account_headers(self) -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.config.base_url
            + "/cgi-bin/J100WebServer.cgi?Operation=17",
        }

    @staticmethod
    def _server_configuration_payload(
        settings: dict[str, Any], session_id: str
    ) -> dict:
        values = {
            form_field: settings.get(parameter)
            for parameter, form_field in SERVER_CONFIGURATION_FIELDS.items()
            if settings.get(parameter) is not None
        }
        if not values:
            raise ValueError("at least one server setting must be supplied")
        return {"RequiredAction": "-1", **values, "XToken": session_id}

    @staticmethod
    def _snmp_configuration_payload(
        settings: dict[str, Any], session_id: str
    ) -> dict:
        snmp_string = settings["SNMPSTRING"]
        snmp_addresses = settings["SNMPADD"]
        if snmp_string is None and snmp_addresses is None:
            raise ValueError("at least one SNMP setting must be supplied")
        if snmp_string is not None and not SNMP_COMMUNITY_PATTERN.fullmatch(
            snmp_string
        ):
            raise ValueError(
                "SNMPSTRING must contain 0-32 permitted J100 characters without spaces"
            )
        if snmp_addresses is not None and (
            len(snmp_addresses) > 255
            or any(character.isspace() for character in snmp_addresses)
        ):
            raise ValueError(
                "SNMPADD must contain at most 255 characters without whitespace"
            )
        values = {
            form_field: settings[parameter]
            for parameter, form_field in SNMP_CONFIGURATION_FIELDS.items()
            if settings[parameter] is not None
        }
        return {"RequiredAction": "-1", **values, "XToken": session_id}

    @staticmethod
    def _debug_configuration_payload(
        settings: dict[str, Any], session_id: str
    ) -> list[tuple[str, str]]:
        reset_to_default = settings["reset_to_default"]
        supplied = [
            parameter
            for parameter in (*DEBUG_CONFIGURATION_FIELDS, "AUTHCTRLSTAT")
            if settings[parameter] is not None
        ]
        if reset_to_default:
            if supplied:
                raise ValueError(
                    "reset_to_default cannot be combined with debug settings"
                )
            return [
                ("RequiredAction", "2"),
                ("SysLogServerAddress", ""),
                ("SysLogEnabled", "0"),
                ("SysLogLevel", "3"),
                ("LogCategoryList", ""),
                ("RequiredAction", "4"),
                ("LocalLogLevel", "3"),
                ("RequiredAction", "17"),
                ("AuthCtrlStat", "0"),
                ("XToken", session_id),
            ]
        if not supplied:
            raise ValueError("at least one debug setting must be supplied")

        values: dict[str, str] = {}
        for parameter in ("SYSLOG_ENABLED", "LOGSRVR_SECURE", "AUTHCTRLSTAT"):
            value = settings[parameter]
            if value is not None:
                normalized = {"yes": "1", "no": "0", "1": "1", "0": "0"}.get(
                    value.lower()
                )
                if normalized is None:
                    raise ValueError(f"{parameter} must be Yes, No, 1, or 0")
                values[parameter] = normalized
        level = settings["SYSLOG_LEVEL"]
        if level is not None:
            if level not in {str(value) for value in range(8)}:
                raise ValueError("SYSLOG_LEVEL must be an integer from 0 to 7")
            values["SYSLOG_LEVEL"] = level
        server = settings["LOGSRVR"]
        if server is not None:
            if len(server) > 255:
                raise ValueError("LOGSRVR must not exceed 255 characters")
            values["LOGSRVR"] = server
        categories = settings["LOG_CATEGORY"]
        if categories is not None:
            if any(character.isspace() for character in categories):
                raise ValueError("LOG_CATEGORY must not contain whitespace")
            values["LOG_CATEGORY"] = categories

        payload: list[tuple[str, str]] = []
        syslog_values = [
            (form_field, values[parameter])
            for parameter, form_field in DEBUG_CONFIGURATION_FIELDS.items()
            if parameter in values
        ]
        if syslog_values:
            payload.append(("RequiredAction", "-1"))
            payload.extend(syslog_values)
        if "AUTHCTRLSTAT" in values:
            payload.extend(
                [
                    ("RequiredAction", "14"),
                    ("AuthCtrlStat", values["AUTHCTRLSTAT"]),
                ]
            )
        payload.append(("XToken", session_id))
        return payload

    @staticmethod
    def _assert_configuration_saved(
        response: Any, operation: str = "server configuration"
    ) -> None:
        _Protocol._assert_ok(response, operation)
        if (
            response.headers.get("Session")
            or "sessionExpired" in response.text
            or 'id="logout"' in response.text
        ):
            raise AuthenticationError(
                f"{operation} session was rejected by the phone"
            )

    @staticmethod
    def _sip_account_status(response: Any) -> tuple[dict[str, str], str, str]:
        _Protocol._assert_ok(response, "SIP account preflight")
        try:
            root = ElementTree.fromstring(response.text)
        except ElementTree.ParseError as error:
            raise ProtocolError(
                "invalid SIP account preflight response"
            ) from error
        values = {}
        for parameter in root.iter():
            if parameter.tag.rsplit("}", 1)[-1] != "Parameter":
                continue
            name = parameter.find("{*}Name")
            current = parameter.find("{*}CurrentValue")
            if name is not None and current is not None:
                values[name.text] = current.text or ""
        reboot_pending = next(
            (
                element.text
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1] == "RebootPending"
            ),
            "0",
        )
        user_logged_in = next(
            (
                element.text
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1] == "UserLoggedIn"
            ),
            "0",
        )
        return values, reboot_pending or "0", user_logged_in or "0"

    @staticmethod
    def _sip_account_result(response: Any) -> SipAccountStatus:
        values, _, user_logged_in = _Protocol._sip_account_status(response)
        registered = user_logged_in == "1"
        return SipAccountStatus(
            registration_status="registered" if registered else "unregistered",
            sip_user_id=values.get("SipUserAccount", "") if registered else "",
            sip_domain=values.get("SipDomain", ""),
            sip_proxy_server=values.get("SipControllerList", ""),
        )

    @staticmethod
    def _trusted_certificates(response: Any) -> list[str]:
        _Protocol._assert_ok(response, "trusted certificates read")
        try:
            root = ElementTree.fromstring(response.text)
        except ElementTree.ParseError as error:
            raise ProtocolError(
                "invalid trusted certificates response"
            ) from error
        values = {}
        for parameter in root.iter():
            if parameter.tag.rsplit("}", 1)[-1] != "Parameter":
                continue
            name = parameter.find("{*}AliasName")
            current = parameter.find("{*}CurrentValue")
            if name is not None and current is not None:
                values[name.text] = current.text or ""
        return [
            certificate
            for value in (
                values.get("TRUSTCERTS_WEB", ""),
                values.get("TRUSTCERTS", ""),
            )
            for certificate in value.split(",")
            if certificate
        ]

    @staticmethod
    def _assert_sip_account_ready(response: Any) -> None:
        values, reboot_pending, user_logged_in = _Protocol._sip_account_status(
            response
        )
        if reboot_pending not in {"0", None}:
            raise ProtocolError("SIP account fields require a completed reboot")
        if user_logged_in not in {"0", None}:
            raise ProtocolError("SIP account is already registered")
        if values.get("SipProxySelectionPolicy") != "1":
            raise ProtocolError("SIP proxy policy must be Manual")
        if not values.get("SipControllerList"):
            raise ProtocolError("SIP controller list must be configured")
        if values.get("SipUserAccount") not in {"", "anonymous"}:
            raise ProtocolError("SIP account is already configured")

    @staticmethod
    def _sip_logout_credentials(response: Any) -> tuple[str, str, str]:
        values, reboot_pending, user_logged_in = _Protocol._sip_account_status(
            response
        )
        if reboot_pending != "0":
            raise ProtocolError("SIP account fields require a completed reboot")
        if user_logged_in != "1":
            raise ProtocolError("SIP account is not registered")
        account = values.get("SipUserAccount", "")
        password = values.get("SipUserPassword", "")
        if account in {"", "anonymous"} or not password:
            raise ProtocolError(
                "registered SIP account credentials are unavailable"
            )
        return account, values.get("SipUserId", ""), password

    @staticmethod
    def _sip_login_payload(
        username: str, password: str, session_id: str
    ) -> str:
        # The phone Web UI concatenates these fields instead of URL-encoding them.
        return (
            "SipUserAccount="
            + username
            + "&SipUserId=&SipUserPassword="
            + password
            + "&XToken="
            + session_id
        )

    @staticmethod
    def _assert_sip_account_registered(response: Any) -> None:
        _Protocol._assert_ok(response, "SIP account registration")
        message = response.text.strip()
        if "Please try again." in message or message.lower().startswith(
            "failed"
        ):
            raise ProtocolError(message)

    @staticmethod
    def _phone_report(response: Any) -> PhoneReport:
        _Protocol._assert_ok(response, "phone report")
        if response.headers.get("Session"):
            raise AuthenticationError(
                "phone report session was rejected by the phone"
            )
        if response.headers.get("Busy") in {"1", "true", "True"}:
            raise PhoneBusyError(
                "phone has an active call; report was not generated"
            )
        if response.headers.get("Report"):
            raise ProtocolError("phone report generation failed")
        disposition = response.headers.get("Content-Disposition", "")
        if "attachment" not in disposition.lower():
            raise ProtocolError("phone did not return a report attachment")
        match = re.search(
            r'filename\s*=\s*(?:"([^"]+)"|([^;\s]+))',
            disposition,
            re.IGNORECASE,
        )
        if not match:
            raise ProtocolError(
                "phone report attachment did not include a filename"
            )
        filename = _Protocol._safe_report_filename(
            match.group(1) or match.group(2), offered=True
        )
        return PhoneReport(response.content, filename)

    @staticmethod
    def _safe_report_filename(filename: str, offered: bool = False) -> str:
        if offered:
            filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if (
            not filename
            or filename in {".", ".."}
            or Path(filename).name != filename
            or "\\" in filename
        ):
            raise ValueError("report filename must be a basename")
        return filename

    @staticmethod
    def _capture_destination(headers: dict, output_dir: Optional[str]) -> Path:
        disposition = headers.get("Content-Disposition", "")
        match = re.search(
            r"filename\s*=\s*(?:\"([^\"]+)\"|([^;\s]+))",
            disposition,
            re.IGNORECASE,
        )
        if not match:
            raise ProtocolError(
                "packet capture response did not include a filename"
            )
        directory = Path.cwd() if output_dir is None else Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        name = _Protocol._safe_report_filename(
            match.group(1) or match.group(2), offered=True
        )
        candidate = directory / name
        index = 0
        while True:
            path = (
                candidate
                if index == 0
                else directory / f"{candidate.stem}-{index}{candidate.suffix}"
            )
            try:
                with path.open("xb"):
                    pass
                return path
            except FileExistsError:
                index += 1

    @staticmethod
    def save_phone_report(
        report: PhoneReport,
        output_dir: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> Path:
        directory = Path.cwd() if output_dir is None else Path(output_dir)
        selected_name = (
            _Protocol._safe_report_filename(filename)
            if filename is not None
            else report.filename
        )
        directory.mkdir(parents=True, exist_ok=True)
        candidate = directory / selected_name
        stem, suffix = candidate.stem, candidate.suffix
        index = 0
        while True:
            path = (
                candidate
                if index == 0
                else directory / f"{stem}-{index}{suffix}"
            )
            try:
                with path.open("xb") as destination:
                    destination.write(report.content)
                return path
            except FileExistsError:
                index += 1

    @staticmethod
    def _current_snmp_addresses(response: Any) -> str:
        _Protocol._assert_ok(response, "SNMP configuration read")
        if (
            response.headers.get("Session")
            or "tryLogin" in response.text
            or "logout" in response.text
        ):
            raise AuthenticationError(
                "SNMP configuration read session was rejected by the phone"
            )
        try:
            document = ElementTree.fromstring(response.text)
        except ElementTree.ParseError as error:
            raise ProtocolError(
                "phone returned an invalid SNMP configuration response"
            ) from error
        for parameter in document.iter():
            if parameter.tag.rsplit("}", 1)[-1] != "Parameter":
                continue
            values = {
                child.tag.rsplit("}", 1)[-1]: child.text or ""
                for child in parameter
            }
            if values.get("Name") == SNMP_CONFIGURATION_FIELDS["SNMPADD"]:
                return values.get("CurrentValue", "")
        raise ProtocolError(
            "phone SNMP configuration response did not include permitted sources"
        )

    def digest(self, nonce: str) -> str:
        return hashlib.sha256(
            (self.config.password + nonce).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _validate_replacement_password(password: str) -> None:
        if password == DEFAULT_PASSWORD:
            raise PasswordValidationError(
                "replacement password must not be the factory default"
            )
        if (
            not PASSWORD_PATTERN.fullmatch(password)
            or not any(character.isdigit() for character in password)
            or not any(character.isalpha() for character in password)
            or not any(
                character in PASSWORD_SPECIAL_CHARACTERS
                for character in password
            )
        ):
            raise PasswordValidationError(
                "replacement password must be 6-31 permitted characters with a letter, digit, and special character"
            )

    @staticmethod
    def _encrypt_password(current_password: str, password: str) -> str:
        key = (
            hashlib.sha256(current_password.encode("utf-8"))
            .hexdigest()
            .upper()
            .encode("ascii")[:32]
        )
        encryptor = Cipher(
            algorithms.AES(key), modes.CBC(PASSWORD_CHANGE_IV)
        ).encryptor()
        plaintext = password.encode("utf-8")
        padding = 16 - len(plaintext) % 16
        ciphertext = (
            encryptor.update(plaintext + bytes([padding]) * padding)
            + encryptor.finalize()
        )
        return base64.b64encode(ciphertext).decode("ascii")

    @staticmethod
    def _assert_ok(response: Any, operation: str) -> None:
        if response.status_code != 200:
            raise ProtocolError(f"phone rejected operation {operation}")


class J100Client(_Protocol):
    def __init__(
        self,
        host: str,
        password: str = "",
        verify: Any = True,
        timeout: float = 10.0,
    ):
        super().__init__(J100Config(host, password, verify, timeout))
        self._transport = SyncTransport(self.config.base_url, verify, timeout)
        self.authenticated = False

    @property
    def backend(self) -> str:
        return self._transport.backend

    def close(self) -> None:
        self._transport.close()

    def authenticate(self) -> None:
        response = self._transport.request("GET", LOGIN_PATH)
        self._assert_ok(response, "login discovery")
        nonce = self._transport.cookie("J100nonce")
        session_id = self._transport.cookie("J100sessionId")
        if not nonce or not session_id:
            raise ProtocolError(
                "phone login response did not provide a session nonce"
            )
        response = self._transport.request(
            "POST",
            LOGIN_POST_PATH,
            data={"uname": DEFAULT_USERNAME, "psw": self.digest(nonce)},
            headers=self.login_headers,
        )
        self._assert_ok(response, "login")
        self._check_session()
        self.authenticated = True

    def _check_session(self) -> None:
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            SESSION_CHECK_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        if (
            response.status_code != 200
            or response.headers.get("Session")
            or "tryLogin" in response.text
            or "logout" in response.text
        ):
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )

    def _phone_busy(self) -> bool:
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            PHONE_STATUS_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        self._assert_ok(response, "phone status")
        return response.headers.get("Busy", "0") == "1"

    def login(self) -> None:
        self.authenticate()

    def packet_capture(
        self, max_duration: int = 300, output_dir: Optional[str] = None
    ) -> PacketCapture:
        async def run() -> PacketCapture:
            client = AsyncJ100Client(
                self.config.host,
                self.config.password,
                self.config.verify,
                self.config.timeout,
            )
            try:
                return await client.packet_capture(max_duration, output_dir)
            finally:
                await client.close()

        return asyncio.run(run())

    def phone_status(self) -> str:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        return "busy" if self._phone_busy() else "idle"

    def set_factory_default_password(self, password: str) -> None:
        self._validate_replacement_password(password)
        self.config = J100Config(
            self.config.host,
            DEFAULT_PASSWORD,
            self.config.verify,
            self.config.timeout,
        )
        self.authenticate()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        encrypted_password = self._encrypt_password(DEFAULT_PASSWORD, password)
        response = self._transport.request(
            "POST",
            PASSWORD_CHANGE_PATH,
            data={
                "RequiredAction": "14",
                "OldWebAdminPassword": DEFAULT_PASSWORD,
                "WebAdminPassword": encrypted_password,
                "cnfWebAdminPassword": encrypted_password,
                "XToken": session_id,
            },
            headers=self.password_change_headers,
        )
        self._assert_ok(response, "password change")
        self.config = J100Config(
            self.config.host, password, self.config.verify, self.config.timeout
        )
        self.authenticated = False
        self.authenticate()

    def configure_servers(
        self,
        *,
        HTTPSRVR: Optional[str] = None,
        TLSSRVR: Optional[str] = None,
        HTTPDIR: Optional[str] = None,
        TLSDIR: Optional[str] = None,
        HTTPPORT: Optional[str] = None,
        TLSPORT: Optional[str] = None,
        DNSSRVR: Optional[str] = None,
        SNTPSRVR: Optional[str] = None,
    ) -> None:
        settings = locals()
        if not any(
            settings.get(parameter) is not None
            for parameter in SERVER_CONFIGURATION_FIELDS
        ):
            raise ValueError("at least one server setting must be supplied")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            CONFIGURATION_SAVE_PATH,
            data=self._server_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers("13"),
        )
        self._assert_configuration_saved(response)

    def configure_snmp(
        self,
        *,
        SNMPSTRING: Optional[str] = None,
        SNMPADD: Optional[str] = None,
        append: bool = False,
    ) -> None:
        settings = {"SNMPSTRING": SNMPSTRING, "SNMPADD": SNMPADD}
        if append and SNMPADD is None:
            raise ValueError(
                "SNMPADD must be supplied when appending permitted sources"
            )
        self._snmp_configuration_payload(settings, "")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        if append:
            assert SNMPADD is not None
            response = self._transport.request(
                "GET", SNMP_CONFIGURATION_READ_PATH
            )
            current_addresses = self._current_snmp_addresses(response)
            settings["SNMPADD"] = (
                f"{current_addresses},{SNMPADD}"
                if current_addresses
                else SNMPADD
            )
        payload = self._snmp_configuration_payload(settings, session_id)
        response = self._transport.request(
            "POST",
            SNMP_CONFIGURATION_SAVE_PATH,
            data=payload,
            headers=self.configuration_save_headers("22"),
        )
        self._assert_configuration_saved(response, "SNMP configuration")

    def configure_debug(
        self,
        *,
        SYSLOG_ENABLED: Optional[str] = None,
        LOGSRVR: Optional[str] = None,
        LOGSRVR_SECURE: Optional[str] = None,
        SYSLOG_LEVEL: Optional[str] = None,
        LOG_CATEGORY: Optional[str] = None,
        AUTHCTRLSTAT: Optional[str] = None,
        reset_to_default: bool = False,
    ) -> None:
        settings = {
            "SYSLOG_ENABLED": SYSLOG_ENABLED,
            "LOGSRVR": LOGSRVR,
            "LOGSRVR_SECURE": LOGSRVR_SECURE,
            "SYSLOG_LEVEL": SYSLOG_LEVEL,
            "LOG_CATEGORY": LOG_CATEGORY,
            "AUTHCTRLSTAT": AUTHCTRLSTAT,
            "reset_to_default": reset_to_default,
        }
        self._debug_configuration_payload(settings, "")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        if self._phone_busy():
            raise PhoneBusyError("phone is busy; configuration was not changed")
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            SNMP_CONFIGURATION_SAVE_PATH,
            data=self._debug_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers("22"),
        )
        self._assert_configuration_saved(response, "debug configuration")

    def configure_sip_global(
        self,
        *,
        SIP_CONTROLLER_LIST: Optional[str] = None,
        SIPDOMAIN: Optional[str] = None,
        ENABLE_PPM_SOURCED_SIPPROXYSRVR: Optional[str] = None,
        automatic: bool = False,
    ) -> None:
        if automatic and (
            SIP_CONTROLLER_LIST is not None
            or ENABLE_PPM_SOURCED_SIPPROXYSRVR is not None
        ):
            raise ValueError(
                "automatic mode cannot set a controller or PPM source"
            )
        if not automatic and not SIP_CONTROLLER_LIST:
            raise ValueError("SIP_CONTROLLER_LIST must be supplied")
        for value in (SIPDOMAIN, SIP_CONTROLLER_LIST):
            if value is not None and len(value) > 255:
                raise ValueError(
                    "SIP Global values must not exceed 255 characters"
                )
        ppm = None
        if ENABLE_PPM_SOURCED_SIPPROXYSRVR is not None:
            ppm = {"Yes": "1", "1": "1", "No": "0", "0": "0"}.get(
                ENABLE_PPM_SOURCED_SIPPROXYSRVR
            )
            if ppm is None:
                raise ValueError("PPM source must be Yes, No, 1, or 0")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        payload = []
        if ppm is not None:
            payload.extend(
                [("RequiredAction", "-1"), ("EnablePpmSipProxy", ppm)]
            )
        if SIPDOMAIN is not None:
            payload.extend([("RequiredAction", "0"), ("SipDomain", SIPDOMAIN)])
        payload.extend(
            [
                ("RequiredAction", "14"),
                ("SipProxySelectionPolicy", "0" if automatic else "1"),
            ]
        )
        if SIP_CONTROLLER_LIST is not None:
            payload.append(("SipControllerList", SIP_CONTROLLER_LIST))
        payload.append(("XToken", session_id))
        response = self._transport.request(
            "POST",
            SIP_GLOBAL_CONFIGURATION_SAVE_PATH,
            data=payload,
            headers=self.configuration_save_headers("17"),
        )
        self._assert_configuration_saved(response, "SIP Global configuration")

    def sip_login(self, username: str, password: str) -> None:
        if not username or not password:
            raise ValueError("SIP username and password must be supplied")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        preflight = self._transport.request("GET", SIP_CONFIGURATION_READ_PATH)
        self._assert_sip_account_ready(preflight)
        response = self._transport.request(
            "POST",
            SIP_ACCOUNT_PATH,
            data=self._sip_login_payload(username, password, session_id),
            headers=self.sip_account_headers,
        )
        self._assert_sip_account_registered(response)

    def sip_logout(self) -> None:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        preflight = self._transport.request("GET", SIP_CONFIGURATION_READ_PATH)
        account, user_id, password = self._sip_logout_credentials(preflight)
        response = self._transport.request(
            "POST",
            SIP_LOGOUT_PATH,
            data={
                "SipUserAccount": account,
                "SipUserId": user_id,
                "SipUserPassword": password,
                "XToken": session_id,
            },
            headers=self.sip_account_headers,
        )
        self._assert_sip_account_registered(response)

    def sip_account_status(self) -> SipAccountStatus:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        response = self._transport.request("GET", SIP_CONFIGURATION_READ_PATH)
        return self._sip_account_result(response)

    def trusted_certificates(self) -> list[str]:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        return self._trusted_certificates(
            self._transport.request("GET", TRUSTED_CERTIFICATES_READ_PATH)
        )

    def import_trusted_certificate(self, filename: str, content: bytes) -> None:
        if not filename or not content:
            raise ValueError(
                "trusted certificate filename and content must be supplied"
            )
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        if self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; certificate was not imported"
            )
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            TRUST_CERTIFICATE_UPLOAD_PATH,
            data={"XToken": session_id},
            files={
                "TrustCertWeb": (filename, content, "application/octet-stream")
            },
            headers={
                "Referer": self.config.base_url
                + "/cgi-bin/J100WebServer.cgi?Operation=23"
            },
        )
        self._assert_ok(response, "trusted certificate upload")
        if "Upload successful" not in response.text:
            raise ProtocolError(
                "phone did not accept trusted certificate upload"
            )
        installed = self._trusted_certificates(
            self._transport.request("GET", TRUSTED_CERTIFICATES_READ_PATH)
        )
        if filename not in installed:
            raise ProtocolError("trusted certificate upload was not installed")

    def generate_phone_report(self) -> PhoneReport:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        if self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; report was not generated"
            )
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            PHONE_REPORT_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        return self._phone_report(response)

    def restart(
        self,
        wait: bool = True,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
    ) -> RestartResult:
        return self._restart_or_reset(
            RESTART_PATH, "restart", wait, timeout, poll_interval
        )

    def reset_to_default(
        self,
        force: bool = False,
        wait: bool = False,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> RestartResult:
        if not force:
            raise ConfirmationRequiredError(
                "factory reset requires force confirmation"
            )
        return self._restart_or_reset(
            FACTORY_RESET_PATH, "factory reset", wait, timeout, poll_interval
        )

    def _restart_or_reset(
        self,
        path: str,
        operation: str,
        wait: bool,
        timeout: float,
        poll_interval: float,
    ) -> RestartResult:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        if self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; operation was not performed"
            )
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = self._transport.request(
            "POST",
            path,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        self._assert_ok(response, operation)
        if response.text.strip() != "1":
            raise ProtocolError(f"phone did not accept {operation} request")
        if not wait:
            return RestartResult(True, False, False)
        deadline = time.monotonic() + timeout
        unavailable = False
        while time.monotonic() < deadline:
            try:
                if unavailable:
                    self.authenticated = False
                    self.authenticate()
                else:
                    self._check_session()
                if unavailable:
                    return RestartResult(True, True, True)
            except (AuthenticationError, TransportError):
                unavailable = True
            time.sleep(poll_interval)
        raise RestartTimeoutError(
            f"{operation} was accepted but the phone did not return before the timeout"
        )


class AsyncJ100Client(_Protocol):
    def __init__(
        self,
        host: str,
        password: str = "",
        verify: Any = True,
        timeout: float = 10.0,
    ):
        super().__init__(J100Config(host, password, verify, timeout))
        self._transport = AsyncTransport(self.config.base_url, verify, timeout)
        self.authenticated = False

    @property
    def backend(self) -> str:
        return self._transport.backend

    async def close(self) -> None:
        await self._transport.close()

    async def authenticate(self) -> None:
        response = await self._transport.request("GET", LOGIN_PATH)
        self._assert_ok(response, "login discovery")
        nonce = await self._transport.cookie("J100nonce")
        session_id = await self._transport.cookie("J100sessionId")
        if not nonce or not session_id:
            raise ProtocolError(
                "phone login response did not provide a session nonce"
            )
        response = await self._transport.request(
            "POST",
            LOGIN_POST_PATH,
            data={"uname": DEFAULT_USERNAME, "psw": self.digest(nonce)},
            headers=self.login_headers,
        )
        self._assert_ok(response, "login")
        await self._check_session()
        self.authenticated = True

    async def _check_session(self) -> None:
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            SESSION_CHECK_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        if (
            response.status_code != 200
            or response.headers.get("Session")
            or "tryLogin" in response.text
            or "logout" in response.text
        ):
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )

    async def _phone_busy(self) -> bool:
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            PHONE_STATUS_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        self._assert_ok(response, "phone status")
        return response.headers.get("Busy", "0") == "1"

    async def login(self) -> None:
        await self.authenticate()

    async def _stop_packet_capture(self) -> None:
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            STOP_PACKET_CAPTURE_PATH,
            data="XToken=" + session_id,
            headers={
                **self.request_headers,
                "Referer": self.config.base_url
                + "/cgi-bin/J100WebServer.cgi?Operation=22",
            },
        )
        self._assert_ok(response, "packet capture stop")
        if response.text.strip() != "1":
            raise ProtocolError(
                "phone did not accept packet capture stop request"
            )

    def _packet_capture_control_client(self) -> "AsyncJ100Client":
        return AsyncJ100Client(
            self.config.host,
            self.config.password,
            self.config.verify,
            self.config.timeout,
        )

    async def packet_capture(
        self, max_duration: int = 300, output_dir: Optional[str] = None
    ) -> PacketCapture:
        if not 1 <= max_duration <= 600:
            raise ValueError("max_duration must be between 1 and 600 seconds")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        headers = {
            **self.request_headers,
            "Referer": self.config.base_url
            + "/cgi-bin/J100WebServer.cgi?Operation=22",
        }
        control: Optional[AsyncJ100Client] = None
        async with self._transport.stream(
            "POST",
            PACKET_CAPTURE_PATH,
            # Browser text/plain form submission terminates the field with CRLF.
            data="XToken=" + session_id + "\r\n",
            headers=headers,
        ) as (status, response_headers, chunks):
            if status != 200:
                raise ProtocolError(
                    "phone did not accept packet capture request"
                )
            path = self._capture_destination(response_headers, output_dir)

            async def write_stream() -> None:
                with path.open("ab") as destination:
                    async for chunk in chunks:
                        destination.write(chunk)

            writer = asyncio.create_task(write_stream())
            timer = asyncio.create_task(asyncio.sleep(max_duration))
            try:
                done, _ = await asyncio.wait(
                    {writer, timer}, return_when=asyncio.FIRST_COMPLETED
                )
                if writer in done and not timer.done():
                    writer.result()
                    raise ProtocolError(
                        "packet capture stream ended unexpectedly"
                    )
            finally:
                timer.cancel()
                control = self._packet_capture_control_client()
                try:
                    await control.authenticate()
                    await control._stop_packet_capture()
                finally:
                    await control.close()
            await writer
        return PacketCapture(str(path))

    async def phone_status(self) -> str:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        return "busy" if await self._phone_busy() else "idle"

    async def set_factory_default_password(self, password: str) -> None:
        self._validate_replacement_password(password)
        self.config = J100Config(
            self.config.host,
            DEFAULT_PASSWORD,
            self.config.verify,
            self.config.timeout,
        )
        await self.authenticate()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        encrypted_password = self._encrypt_password(DEFAULT_PASSWORD, password)
        response = await self._transport.request(
            "POST",
            PASSWORD_CHANGE_PATH,
            data={
                "RequiredAction": "14",
                "OldWebAdminPassword": DEFAULT_PASSWORD,
                "WebAdminPassword": encrypted_password,
                "cnfWebAdminPassword": encrypted_password,
                "XToken": session_id,
            },
            headers=self.password_change_headers,
        )
        self._assert_ok(response, "password change")
        self.config = J100Config(
            self.config.host, password, self.config.verify, self.config.timeout
        )
        self.authenticated = False
        await self.authenticate()

    async def configure_servers(
        self,
        *,
        HTTPSRVR: Optional[str] = None,
        TLSSRVR: Optional[str] = None,
        HTTPDIR: Optional[str] = None,
        TLSDIR: Optional[str] = None,
        HTTPPORT: Optional[str] = None,
        TLSPORT: Optional[str] = None,
    ) -> None:
        settings = locals()
        if not any(
            settings[parameter] is not None
            for parameter in SERVER_CONFIGURATION_FIELDS
        ):
            raise ValueError("at least one server setting must be supplied")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            CONFIGURATION_SAVE_PATH,
            data=self._server_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers("13"),
        )
        self._assert_configuration_saved(response)

    async def configure_snmp(
        self,
        *,
        SNMPSTRING: Optional[str] = None,
        SNMPADD: Optional[str] = None,
        append: bool = False,
    ) -> None:
        settings = {"SNMPSTRING": SNMPSTRING, "SNMPADD": SNMPADD}
        if append and SNMPADD is None:
            raise ValueError(
                "SNMPADD must be supplied when appending permitted sources"
            )
        self._snmp_configuration_payload(settings, "")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        if append:
            assert SNMPADD is not None
            response = await self._transport.request(
                "GET", SNMP_CONFIGURATION_READ_PATH
            )
            current_addresses = self._current_snmp_addresses(response)
            settings["SNMPADD"] = (
                f"{current_addresses},{SNMPADD}"
                if current_addresses
                else SNMPADD
            )
        payload = self._snmp_configuration_payload(settings, session_id)
        response = await self._transport.request(
            "POST",
            SNMP_CONFIGURATION_SAVE_PATH,
            data=payload,
            headers=self.configuration_save_headers("22"),
        )
        self._assert_configuration_saved(response, "SNMP configuration")

    async def configure_debug(
        self,
        *,
        SYSLOG_ENABLED: Optional[str] = None,
        LOGSRVR: Optional[str] = None,
        LOGSRVR_SECURE: Optional[str] = None,
        SYSLOG_LEVEL: Optional[str] = None,
        LOG_CATEGORY: Optional[str] = None,
        AUTHCTRLSTAT: Optional[str] = None,
        reset_to_default: bool = False,
    ) -> None:
        settings = {
            "SYSLOG_ENABLED": SYSLOG_ENABLED,
            "LOGSRVR": LOGSRVR,
            "LOGSRVR_SECURE": LOGSRVR_SECURE,
            "SYSLOG_LEVEL": SYSLOG_LEVEL,
            "LOG_CATEGORY": LOG_CATEGORY,
            "AUTHCTRLSTAT": AUTHCTRLSTAT,
            "reset_to_default": reset_to_default,
        }
        self._debug_configuration_payload(settings, "")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        if await self._phone_busy():
            raise PhoneBusyError("phone is busy; configuration was not changed")
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            SNMP_CONFIGURATION_SAVE_PATH,
            data=self._debug_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers("22"),
        )
        self._assert_configuration_saved(response, "debug configuration")

    async def configure_sip_global(self, **settings: Any) -> None:
        automatic = settings.pop("automatic", False)
        if automatic and (
            settings.get("SIP_CONTROLLER_LIST") is not None
            or settings.get("ENABLE_PPM_SOURCED_SIPPROXYSRVR") is not None
        ):
            raise ValueError(
                "automatic mode cannot set a controller or PPM source"
            )
        controller = settings.get("SIP_CONTROLLER_LIST")
        if not automatic and not controller:
            raise ValueError("SIP_CONTROLLER_LIST must be supplied")
        for value in (settings.get("SIPDOMAIN"), controller):
            if value is not None and len(value) > 255:
                raise ValueError(
                    "SIP Global values must not exceed 255 characters"
                )
        ppm = settings.get("ENABLE_PPM_SOURCED_SIPPROXYSRVR")
        if ppm is not None:
            ppm = {"Yes": "1", "1": "1", "No": "0", "0": "0"}.get(ppm)
            if ppm is None:
                raise ValueError("PPM source must be Yes, No, 1, or 0")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        payload = [
            ("RequiredAction", "14"),
            ("SipProxySelectionPolicy", "0" if automatic else "1"),
        ]
        if controller is not None:
            payload.append(("SipControllerList", controller))
        if settings.get("SIPDOMAIN") is not None:
            payload.extend(
                [("RequiredAction", "0"), ("SipDomain", settings["SIPDOMAIN"])]
            )
        if ppm is not None:
            payload.extend(
                [("RequiredAction", "-1"), ("EnablePpmSipProxy", ppm)]
            )
        payload.append(("XToken", session_id))
        response = await self._transport.request(
            "POST",
            SIP_GLOBAL_CONFIGURATION_SAVE_PATH,
            data=payload,
            headers=self.configuration_save_headers("17"),
        )
        self._assert_configuration_saved(response, "SIP Global configuration")

    async def sip_login(self, username: str, password: str) -> None:
        if not username or not password:
            raise ValueError("SIP username and password must be supplied")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        preflight = await self._transport.request(
            "GET", SIP_CONFIGURATION_READ_PATH
        )
        self._assert_sip_account_ready(preflight)
        response = await self._transport.request(
            "POST",
            SIP_ACCOUNT_PATH,
            data=self._sip_login_payload(username, password, session_id),
            headers=self.sip_account_headers,
        )
        self._assert_sip_account_registered(response)

    async def sip_logout(self) -> None:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        preflight = await self._transport.request(
            "GET", SIP_CONFIGURATION_READ_PATH
        )
        account, user_id, password = self._sip_logout_credentials(preflight)
        response = await self._transport.request(
            "POST",
            SIP_LOGOUT_PATH,
            data={
                "SipUserAccount": account,
                "SipUserId": user_id,
                "SipUserPassword": password,
                "XToken": session_id,
            },
            headers=self.sip_account_headers,
        )
        self._assert_sip_account_registered(response)

    async def sip_account_status(self) -> SipAccountStatus:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        response = await self._transport.request(
            "GET", SIP_CONFIGURATION_READ_PATH
        )
        return self._sip_account_result(response)

    async def trusted_certificates(self) -> list[str]:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        return self._trusted_certificates(
            await self._transport.request("GET", TRUSTED_CERTIFICATES_READ_PATH)
        )

    async def import_trusted_certificate(
        self, filename: str, content: bytes
    ) -> None:
        if not filename or not content:
            raise ValueError(
                "trusted certificate filename and content must be supplied"
            )
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        if await self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; certificate was not imported"
            )
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            TRUST_CERTIFICATE_UPLOAD_PATH,
            data={"XToken": session_id},
            files={
                "TrustCertWeb": (filename, content, "application/octet-stream")
            },
            headers={
                "Referer": self.config.base_url
                + "/cgi-bin/J100WebServer.cgi?Operation=23"
            },
        )
        self._assert_ok(response, "trusted certificate upload")
        if "Upload successful" not in response.text:
            raise ProtocolError(
                "phone did not accept trusted certificate upload"
            )
        installed = self._trusted_certificates(
            await self._transport.request("GET", TRUSTED_CERTIFICATES_READ_PATH)
        )
        if filename not in installed:
            raise ProtocolError("trusted certificate upload was not installed")

    async def generate_phone_report(self) -> PhoneReport:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        if await self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; report was not generated"
            )
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            PHONE_REPORT_PATH,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        return self._phone_report(response)

    async def restart(
        self,
        wait: bool = True,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
    ) -> RestartResult:
        return await self._restart_or_reset(
            RESTART_PATH, "restart", wait, timeout, poll_interval
        )

    async def reset_to_default(
        self,
        force: bool = False,
        wait: bool = False,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> RestartResult:
        if not force:
            raise ConfirmationRequiredError(
                "factory reset requires force confirmation"
            )
        return await self._restart_or_reset(
            FACTORY_RESET_PATH, "factory reset", wait, timeout, poll_interval
        )

    async def _restart_or_reset(
        self,
        path: str,
        operation: str,
        wait: bool,
        timeout: float,
        poll_interval: float,
    ) -> RestartResult:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        if await self._phone_busy():
            raise PhoneBusyError(
                "phone has an active call; operation was not performed"
            )
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError(
                "authentication was rejected by the phone"
            )
        response = await self._transport.request(
            "POST",
            path,
            data="XToken=" + session_id,
            headers=self.request_headers,
        )
        self._assert_ok(response, operation)
        if response.text.strip() != "1":
            raise ProtocolError(f"phone did not accept {operation} request")
        if not wait:
            return RestartResult(True, False, False)
        deadline = time.monotonic() + timeout
        unavailable = False
        while time.monotonic() < deadline:
            try:
                if unavailable:
                    self.authenticated = False
                    await self.authenticate()
                else:
                    await self._check_session()
                if unavailable:
                    return RestartResult(True, True, True)
            except (AuthenticationError, TransportError):
                unavailable = True
            await asyncio.sleep(poll_interval)
        raise RestartTimeoutError(
            f"{operation} was accepted but the phone did not return before the timeout"
        )
