"""Synchronous and asynchronous J100 Web UI clients."""

import asyncio
import base64
import hashlib
import re
import time
from typing import Any, Optional

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
from .models import J100Config, RestartResult
from .transport import AsyncTransport, SyncTransport

LOGIN_PATH = "/cgi-bin/J100WebServer.cgi?Operation=0"
LOGIN_POST_PATH = "/cgi-bin/J100WebServer.cgi?Operation=1"
SESSION_CHECK_PATH = "/cgi-bin/J100WebServer.cgi?Operation=33"
PHONE_STATUS_PATH = "/cgi-bin/J100WebServer.cgi?Operation=34"
RESTART_PATH = "/cgi-bin/J100WebServer.cgi?Operation=4"
FACTORY_RESET_PATH = "/cgi-bin/J100WebServer.cgi?Operation=5"
PASSWORD_CHANGE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=212"
CONFIGURATION_SAVE_PATH = "/cgi-bin/J100WebServer.cgi?Operation=3213"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "27238"
PASSWORD_PATTERN = re.compile(r"^[A-Za-z0-9~!@#$%^&*_=+`|\\(){}\[\]:;'<>.,?/]{6,31}$")
PASSWORD_SPECIAL_CHARACTERS = "~!@#$%^&*_-+=`|\\(){}[]:;'<>.,?/"
PASSWORD_CHANGE_IV = bytes([185, 81, 2, 73, 200, 160, 146, 101, 228, 36, 138, 96, 102, 0, 129, 7])
SERVER_CONFIGURATION_FIELDS = {
    "HTTPSRVR": "FileServerHttpDownloadList",
    "TLSSRVR": "FileServerTlsDownloadList",
    "HTTPDIR": "DirectoryForHttpDownload",
    "TLSDIR": "DirectoryForTlsDownload",
    "HTTPPORT": "PortForHttpDownload",
    "TLSPORT": "PortForTlsDownload",
}


class _Protocol:
    def __init__(self, config: J100Config):
        self.config = config

    @property
    def login_headers(self) -> dict:
        return {"Origin": self.config.base_url, "Referer": self.config.base_url + LOGIN_PATH}

    @property
    def request_headers(self) -> dict:
        return {
            "Cache-Control": "no-cache",
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url + "/cgi-bin/J100WebServer.cgi?Operation=10",
        }

    @property
    def password_change_headers(self) -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url + "/cgi-bin/J100WebServer.cgi?Operation=211",
        }

    @property
    def configuration_save_headers(self) -> dict:
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.base_url,
            "Referer": self.config.base_url + "/cgi-bin/J100WebServer.cgi?Operation=13",
        }

    @staticmethod
    def _server_configuration_payload(settings: dict[str, Any], session_id: str) -> dict:
        values = {
            form_field: settings[parameter]
            for parameter, form_field in SERVER_CONFIGURATION_FIELDS.items()
            if settings[parameter] is not None
        }
        if not values:
            raise ValueError("at least one server setting must be supplied")
        return {"RequiredAction": "-1", **values, "XToken": session_id}

    @staticmethod
    def _assert_configuration_saved(response: Any) -> None:
        _Protocol._assert_ok(response, "server configuration")
        if response.headers.get("Session") or "sessionExpired" in response.text or 'id="logout"' in response.text:
            raise AuthenticationError("server configuration session was rejected by the phone")

    def digest(self, nonce: str) -> str:
        return hashlib.sha256((self.config.password + nonce).encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_replacement_password(password: str) -> None:
        if password == DEFAULT_PASSWORD:
            raise PasswordValidationError("replacement password must not be the factory default")
        if (
            not PASSWORD_PATTERN.fullmatch(password)
            or not any(character.isdigit() for character in password)
            or not any(character.isalpha() for character in password)
            or not any(character in PASSWORD_SPECIAL_CHARACTERS for character in password)
        ):
            raise PasswordValidationError("replacement password must be 6-31 permitted characters with a letter, digit, and special character")

    @staticmethod
    def _encrypt_password(current_password: str, password: str) -> str:
        key = hashlib.sha256(current_password.encode("utf-8")).hexdigest().upper().encode("ascii")[:32]
        encryptor = Cipher(algorithms.AES(key), modes.CBC(PASSWORD_CHANGE_IV)).encryptor()
        plaintext = password.encode("utf-8")
        padding = 16 - len(plaintext) % 16
        ciphertext = encryptor.update(plaintext + bytes([padding]) * padding) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode("ascii")

    @staticmethod
    def _assert_ok(response: Any, operation: str) -> None:
        if response.status_code != 200:
            raise ProtocolError(f"phone rejected operation {operation}")


class J100Client(_Protocol):
    def __init__(self, host: str, username: str = "admin", password: str = "", verify: Any = True, timeout: float = 10.0):
        super().__init__(J100Config(host, username, password, verify, timeout))
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
            raise ProtocolError("phone login response did not provide a session nonce")
        response = self._transport.request(
            "POST", LOGIN_POST_PATH, data={"uname": self.config.username, "psw": self.digest(nonce)}, headers=self.login_headers
        )
        self._assert_ok(response, "login")
        self._check_session()
        self.authenticated = True

    def _check_session(self) -> None:
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = self._transport.request("POST", SESSION_CHECK_PATH, data="XToken=" + session_id, headers=self.request_headers)
        if response.status_code != 200 or response.headers.get("Session") or "tryLogin" in response.text or "logout" in response.text:
            raise AuthenticationError("authentication was rejected by the phone")

    def _phone_busy(self) -> bool:
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = self._transport.request("POST", PHONE_STATUS_PATH, data="XToken=" + session_id, headers=self.request_headers)
        self._assert_ok(response, "phone status")
        return response.headers.get("Busy", "0") == "1"

    def login(self) -> None:
        self.authenticate()

    def set_factory_default_password(self, password: str) -> None:
        self._validate_replacement_password(password)
        self.config = J100Config(self.config.host, DEFAULT_USERNAME, DEFAULT_PASSWORD, self.config.verify, self.config.timeout)
        self.authenticate()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
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
        self.config = J100Config(self.config.host, DEFAULT_USERNAME, password, self.config.verify, self.config.timeout)
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
    ) -> None:
        settings = locals()
        if not any(settings[parameter] is not None for parameter in SERVER_CONFIGURATION_FIELDS):
            raise ValueError("at least one server setting must be supplied")
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = self._transport.request(
            "POST",
            CONFIGURATION_SAVE_PATH,
            data=self._server_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers,
        )
        self._assert_configuration_saved(response)

    def restart(self, force: bool = False, wait: bool = True, timeout: float = 120.0, poll_interval: float = 2.0) -> RestartResult:
        return self._restart_or_reset(RESTART_PATH, "restart", force, wait, timeout, poll_interval, allow_busy=force)

    def reset_to_default(self, force: bool = False, wait: bool = False, timeout: float = 300.0, poll_interval: float = 5.0) -> RestartResult:
        if not force:
            raise ConfirmationRequiredError("factory reset requires force confirmation")
        return self._restart_or_reset(FACTORY_RESET_PATH, "factory reset", force, wait, timeout, poll_interval, allow_busy=False)

    def _restart_or_reset(
        self, path: str, operation: str, force: bool, wait: bool, timeout: float, poll_interval: float, allow_busy: bool
    ) -> RestartResult:
        if not self.authenticated:
            self.authenticate()
        self._check_session()
        if self._phone_busy() and not allow_busy:
            raise PhoneBusyError("phone has an active call; operation was not performed")
        session_id = self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = self._transport.request("POST", path, data="XToken=" + session_id, headers=self.request_headers)
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
        raise RestartTimeoutError(f"{operation} was accepted but the phone did not return before the timeout")


class AsyncJ100Client(_Protocol):
    def __init__(self, host: str, username: str = "admin", password: str = "", verify: Any = True, timeout: float = 10.0):
        super().__init__(J100Config(host, username, password, verify, timeout))
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
            raise ProtocolError("phone login response did not provide a session nonce")
        response = await self._transport.request(
            "POST", LOGIN_POST_PATH, data={"uname": self.config.username, "psw": self.digest(nonce)}, headers=self.login_headers
        )
        self._assert_ok(response, "login")
        await self._check_session()
        self.authenticated = True

    async def _check_session(self) -> None:
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = await self._transport.request("POST", SESSION_CHECK_PATH, data="XToken=" + session_id, headers=self.request_headers)
        if response.status_code != 200 or response.headers.get("Session") or "tryLogin" in response.text or "logout" in response.text:
            raise AuthenticationError("authentication was rejected by the phone")

    async def _phone_busy(self) -> bool:
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = await self._transport.request("POST", PHONE_STATUS_PATH, data="XToken=" + session_id, headers=self.request_headers)
        self._assert_ok(response, "phone status")
        return response.headers.get("Busy", "0") == "1"

    async def login(self) -> None:
        await self.authenticate()

    async def set_factory_default_password(self, password: str) -> None:
        self._validate_replacement_password(password)
        self.config = J100Config(self.config.host, DEFAULT_USERNAME, DEFAULT_PASSWORD, self.config.verify, self.config.timeout)
        await self.authenticate()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
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
        self.config = J100Config(self.config.host, DEFAULT_USERNAME, password, self.config.verify, self.config.timeout)
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
        if not any(settings[parameter] is not None for parameter in SERVER_CONFIGURATION_FIELDS):
            raise ValueError("at least one server setting must be supplied")
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = await self._transport.request(
            "POST",
            CONFIGURATION_SAVE_PATH,
            data=self._server_configuration_payload(settings, session_id),
            headers=self.configuration_save_headers,
        )
        self._assert_configuration_saved(response)

    async def restart(self, force: bool = False, wait: bool = True, timeout: float = 120.0, poll_interval: float = 2.0) -> RestartResult:
        return await self._restart_or_reset(RESTART_PATH, "restart", force, wait, timeout, poll_interval, allow_busy=force)

    async def reset_to_default(
        self, force: bool = False, wait: bool = False, timeout: float = 300.0, poll_interval: float = 5.0
    ) -> RestartResult:
        if not force:
            raise ConfirmationRequiredError("factory reset requires force confirmation")
        return await self._restart_or_reset(FACTORY_RESET_PATH, "factory reset", force, wait, timeout, poll_interval, allow_busy=False)

    async def _restart_or_reset(
        self, path: str, operation: str, force: bool, wait: bool, timeout: float, poll_interval: float, allow_busy: bool
    ) -> RestartResult:
        if not self.authenticated:
            await self.authenticate()
        await self._check_session()
        if await self._phone_busy() and not allow_busy:
            raise PhoneBusyError("phone has an active call; operation was not performed")
        session_id = await self._transport.cookie("J100sessionId")
        if not session_id:
            raise AuthenticationError("authentication was rejected by the phone")
        response = await self._transport.request("POST", path, data="XToken=" + session_id, headers=self.request_headers)
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
        raise RestartTimeoutError(f"{operation} was accepted but the phone did not return before the timeout")
