"""Click command line interface."""

import asyncio
import json
import signal
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

import click

from .client import AsyncJ100Client
from .exceptions import (
    AuthenticationError,
    ConfirmationRequiredError,
    J100Error,
    PhoneBusyError,
    ProtocolError,
    RestartTimeoutError,
    TransportError,
)
from .models import SipAccountStatus


@dataclass
class BatchResult:
    host: str
    status: str
    message: str
    error_type: Optional[str] = None


@dataclass
class OperationResult:
    status: str
    message: Any


@dataclass
class SipAccountBatchResult:
    host: str
    account: Optional[SipAccountStatus] = None
    message: Optional[str] = None
    error_type: Optional[str] = None


def _unique_hosts(_ctx, _param, hosts):
    return tuple(dict.fromkeys(hosts))


def _batch_options(command):
    command = click.argument(
        "hosts",
        nargs=-1,
        required=True,
        metavar="HOST...",
        callback=_unique_hosts,
    )(command)
    command = click.option(
        "--json", "json_output", is_flag=True, help="Write results as JSON."
    )(command)
    command = click.option(
        "--concurrency",
        default=10,
        show_default=True,
        type=click.IntRange(min=1),
        help="Maximum simultaneous phone operations.",
    )(command)
    command = click.option(
        "--insecure", is_flag=True, help="Disable TLS certificate verification."
    )(command)
    return click.option(
        "--password", required=True, hide_input=False, help="Web UI password."
    )(command)


def _error_type(error: Exception) -> str:
    if isinstance(error, AuthenticationError):
        return "authentication"
    if isinstance(error, PhoneBusyError):
        return "phone_busy"
    if isinstance(error, TransportError):
        return "transport"
    if isinstance(error, RestartTimeoutError):
        return "timeout"
    if isinstance(error, ProtocolError):
        return "protocol"
    if isinstance(error, ConfirmationRequiredError):
        return "confirmation"
    return "validation"


async def _run_batch(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    operation: Callable[
        [AsyncJ100Client], Awaitable[Union[str, OperationResult]]
    ],
    timeout: float = 10.0,
) -> list[BatchResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run_one(host: str) -> BatchResult:
        client: Optional[AsyncJ100Client] = None
        try:
            async with semaphore:
                client = AsyncJ100Client(
                    host,
                    password=password,
                    verify=not insecure,
                    timeout=timeout,
                )
                outcome = await operation(client)
            if isinstance(outcome, OperationResult):
                return BatchResult(host, outcome.status, outcome.message)
            return BatchResult(host, "success", outcome)
        except (J100Error, OSError, ValueError) as error:
            return BatchResult(
                host,
                "error",
                str(error),
                _error_type(error),
            )
        finally:
            if client is not None:
                await client.close()

    return list(await asyncio.gather(*(run_one(host) for host in hosts)))


def _render(results: Sequence[BatchResult], json_output: bool) -> None:
    if json_output:
        click.echo(json.dumps([asdict(result) for result in results]))
        return
    for result in results:
        message = (
            result.message
            if result.status != "error"
            else f"error: {result.message}"
        )
        click.echo(f"{result.host}: {message}")


def _run_and_render(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    operation: Callable[
        [AsyncJ100Client], Awaitable[Union[str, OperationResult]]
    ],
    timeout: float = 10.0,
) -> None:
    results = asyncio.run(
        _run_batch(hosts, password, insecure, concurrency, operation, timeout)
    )
    _render(results, json_output)
    if any(result.status == "error" for result in results):
        raise click.exceptions.Exit(1)


async def _run_sip_account_batch(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    timeout: float,
) -> list[SipAccountBatchResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run_one(host: str) -> SipAccountBatchResult:
        client: Optional[AsyncJ100Client] = None
        try:
            async with semaphore:
                client = AsyncJ100Client(
                    host,
                    password=password,
                    verify=not insecure,
                    timeout=timeout,
                )
                return SipAccountBatchResult(
                    host, account=await client.sip_account_status()
                )
        except (J100Error, OSError, ValueError) as error:
            return SipAccountBatchResult(
                host, message=str(error), error_type=_error_type(error)
            )
        finally:
            if client is not None:
                await client.close()

    return list(await asyncio.gather(*(run_one(host) for host in hosts)))


def _render_sip_accounts(
    results: Sequence[SipAccountBatchResult], json_output: bool
) -> None:
    if json_output:
        rendered = []
        for result in results:
            if result.account is None:
                rendered.append(
                    {
                        "host": result.host,
                        "status": "error",
                        "message": result.message,
                        "error_type": result.error_type,
                    }
                )
            else:
                rendered.append({"host": result.host, **asdict(result.account)})
        click.echo(json.dumps(rendered))
        return
    for result in results:
        if result.account is None:
            click.echo(f"{result.host}: error,,,")
        else:
            account = result.account
            click.echo(
                f"{result.host}: {account.registration_status},{account.sip_user_id},"
                f'{account.sip_domain},"{account.sip_proxy_server}"'
            )


@click.group()
def main() -> None:
    """Manage Avaya J100 phones through their Web UI."""


@main.command()
@click.option(
    "--wait",
    is_flag=True,
    help="Wait until each phone is reachable after restarting.",
)
@click.option(
    "--timeout",
    default=None,
    type=click.FloatRange(min=1.0),
    help=(
        "Maximum request seconds without --wait or recovery seconds with --wait. "
        "Defaults to 10 seconds without --wait and 300 seconds with it."
    ),
)
@click.option(
    "--poll-interval",
    default=5.0,
    show_default=True,
    type=click.FloatRange(min=0.1),
    help="Seconds between checks when --wait is set.",
)
@_batch_options
def restart(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    wait: bool,
    timeout: Optional[float],
    poll_interval: float,
) -> None:
    """Restart."""
    request_timeout = timeout if timeout is not None else 10.0
    recovery_timeout = timeout if timeout is not None else 300.0

    async def operation(client: AsyncJ100Client) -> str:
        result = await client.restart(
            wait=wait, timeout=recovery_timeout, poll_interval=poll_interval
        )
        return "restart completed" if result.completed else "restart accepted"

    _run_and_render(
        hosts,
        password,
        insecure,
        concurrency,
        json_output,
        operation,
        request_timeout,
    )


@main.command("reset-to-default")
@click.option(
    "--force", is_flag=True, help="Confirm destructive factory reset."
)
@click.option(
    "--wait",
    is_flag=True,
    help="Wait until each phone is reachable after reset.",
)
@click.option(
    "--timeout",
    default=300.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds to wait when --wait is set.",
)
@click.option(
    "--poll-interval",
    default=5.0,
    show_default=True,
    type=click.FloatRange(min=0.1),
    help="Seconds between checks when --wait is set.",
)
@_batch_options
def reset_to_default(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    force: bool,
    wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Reset to factory default."""
    if not force:
        raise click.UsageError("factory reset requires --force")

    async def operation(client: AsyncJ100Client) -> str:
        result = await client.reset_to_default(
            force=True, wait=wait, timeout=timeout, poll_interval=poll_interval
        )
        return (
            "factory reset completed"
            if result.completed
            else "factory reset accepted"
        )

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("status")
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for each phone request.",
)
@_batch_options
def status(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    timeout: float,
) -> None:
    """Report online status."""

    async def operation(client: AsyncJ100Client) -> OperationResult:
        phone_status = await client.phone_status()
        return OperationResult(phone_status, phone_status)

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("packet-capture")
@click.option(
    "--max-duration",
    default=300,
    show_default=True,
    type=click.IntRange(min=1, max=600),
    help="Maximum capture duration in seconds.",
)
@click.option("--output-dir", default=None, help="Directory for capture files.")
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for authentication and control requests.",
)
@_batch_options
def packet_capture(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    max_duration: int,
    output_dir: Optional[str],
    timeout: float,
) -> None:
    """Stream packet captures."""
    selected = hosts[: min(len(hosts), concurrency, 10)]

    async def operation(client: AsyncJ100Client) -> str:
        capture = await client.packet_capture(max_duration, output_dir)
        return f"packet capture saved to {capture.path}"

    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(
        signal.SIGTERM,
        lambda *_: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    try:
        results = asyncio.run(
            _run_batch(
                selected, password, insecure, len(selected), operation, timeout
            )
        )
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
    results.extend(
        BatchResult(host, "skipped", "skipped: packet capture session limit")
        for host in hosts[len(selected) :]
    )
    _render(results, json_output)
    if any(result.status == "error" for result in results):
        raise click.exceptions.Exit(1)


@main.command("set-password")
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for each phone request.",
)
@_batch_options
def set_password(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    timeout: float,
) -> None:
    """Set Web admin password."""
    if password == "27238":
        raise click.UsageError(
            "replacement password must not be the factory default"
        )

    async def operation(client: AsyncJ100Client) -> str:
        await client.set_factory_default_password(password)
        return "password changed"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("configure-servers")
@click.option("--HTTPSRVR", default=None, help="HTTP download server list.")
@click.option("--TLSSRVR", default=None, help="HTTPS download server list.")
@click.option("--HTTPDIR", default=None, help="HTTP download directory.")
@click.option("--TLSDIR", default=None, help="TLS download directory.")
@click.option("--HTTPPORT", default=None, help="HTTP download port.")
@click.option("--TLSPORT", default=None, help="TLS download port.")
@click.option("--DNSSRVR", default=None, help="DNS server list.")
@click.option("--SNTPSRVR", default=None, help="SNTP server list.")
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for each phone request.",
)
@_batch_options
def configure_servers(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    httpsrvr: Optional[str],
    tlssrvr: Optional[str],
    httpdir: Optional[str],
    tlsdir: Optional[str],
    httpport: Optional[str],
    tlsport: Optional[str],
    dnssrvr: Optional[str],
    sntpsrvr: Optional[str],
    timeout: float,
) -> None:
    """Update HTTP(S)/DNS/NTP server settings."""
    settings = (
        httpsrvr,
        tlssrvr,
        httpdir,
        tlsdir,
        httpport,
        tlsport,
        dnssrvr,
        sntpsrvr,
    )
    if not any(value is not None for value in settings):
        raise click.UsageError("at least one server setting must be supplied")

    async def operation(client: AsyncJ100Client) -> str:
        await client.configure_servers(
            HTTPSRVR=httpsrvr,
            TLSSRVR=tlssrvr,
            HTTPDIR=httpdir,
            TLSDIR=tlsdir,
            HTTPPORT=httpport,
            TLSPORT=tlsport,
            DNSSRVR=dnssrvr,
            SNTPSRVR=sntpsrvr,
        )
        return "server configuration updated"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("configure-debug")
@click.option(
    "--SYSLOG_ENABLED", default=None, help="Enable syslog (Yes, No, 1, or 0)."
)
@click.option("--LOGSRVR", default=None, help="Syslog server address.")
@click.option(
    "--LOGSRVR_SECURE",
    default=None,
    help="Use secure syslog (Yes, No, 1, or 0).",
)
@click.option(
    "--SYSLOG_LEVEL", default=None, help="Syslog severity from 0 to 7."
)
@click.option(
    "--LOG_CATEGORY", default=None, help="Comma-separated log categories."
)
@click.option(
    "--AUTHCTRLSTAT",
    default=None,
    help="Enable authentication-control logging (Yes, No, 1, or 0).",
)
@click.option("--reset-to-default", is_flag=True)
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for each phone request.",
)
@_batch_options
def configure_debug(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    syslog_enabled: Optional[str],
    logsrvr: Optional[str],
    logsrvr_secure: Optional[str],
    syslog_level: Optional[str],
    log_category: Optional[str],
    authctrlstat: Optional[str],
    reset_to_default: bool,
    timeout: float,
) -> None:
    """Update Debug settings."""
    settings = (
        syslog_enabled,
        logsrvr,
        logsrvr_secure,
        syslog_level,
        log_category,
        authctrlstat,
    )
    if reset_to_default and any(value is not None for value in settings):
        raise click.UsageError(
            "reset_to_default cannot be combined with debug settings"
        )
    if not reset_to_default and not any(
        value is not None for value in settings
    ):
        raise click.UsageError("at least one debug setting must be supplied")

    async def operation(client: AsyncJ100Client) -> str:
        await client.configure_debug(
            SYSLOG_ENABLED=syslog_enabled,
            LOGSRVR=logsrvr,
            LOGSRVR_SECURE=logsrvr_secure,
            SYSLOG_LEVEL=syslog_level,
            LOG_CATEGORY=log_category,
            AUTHCTRLSTAT=authctrlstat,
            reset_to_default=reset_to_default,
        )
        return "debug configuration updated"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("configure-snmp")
@click.option("--SNMPSTRING", default=None, help="SNMP community string.")
@click.option("--SNMPADD", default=None, help="Allowed SNMP query sources.")
@click.option(
    "--append",
    "append",
    is_flag=True,
    help="Append SNMPADD to the current permitted sources.",
)
@click.option(
    "--timeout",
    default=10.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds for each phone request.",
)
@_batch_options
def configure_snmp(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    snmpstring: Optional[str],
    snmpadd: Optional[str],
    append: bool,
    timeout: float,
) -> None:
    """Update SNMP settings."""
    if append and snmpadd is None:
        raise click.UsageError(
            "SNMPADD must be supplied when appending permitted sources"
        )

    async def operation(client: AsyncJ100Client) -> str:
        await client.configure_snmp(
            SNMPSTRING=snmpstring, SNMPADD=snmpadd, append=append
        )
        return "SNMP configuration updated"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("configure-sip-global")
@click.option("--SIPDOMAIN", default=None)
@click.option("--ENABLE_PPM_SOURCED_SIPPROXYSRVR", default=None)
@click.option("--SIP_CONTROLLER_LIST", default=None)
@click.option("--automatic-sip-proxy", is_flag=True)
@click.option(
    "--timeout", default=10.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def configure_sip_global(
    hosts,
    password,
    insecure,
    concurrency,
    json_output,
    sipdomain,
    enable_ppm_sourced_sipproxysrvr,
    sip_controller_list,
    automatic_sip_proxy,
    timeout,
):
    """Update SIP Global settings."""
    if automatic_sip_proxy and (
        enable_ppm_sourced_sipproxysrvr is not None
        or sip_controller_list is not None
    ):
        raise click.UsageError(
            "automatic mode cannot set a controller or PPM source"
        )
    if not automatic_sip_proxy and not sip_controller_list:
        raise click.UsageError("SIP_CONTROLLER_LIST must be supplied")

    async def operation(client: AsyncJ100Client) -> str:
        await client.configure_sip_global(
            SIPDOMAIN=sipdomain,
            ENABLE_PPM_SOURCED_SIPPROXYSRVR=enable_ppm_sourced_sipproxysrvr,
            SIP_CONTROLLER_LIST=sip_controller_list,
            automatic=automatic_sip_proxy,
        )
        return "SIP Global configuration updated"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("sip-login")
@click.option("--SIPUSERNAME", required=True)
@click.option("--SIPPASSWORD", required=True)
@click.option(
    "--timeout", default=30.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def sip_login(
    hosts,
    password,
    insecure,
    concurrency,
    json_output,
    sipusername,
    sippassword,
    timeout,
):
    """Log in a SIP account."""

    async def operation(client: AsyncJ100Client) -> str:
        await client.sip_login(sipusername, sippassword)
        return "SIP account logged in"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("sip-logout")
@click.option(
    "--timeout", default=10.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def sip_logout(hosts, password, insecure, concurrency, json_output, timeout):
    """Log out SIP account."""

    async def operation(client: AsyncJ100Client) -> str:
        await client.sip_logout()
        return "SIP account logged out"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("sip-account")
@click.option(
    "--timeout", default=10.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def sip_account(hosts, password, insecure, concurrency, json_output, timeout):
    """Report SIP account status."""
    results = asyncio.run(
        _run_sip_account_batch(hosts, password, insecure, concurrency, timeout)
    )
    _render_sip_accounts(results, json_output)
    if any(result.account is None for result in results):
        raise click.exceptions.Exit(1)


@main.command("trust-certs")
@click.option(
    "--timeout", default=10.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def trust_certs(hosts, password, insecure, concurrency, json_output, timeout):
    """Report installed trusted certificates."""

    async def operation(client: AsyncJ100Client) -> OperationResult:
        certificates = await client.trusted_certificates()
        return OperationResult("success", certificates)

    results = asyncio.run(
        _run_batch(hosts, password, insecure, concurrency, operation, timeout)
    )
    if json_output:
        click.echo(
            json.dumps(
                [
                    {"host": result.host, "trust_certs": result.message}
                    if result.status != "error"
                    else asdict(result)
                    for result in results
                ]
            )
        )
    else:
        for result in results:
            if result.status == "error":
                click.echo(f"{result.host}: error: {result.message}")
            else:
                click.echo(f"{result.host}: {','.join(result.message)}")
    if any(result.status == "error" for result in results):
        raise click.exceptions.Exit(1)


@main.command("import-trust-cert")
@click.option(
    "--certificate",
    "certificate_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Local trusted certificate to upload.",
)
@click.option(
    "--timeout", default=10.0, show_default=True, type=click.FloatRange(min=1.0)
)
@_batch_options
def import_trust_cert(
    hosts,
    password,
    insecure,
    concurrency,
    json_output,
    certificate_path,
    timeout,
):
    """Import a trusted certificate."""
    content = certificate_path.read_bytes()

    async def operation(client: AsyncJ100Client) -> str:
        await client.import_trusted_certificate(certificate_path.name, content)
        return "trusted certificate imported"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )


@main.command("generate-report")
@click.option(
    "--output-dir", default=None, help="Directory for downloaded reports."
)
@click.option(
    "--filename", default=None, help="Basename for downloaded reports."
)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    type=click.FloatRange(min=1.0),
    help="Maximum seconds to wait for report generation.",
)
@_batch_options
def generate_report(
    hosts: Sequence[str],
    password: str,
    insecure: bool,
    concurrency: int,
    json_output: bool,
    output_dir: Optional[str],
    filename: Optional[str],
    timeout: float,
) -> None:
    """Generate and download phone report."""

    async def operation(client: AsyncJ100Client) -> str:
        report = await client.generate_phone_report()
        path: Path = client.save_phone_report(report, output_dir, filename)
        return f"phone report saved to {path}"

    _run_and_render(
        hosts, password, insecure, concurrency, json_output, operation, timeout
    )
