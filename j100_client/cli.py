"""Click command line interface."""

from typing import Optional

import click

from .client import J100Client
from .exceptions import AuthenticationError, J100Error, TransportError


@click.group()
def main() -> None:
    """Manage Avaya J100 phones through their Web UI."""


@main.command()
@click.option("--ip", "host", required=True, help="Phone IP address or hostname.")
@click.option("--password", required=True, hide_input=False, help="Web UI password.")
@click.option("--username", default="admin", show_default=True, help="Web UI username.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
@click.option("--force", is_flag=True, help="Restart even if the phone reports an active call.")
@click.option("--wait", is_flag=True, help="Wait until the phone is reachable after restarting.")
@click.option("--timeout", default=300.0, show_default=True, type=click.FloatRange(min=1.0), help="Maximum seconds to wait when --wait is set.")
@click.option("--poll-interval", default=5.0, show_default=True, type=click.FloatRange(min=0.1), help="Seconds between checks when --wait is set.")
def restart(host: str, password: str, username: str, insecure: bool, force: bool, wait: bool, timeout: float, poll_interval: float) -> None:
    """Restart a phone after authenticated idle-state checks."""
    client = J100Client(host, username=username, password=password, verify=not insecure)
    try:
        result = client.restart(force=force, wait=wait, timeout=timeout, poll_interval=poll_interval)
    except J100Error as error:
        raise click.ClickException(str(error))
    finally:
        client.close()
    if result.completed:
        click.echo("Restart completed.")
    else:
        click.echo("Restart accepted.")


@main.command("reset-to-default")
@click.option("--ip", "host", required=True, help="Phone IP address or hostname.")
@click.option("--password", required=True, hide_input=False, help="Web UI password.")
@click.option("--username", default="admin", show_default=True, help="Web UI username.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
@click.option("--force", is_flag=True, help="Confirm destructive factory reset.")
@click.option("--wait", is_flag=True, help="Wait until the phone is reachable after reset.")
@click.option("--timeout", default=300.0, show_default=True, type=click.FloatRange(min=1.0), help="Maximum seconds to wait when --wait is set.")
@click.option("--poll-interval", default=5.0, show_default=True, type=click.FloatRange(min=0.1), help="Seconds between checks when --wait is set.")
def reset_to_default(host: str, password: str, username: str, insecure: bool, force: bool, wait: bool, timeout: float, poll_interval: float) -> None:
    """Erase phone configuration and restore factory defaults."""
    client = J100Client(host, username=username, password=password, verify=not insecure)
    try:
        result = client.reset_to_default(force=force, wait=wait, timeout=timeout, poll_interval=poll_interval)
    except J100Error as error:
        raise click.ClickException(str(error))
    finally:
        client.close()
    if result.completed:
        click.echo("Factory reset completed.")
    else:
        click.echo("Factory reset accepted.")


@main.command()
@click.option("--ip", "host", required=True, help="Phone IP address or hostname.")
@click.option("--password", required=True, hide_input=False, help="Web UI password.")
@click.option("--username", default="admin", show_default=True, help="Web UI username.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
def login(host: str, password: str, username: str, insecure: bool) -> None:
    """Verify that the Web UI is reachable and credentials are valid."""
    client = J100Client(host, username=username, password=password, verify=not insecure)
    try:
        client.login()
    except AuthenticationError as error:
        click.echo(f"Error: {error}", err=True)
        raise click.exceptions.Exit(2)
    except TransportError as error:
        click.echo(f"Error: {error}", err=True)
        raise click.exceptions.Exit(1)
    finally:
        client.close()
    click.echo("Login successful.")


@main.command("set-password")
@click.option("--ip", "host", required=True, help="Phone IP address or hostname.")
@click.option("--password", required=True, hide_input=False, help="New Web UI password.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
def set_password(host: str, password: str, insecure: bool) -> None:
    """Set the password on a factory-reset phone."""
    if password == "27238":
        raise click.ClickException("replacement password must not be the factory default")
    client = J100Client(host, verify=not insecure)
    try:
        client.set_factory_default_password(password)
    except J100Error as error:
        raise click.ClickException(str(error))
    finally:
        client.close()
    click.echo("Password changed.")


@main.command("configure-servers")
@click.option("--ip", "host", required=True, help="Phone IP address or hostname.")
@click.option("--password", required=True, hide_input=False, help="Web UI password.")
@click.option("--username", default="admin", show_default=True, help="Web UI username.")
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification.")
@click.option("--HTTPSRVR", default=None, help="HTTPS download server list.")
@click.option("--TLSSRVR", default=None, help="HTTP download server list.")
@click.option("--HTTPDIR", default=None, help="HTTP download directory.")
@click.option("--TLSDIR", default=None, help="TLS download directory.")
@click.option("--HTTPPORT", default=None, help="HTTP download port.")
@click.option("--TLSPORT", default=None, help="TLS download port.")
def configure_servers(
    host: str,
    password: str,
    username: str,
    insecure: bool,
    httpsrvr: Optional[str],
    tlssrvr: Optional[str],
    httpdir: Optional[str],
    tlsdir: Optional[str],
    httpport: Optional[str],
    tlsport: Optional[str],
) -> None:
    """Update one or more provisioning download server settings."""
    client = J100Client(host, username=username, password=password, verify=not insecure)
    try:
        client.configure_servers(
            HTTPSRVR=httpsrvr,
            TLSSRVR=tlssrvr,
            HTTPDIR=httpdir,
            TLSDIR=tlsdir,
            HTTPPORT=httpport,
            TLSPORT=tlsport,
        )
    except (J100Error, ValueError) as error:
        raise click.ClickException(str(error))
    finally:
        client.close()
    click.echo("Server configuration updated.")
