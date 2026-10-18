# j100-client

Python 3.9+ client and CLI for the Avaya J100 phone Web UI.

The current MVP supports authenticated verification checks, password bootstrap after a
factory reset, restart, factory reset, and provisioning download server
configuration. Packet capture, live logs, and other Web UI operations are not
implemented yet.

Run the CLI through its installed command or as a Python module:

```bash
uv run j100-client --help
uv run -m j100_client --help
```

## Installation

The base installation requires only `requests` and `click`:

```bash
uv sync
```

Optional native transports can be installed with:

```bash
uv sync --extra httpx
uv sync --extra httpx2
```

## Single-File Bundle

Build a compression-only standalone bundle:

```bash
uv run python scripts/build_single_file.py --output-dir dist
```

Use `--valid-days N` to expire the bundle exactly `N * 24` hours after
generation. Timed bundles display a validity comment; enforcement stays inside
the compressed payload. Bundles are not encrypted or signed.

At runtime the client selects a compatible `httpx2` installation first, then
`httpx`, then the threaded `requests` fallback. The fallback needs no `anyio`.

## Run Commands On Phones

Every phone-targeting command takes one or more positional hosts. Commands run
up to 10 phone operations concurrently by default; use `--concurrency` to set
another positive limit:

```bash
uv run j100-client restart --password 'your-password' \
  10.10.10.1 10.10.10.2 10.10.10.3
```

By default, output contains one ordered `host: result` line per phone. Add
`--json` to write one JSON result array for scripts. The command exits 0 only
when every phone succeeds, 1 when any phone operation fails, and 2 for invalid
usage before contacting a phone. Replace legacy `--ip <host>` usage with a
trailing `<host>` argument.

`status`, `set-password`, `configure-servers`, and `configure-snmp` use a
10-second request timeout by default. Pass `--timeout <seconds>` to tune that
limit for every target in a batch. `restart` uses a 10-second request timeout
without `--wait` and a 300-second recovery timeout with it. `reset-to-default`
and `generate-report` retain their existing timeout defaults.

## Restart A Phone

### CLI

```bash
uv run j100-client restart --password 'your-password' 10.10.10.1
```

### Python API

```python
from j100_client import J100Client

client = J100Client("10.10.10.1", password="your-password")
try:
    client.restart(wait=False)
finally:
    client.close()
```

J100 Web UI authentication always uses the built-in `admin` username. TLS
certificate verification is enabled by default. For a lab phone with a
self-signed certificate, opt in explicitly:

```bash
uv run j100-client restart --insecure --password 'your-password' 10.10.10.1
```

Restart is refused while the phone reports an active call. Without `--wait`, a
phone request times out after 10 seconds by default. Add `--wait` only when a
workflow needs to wait for recovery; its default recovery timeout is 300
seconds. J169 phones typically need at least four minutes; J139 phones and
firmware upgrades can take longer. Use `--timeout` and `--poll-interval` with
`--wait` to suit your firmware and network. An explicit `--timeout` also sets
the HTTP request timeout.

Passwords passed through `--password` can be visible to other local users in
process listings. Use this MVP interface only in environments where that risk
is acceptable.

## Factory Reset

Factory reset erases phone configuration and restarts the device. Its `--force`
option is an explicit destructive-action confirmation; it will still refuse to
run if the phone reports an active call:

```bash
uv run j100-client reset-to-default --password 'your-password' --force 10.10.10.1
```

The command returns immediately after the reset request is accepted. Add
`--wait` to observe recovery, but do not assume the phone retains its address
or network configuration after factory reset.

## Phone Status

Use `status` to confirm that the Web UI responds and accepts the supplied
credentials, then report whether each phone is idle or handling an active call:

```bash
uv run j100-client status --password 'your-password' 10.10.10.1
```

Status checks never submit a restart request. A reachable authenticated phone
reports `idle` or `busy`, and either result exits with status 0. Unreachable
phones, rejected credentials, and other request failures report `error` with an
actionable message and cause the batch to exit with status 1. Add `--json` to
receive the same `idle`, `busy`, or `error` value in each result's `status`
field.

## Packet Capture

Stream a phone-provided `.pcap` file to the current directory for up to five
minutes by default:

```bash
uv run j100-client packet-capture --password 'your-password' 10.10.10.1
```

Use `--max-duration` for an integer duration from 1 through 600 seconds and
`--output-dir` to select a destination. The command starts only the first
`min(hosts, --concurrency, 10)` captures; later hosts are reported as skipped.
Press Ctrl+C to request capture stop for active phones before the command exits.

## Set Factory-Default Password

Immediately after a factory reset, use `set-password` to replace the Web UI
default password (`27238`). The command always authenticates as `admin` with
that default password and accepts the replacement password through `--password`:

```bash
uv run j100-client set-password --password 'NewPassword1!' 10.10.10.1
```

The replacement must be 6 through 31 permitted J100 Web UI characters and
include a letter, digit, and supported special character. It cannot be `27238`.

## Configure Provisioning Servers

Use `configure-servers` to update one or more provisioning download settings.
The option names match the canonical J100 parameter names. Only supplied settings
are changed:

### CLI

```bash
uv run j100-client configure-servers --password 'your-password' \
  --HTTPSRVR provisioning.example --HTTPDIR /j100 --HTTPPORT 80 10.10.10.1
```

### Python API

```python
from j100_client import J100Client

client = J100Client("10.10.10.1", password="your-password")
try:
    client.configure_servers(
        HTTPSRVR="provisioning.example",
        HTTPDIR="/j100",
        HTTPPORT="80",
    )
finally:
    client.close()
```

Supported settings are `--HTTPSRVR`, `--TLSSRVR`, `--HTTPDIR`, `--TLSDIR`,
`--HTTPPORT`, and `--TLSPORT`. As with other commands, use `--insecure` only
when connecting to a self-signed lab certificate.

## Configure SNMP

Use `configure-snmp` to update the SNMP community string or permitted query
sources. Only supplied settings are changed:

```bash
uv run j100-client configure-snmp --password 'your-password' \
  --SNMPSTRING monitoring --SNMPADD 192.0.2.10,monitoring.example 10.10.10.1
```

`--SNMPSTRING` accepts zero through 32 permitted J100 password characters
without whitespace. `--SNMPADD` accepts up to 255 characters without
whitespace and may contain the phone-supported IPv4, IPv6, or DNS source
formats.

Use `--append` with `--SNMPADD` to retain the current source list and append
the supplied sources after a comma. The combined list must remain within 255
characters:

## Configure SIP Global Settings

Configure a manual SIP proxy controller. This forces the phone's proxy policy
to Manual:

```bash
uv run j100-client configure-sip-global --password 'your-password' \
  --SIPDOMAIN example.com \
  --ENABLE_PPM_SOURCED_SIPPROXYSRVR No \
  --SIP_CONTROLLER_LIST '192.168.1.10:5061;transport=tls' 10.10.10.1
```

Use `--automatic-sip-proxy` to restore Automatic proxy discovery. It cannot be
combined with a controller list or PPM source. It does not clear values unless
you explicitly pass `--SIPDOMAIN ''` to clear the SIP domain.

## SIP Account Login And Logout

Log in an unconfigured SIP account after manual SIP proxy settings have been
applied and the phone has rebooted:

```bash
uv run j100-client sip-login --password 'admin-password' \
  --SIPUSERNAME '1000@example.com' --SIPPASSWORD 'sip-password' 10.10.10.1
```

`sip-login` rejects phones with a pending reboot, automatic proxy policy, no
controller, an existing SIP account, or an already registered SIP user.

Log out a registered SIP account without re-entering its SIP credentials:

```bash
uv run j100-client sip-logout --password 'admin-password' 10.10.10.1
```

`sip-logout` reads the registered SIP credentials from each phone and rejects
phones that are not registered or cannot provide complete credentials.

```bash
uv run j100-client configure-snmp --password 'your-password' \
  --append --SNMPADD monitoring.example 10.10.10.1
```

## Generate Phone Report

Use `generate-report` to create and download the authenticated Debugging-page
phone report:

```bash
uv run j100-client generate-report --password 'your-password' 10.10.10.1
```

The report is saved in the current working directory under the filename offered
by the phone. Use `--output-dir` to select another directory and `--filename`
to supply a basename. Existing filenames receive `-1`, `-2`, and so on before
their extension instead of being overwritten. The command waits up to 30
seconds by default; use `--timeout` for phones that need longer to generate a
report.
