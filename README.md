# j100-client

Python 3.9+ client and CLI for the Avaya J100 phone Web UI.

The current MVP supports authenticated login checks, password bootstrap after a
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

At runtime the client selects a compatible `httpx2` installation first, then
`httpx`, then the threaded `requests` fallback. The fallback needs no `anyio`.

## Restart A Phone

```bash
uv run j100-client restart --ip 10.10.10.1 --password 'your-password'
```

The username defaults to `admin`. Use `--username` to override it. TLS
certificate verification is enabled by default. For a lab phone with a
self-signed certificate, opt in explicitly:

```bash
uv run j100-client restart --ip 10.10.10.1 --password 'your-password' --insecure
```

Use `--force` only when it is acceptable to restart a phone with an active
call. The command returns immediately after the phone accepts the restart
request. Add `--wait` only when a workflow needs to wait for recovery. J169
phones typically need at least four minutes; J139 phones and firmware upgrades
can take longer. Use `--timeout` and `--poll-interval` with `--wait` to suit
your firmware and network.

Passwords passed through `--password` can be visible to other local users in
process listings. Use this MVP interface only in environments where that risk
is acceptable.

## Factory Reset

Factory reset erases phone configuration and restarts the device. It requires
an explicit `--force` confirmation and will still refuse to run if the phone
reports an active call:

```bash
uv run j100-client reset-to-default --ip 10.10.10.1 --password 'your-password' --force
```

The command returns immediately after the reset request is accepted. Add
`--wait` to observe recovery, but do not assume the phone retains its address
or network configuration after factory reset.

## Login Check

Use `login` to confirm that the Web UI responds and accepts the supplied
credentials:

```bash
uv run j100-client login --ip 10.10.10.1 --password 'your-password'
```

It exits with status 0 on success, 1 when the Web UI or TLS connection is not
available, and 2 when the phone rejects the credentials.

## Set Factory-Default Password

Immediately after a factory reset, use `set-password` to replace the Web UI
default password (`27238`). The command always authenticates as `admin` with
that default password and accepts the replacement password through `--password`:

```bash
uv run j100-client set-password --ip 10.10.10.1 --password 'NewPassword1!'
```

The replacement must be 6 through 31 permitted J100 Web UI characters and
include a letter, digit, and supported special character. It cannot be `27238`.

## Configure Provisioning Servers

Use `configure-servers` to update one or more provisioning download settings.
The option names match the canonical J100 parameter names. Only options supplied
on the command line are changed:

```bash
uv run j100-client configure-servers --ip 10.10.10.1 --password 'your-password' \
  --HTTPSRVR provisioning.example --HTTPDIR /j100 --HTTPPORT 80
```

Supported settings are `--HTTPSRVR`, `--TLSSRVR`, `--HTTPDIR`, `--TLSDIR`,
`--HTTPPORT`, and `--TLSPORT`. As with other commands, use `--insecure` only
when connecting to a self-signed lab certificate.
