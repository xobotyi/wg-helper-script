# wg-helper-script

WireGuard helper CLI for initializing, validating, and emitting server/client configs with optional QR codes. Includes
client management (add/disable/remove) and AmneziaWG parameters.

## Features

- Initialize a secure YAML config (`init`) with generated keys.
- Validate configuration (`validate-cfg`).
- Emit server and client `.conf` files and client QR codes (`emit-configs`).
- Manage clients: `client-add`, `client-disable`, `client-remove`.

## Install

```bash
python -m pip install wg-helper-script
```

## Quickstart

```bash
wg-helper-script init -o config.yml --overwrite
wg-helper-script validate-cfg -c config.yml
wg-helper-script emit-configs -c config.yml
```

Run with module if not installed: `python -m wg_helper_script ...`.

Requires Python 3.11+.

## Configuration

- YAML file (default `./config.yml`). Paths inside are relative to the config location.
- Environment overrides: prefix `WGHS_` (e.g., `WGHS_CONFIG`, `WGHS_SERVER_NAME`, `WGHS_SERVER_DNS`).

Server keys: if both are omitted on init, a valid keypair is generated. Validation ensures keys are well‑formed and
match when both present.

## Commands

- `init`: Generate initial config. Flags mirror env vars (e.g., `--server-name`, `--server-dns`).
- `validate-cfg`: Load and validate a config file.
- `emit-configs`: Write server/client configs under `server-path`/`clients-path`. Use `--only-server` or
  `--only-clients`. QR generation can be disabled by (`--qr/--no-qr`).
- `client-add NAME`: Adds a client with next free IP, keys, psk.
- `client-disable NAME`: Marks a client disabled.
- `client-remove NAME`: Removes a client.

## Init Options

The `init` command accepts flags and/or `WGHS_*` environment variables. Unspecified Amnezia fields are auto‑generated
within recommended ranges when Amnezia is enabled.

| Flag                                             | Env var                   | Type   | Default            | Description                                 |
|--------------------------------------------------|---------------------------|--------|--------------------|---------------------------------------------|
| `-o, --output`                                   | `WGHS_OUTPUT`             | path   | `config.yml`       | Output config path                          |
| `--overwrite`                                    | –                         | bool   | `false`            | Overwrite existing file                     |
| `--clients-path`                                 | `WGHS_CLIENTS_PATH`       | str    | `clients`          | Relative clients dir                        |
| `--server-path`                                  | `WGHS_SERVER_PATH`        | str    | `server`           | Relative server dir                         |
| `--emit-qr` <br/> `--no-emit-qr`                 | `WGHS_EMIT_QR`            | bool   | `true`             | Emit client QR PNGs                         |
| `--amnezia-enabled` <br/> `--no-amnezia-enabled` | `WGHS_AMNEZIA_ENABLED`    | bool   | `true`             | Toggle AmneziaWG fields                     |
| `--amnezia-jc`                                   | `WGHS_AMNEZIA_JC`         | str    | random             | Amnezia `Jc`                                |
| `--amnezia-jmin`                                 | `WGHS_AMNEZIA_JMIN`       | str    | random             | Amnezia `Jmin`                              |
| `--amnezia-jmax`                                 | `WGHS_AMNEZIA_JMAX`       | str    | random             | Amnezia `Jmax`                              |
| `--amnezia-s1`                                   | `WGHS_AMNEZIA_S1`         | str    | random             | Amnezia `S1`                                |
| `--amnezia-s2`                                   | `WGHS_AMNEZIA_S2`         | str    | random             | Amnezia `S2`                                |
| `--amnezia-h[1-4]`                               | `WGHS_AMNEZIA_H[1-4]`     | str    | random             | Amnezia `H1-4`                              |
| `--amnezia-i[1-5]`                               | `WGHS_AMNEZIA_I[1-5]`     | str    | none               | Amnezia `I1-5`                              |
| `--server-name`                                  | `WGHS_SERVER_NAME`        | str    | `wg0`              | Interface name                              |
| `--server-private-key`                           | `WGHS_SERVER_PRIVATE_KEY` | base64 | autogenerate       | Server private key (32‑byte base64)         |
| `--server-public-key`                            | `WGHS_SERVER_PUBLIC_KEY`  | base64 | autogenerate       | Server public key (derived if both missing) |
| `--server-public-host`                           | `WGHS_SERVER_PUBLIC_HOST` | str    | –                  | Public host/IP for clients                  |
| `--server-address`                               | `WGHS_SERVER_ADDRESS`     | CIDR   | `10.10.10.1/24`    | Server address/CIDR                         |
| `--server-listen-port`                           | `WGHS_SERVER_LISTEN_PORT` | int    | `51821`            | Server `ListenPort`                         |
| `--server-mtu`                                   | `WGHS_SERVER_MTU`         | int    | `1380`             | Interface MTU                               |
| `--server-dns`                                   | `WGHS_SERVER_DNS`         | str    | `1.1.1.1, 8.8.8.8` | Comma‑separated DNS list                    |
| `--server-pre-up`                                | `WGHS_SERVER_PRE_UP`      | str    | –                  | `PreUp` hook                                |
| `--server-post-up`                               | `WGHS_SERVER_POST_UP`     | str    | –                  | `PostUp` hook                               |
| `--server-pre-down`                              | `WGHS_SERVER_PRE_DOWN`    | str    | –                  | `PreDown` hook                              |
| `--server-post-down`                             | `WGHS_SERVER_POST_DOWN`   | str    | –                  | `PostDown` hook                             |

## Security Notes

- Do not commit real private keys. Examples are placeholders.
- Emitted configs and `config.yml` are written with `0600` permissions on POSIX.
