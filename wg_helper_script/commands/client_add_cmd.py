import argparse
import ipaddress
import os
import sys
from datetime import datetime, timezone

from ..common import require_and_load_config
from ..config import ClientConfig, generate_wg_keypair, generate_preshared_key, WireGuardKey


def add_client_add_cmd(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "client-add",
        help="Add a new client (auto-populated settings)",
        description="Adds a client with generated keys, preshared key, and the next available IP in the server subnet.",
    )
    p.add_argument("name", help="Client name")
    p.add_argument("-c", "--config", default=os.environ.get("WGHS_CONFIG", "config.yml"), help="Path to config file")
    p.set_defaults(func=run_client_add_cmd)


def run_client_add_cmd(args: argparse.Namespace) -> int:
    cfg, cfg_path = require_and_load_config(args)
    if cfg is None or cfg_path is None:
        return 2

    name = args.name.strip()
    if not name:
        print("Client name must be non-empty", file=sys.stderr)
        return 2

    # Ensure unique name
    for c in cfg.clients:
        if c.name == name:
            print(f"Client '{name}' already exists", file=sys.stderr)
            return 2

    # Generate keys
    priv, pub = generate_wg_keypair()
    psk = generate_preshared_key()

    # Determine next free IP in the server subnet
    server_if = ipaddress.ip_interface(str(cfg.server.address))
    network = server_if.network
    used = set()
    used.add(str(server_if.ip))
    for c in cfg.clients:
        if c.address:
            used.add(str(ipaddress.ip_address(c.address)))
    next_ip = None
    for host in network.hosts():
        ip_str = str(host)
        if ip_str not in used:
            next_ip = ip_str
            break
    if next_ip is None:
        print("No available IP addresses in the server subnet", file=sys.stderr)
        return 2

    now_iso = datetime.now(timezone.utc).isoformat()
    new_client = ClientConfig(
        name=name,
        enabled=True,
        address=next_ip,
        private_key=WireGuardKey(priv),
        public_key=WireGuardKey(pub),
        preshared_key=WireGuardKey(psk),
        persistent_keepalive=25,
        created_at=now_iso,
        updated_at=now_iso,
    )
    cfg.clients.append(new_client)

    # Ensure Amnezia defaults if enabled
    cfg.amnezia.ensure_recommended_defaults()
    # Validate and write
    errs = cfg.validate()
    if errs:
        for e in errs:
            print(f"- {e}", file=sys.stderr)
        return 2
    cfg.write_file(cfg_path, overwrite=True)
    print(f"Client '{name}' added with IP {next_ip}")
    return 0
