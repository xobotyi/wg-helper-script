import argparse
import os
import sys
from datetime import datetime, timezone

from ..common import require_and_load_config


def add_client_disable_cmd(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "client-disable",
        help="Disable a client by name",
        description="Marks a client as disabled.",
    )
    p.add_argument("name", help="Client name")
    p.add_argument("-c", "--config", default=os.environ.get("WGHS_CONFIG", "config.yml"), help="Path to config file")
    p.set_defaults(func=run_client_disable_cmd)


def run_client_disable_cmd(args: argparse.Namespace) -> int:
    cfg, cfg_path = require_and_load_config(args)
    if cfg is None or cfg_path is None:
        return 2

    name = args.name
    found = False
    now_iso = datetime.now(timezone.utc).isoformat()
    for c in cfg.clients:
        if c.name == name:
            c.enabled = False
            c.updated_at = now_iso
            found = True
            break
    if not found:
        print(f"Client '{name}' not found", file=sys.stderr)
        return 2

    cfg.write_file(cfg_path, overwrite=True)
    print(f"Client '{name}' disabled")
    return 0
