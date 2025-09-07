import argparse
import os
import sys

from ..common import require_and_load_config


def add_client_remove_cmd(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "client-remove",
        help="Remove an existing client by name",
        description="Removes a client from the config by name.",
    )
    p.add_argument("name", help="Client name")
    p.add_argument("-c", "--config", default=os.environ.get("WGHS_CONFIG", "config.yml"), help="Path to config file")
    p.set_defaults(func=run_client_remove_cmd)


def run_client_remove_cmd(args: argparse.Namespace) -> int:
    cfg, cfg_path = require_and_load_config(args)
    if cfg is None or cfg_path is None:
        return 2

    name = args.name
    orig_len = len(cfg.clients)
    cfg.clients = [c for c in cfg.clients if c.name != name]
    if len(cfg.clients) == orig_len:
        print(f"Client '{name}' not found", file=sys.stderr)
        return 2

    cfg.write_file(cfg_path, overwrite=True)
    print(f"Client '{name}' removed")
    return 0
