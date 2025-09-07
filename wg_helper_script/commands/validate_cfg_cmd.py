import argparse
import os
import sys

from ..config import RootConfig


def add_validate_cfg_cmd(subparsers: argparse._SubParsersAction) -> None:
    v = subparsers.add_parser(
        "validate-cfg",
        help="Load and validate a config file",
        description="Loads a YAML config and validates its structure and values.",
    )
    v.add_argument(
        "-c",
        "--config",
        default=os.environ.get("WGHS_CONFIG", "config.yml"),
        help="Path to config file (env: WGHS_CONFIG). Default: config.yml",
    )
    v.set_defaults(func=run_validate_cfg_cmd)


def run_validate_cfg_cmd(args: argparse.Namespace) -> int:
    path = args.config
    if not os.path.exists(path):
        print(f"Config file not found: {path}", file=sys.stderr)
        return 2
    try:
        cfg = RootConfig.read_file(path)
    except Exception as e:
        print(f"Failed to parse config: {e}", file=sys.stderr)
        return 2

    errs = cfg.validate()
    if errs:
        print("Invalid configuration:", file=sys.stderr)
        for err in errs:
            print(f"- {err}", file=sys.stderr)
        return 2

    print("Configuration is valid.")
    return 0
