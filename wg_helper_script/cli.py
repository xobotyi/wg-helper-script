import argparse
from typing import Callable, Optional

from .commands.init_cmd import add_init_cmd
from .commands.validate_cfg_cmd import add_validate_cfg_cmd
from .commands.emit_configs_cmd import add_emit_configs_cmd
from .commands.client_add_cmd import add_client_add_cmd
from .commands.client_remove_cmd import add_client_remove_cmd
from .commands.client_disable_cmd import add_client_disable_cmd

CommandHandler = Callable[[argparse.Namespace], int]


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wg-helper-script",
        description="WireGuard helper script.",
    )
    # Subcommands are responsible for their own --config options

    sub = p.add_subparsers(dest="command", required=True)
    add_init_cmd(sub)  # init does not require pre-existing config
    add_validate_cfg_cmd(sub)  # validate has own config flag definition for clarity
    add_emit_configs_cmd(sub)
    add_client_add_cmd(sub)
    add_client_remove_cmd(sub)
    add_client_disable_cmd(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    handler: Optional[CommandHandler] = getattr(args, "func", None)
    if handler is None:
        parser.error("No subcommand handler attached")
    return handler(args)
