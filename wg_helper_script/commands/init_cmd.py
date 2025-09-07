import argparse
import os
import sys

from ..config import RootConfig, generate_wg_keypair


def add_init_cmd(subparsers: argparse._SubParsersAction) -> None:
    init = subparsers.add_parser(
        "init",
        help="Generate initial config YAML (no clients)",
        description="Generate initial config YAML (no clients). Values can come from env (WGHS_*) and flags.",
    )

    # Output and global paths
    init.add_argument(
        "-o",
        "--output",
        default=os.environ.get("WGHS_OUTPUT", "config.yml"),
        help="Path to write the generated config (env: WGHS_OUTPUT). Default: config.yml",
    )
    init.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output file if it exists",
    )

    init.add_argument("--clients-path", default=None,
                      help="Relative path to clients directory (env: WGHS_CLIENTS_PATH).")
    init.add_argument("--server-path", default=None, help="Relative path to server directory (env: WGHS_SERVER_PATH).")

    emit_qr_group = init.add_mutually_exclusive_group()
    emit_qr_group.add_argument("--emit-qr", dest="emit_qr", action="store_true", default=None, help="Emit QR codes")
    emit_qr_group.add_argument("--no-emit-qr", dest="emit_qr", action="store_false", help="Disable QR emission")
    init.set_defaults(emit_qr=None)

    # Amnezia WG obfuscation parameters
    amn = init.add_argument_group("amnezia")
    amn_enabled = amn.add_mutually_exclusive_group()
    amn_enabled.add_argument("--amnezia-enabled", dest="amnezia_enabled", action="store_true", default=None)
    amn_enabled.add_argument("--no-amnezia-enabled", dest="amnezia_enabled", action="store_false")
    init.set_defaults(amnezia_enabled=None)

    def add_amn_opt(flag: str) -> None:
        amn.add_argument(f"--amnezia-{flag}", default=None)

    for k in ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"):
        add_amn_opt(k)

    # Server block
    srv = init.add_argument_group("server")
    srv.add_argument("--server-name", default=None)
    srv.add_argument("--server-private-key", default=None)
    srv.add_argument("--server-public-key", default=None)
    srv.add_argument("--server-public-host", default=None)
    srv.add_argument("--server-address", default=None)
    srv.add_argument("--server-listen-port", type=int, default=None)
    srv.add_argument("--server-mtu", type=int, default=None)
    srv.add_argument("--server-dns", default=None)
    srv.add_argument("--server-pre-up", default=None)
    srv.add_argument("--server-post-up", default=None)
    srv.add_argument("--server-pre-down", default=None)
    srv.add_argument("--server-post-down", default=None)

    init.set_defaults(func=run_init_cmd)


def run_init_cmd(args: argparse.Namespace) -> int:
    out_path = args.output
    if os.path.exists(out_path) and not args.overwrite:
        print(f"Refusing to overwrite existing file: {out_path}. Use --overwrite to replace.", file=sys.stderr)
        return 2

    cfg = RootConfig.from_env(os.environ)
    cfg.apply_args_overrides(args)
    # If Amnezia is enabled, fill defaults within recommended ranges
    cfg.amnezia.ensure_recommended_defaults()
    # Generate keypair if both keys are missing
    if cfg.server.private_key is None and cfg.server.public_key is None:
        priv, pub = generate_wg_keypair()
        from ..config import WireGuardKey
        cfg.server.private_key = WireGuardKey(priv)
        cfg.server.public_key = WireGuardKey(pub)

    errs = cfg.validate()
    if errs:
        print("Config validation failed:", file=sys.stderr)
        for e in errs:
            print(f"- {e}", file=sys.stderr)
        return 2

    cfg.write_file(out_path, overwrite=args.overwrite)
    print(f"Config written to {out_path}")
    return 0
