import argparse
import os
import sys

from ..common import require_and_load_config
from ..config import RootConfig, _parse_dns
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
from qrcode.image.styles.colormasks import HorizontalGradiantColorMask


def add_emit_configs_cmd(subparsers: argparse._SubParsersAction) -> None:
    c = subparsers.add_parser(
        "emit-configs",
        help="Emit WireGuard configs (server/clients) based on config file",
        description="Generate WireGuard configuration files under server and clients paths relative to the config file.",
    )
    c.add_argument("-c", "--config", default=os.environ.get("WGHS_CONFIG", "config.yml"), help="Path to config file")
    group = c.add_mutually_exclusive_group()
    group.add_argument("--only-server", action="store_true", help="Emit only server config")
    group.add_argument("--only-clients", action="store_true", help="Emit only client configs")
    qr = c.add_mutually_exclusive_group()
    qr.add_argument("--qr", dest="qr", action="store_true", default=None, help="Force QR generation ON")
    qr.add_argument("--no-qr", dest="qr", action="store_false", help="Force QR generation OFF")
    c.add_argument("--client-dns", default=None, help="Override client DNS (comma-separated)")
    c.add_argument("--client-allowed-ips", default=None, help="Override client AllowedIPs (comma-separated)")
    c.add_argument("--endpoint", default=None, help="Override server endpoint host:port for clients")
    c.set_defaults(func=run_emit_configs_cmd)


def run_emit_configs_cmd(args: argparse.Namespace) -> int:
    cfg, cfg_path = require_and_load_config(args)
    if cfg is None or cfg_path is None:
        return 2

    # Determine which to emit
    emit_server = True
    emit_clients = True
    if args.only_server:
        emit_clients = False
    if args.only_clients:
        emit_server = False

    # Resolve overrides (guard for tests constructing SimpleNamespace)
    qr_arg = getattr(args, "qr", None)
    qr_emit = cfg.emit_qr if qr_arg is None else bool(qr_arg)
    dns_arg = getattr(args, "client_dns", None)
    client_dns = _parse_dns(dns_arg) if dns_arg else None
    client_allowed_ips = getattr(args, "client_allowed_ips", None)
    endpoint_override = getattr(args, "endpoint", None)

    rc = 0
    if emit_server:
        rc |= _emit_server(cfg, cfg_path)
    if emit_clients:
        rc |= _emit_clients(
            cfg,
            cfg_path,
            qr_emit=qr_emit,
            client_dns=client_dns,
            client_allowed_ips=client_allowed_ips,
            endpoint_override=endpoint_override,
        )
    return rc


def _emit_server(cfg: RootConfig, cfg_path: str) -> int:
    server_dir = cfg.resolve_server_dir(cfg_path)
    os.makedirs(server_dir, exist_ok=True)
    out_path = os.path.join(server_dir, f"{cfg.server.name}.conf")
    text = _render_server_conf(cfg, cfg_path)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    return 0


def _emit_clients(
    cfg: RootConfig,
    cfg_path: str,
    *,
    qr_emit: bool,
    client_dns: list[str] | None,
    client_allowed_ips: str | None,
    endpoint_override: str | None,
) -> int:
    clients_dir = cfg.resolve_clients_dir(cfg_path)
    os.makedirs(clients_dir, exist_ok=True)
    rc = 0
    for c in cfg.clients:
        if not c.enabled:
            continue
        out = os.path.join(clients_dir, f"{c.name}.conf")
        text = _render_client_conf(
            cfg,
            cfg_path,
            c,
            client_dns=client_dns,
            client_allowed_ips=client_allowed_ips,
            endpoint_override=endpoint_override,
        )
        if text is None:
            rc |= 1
            continue
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(out, 0o600)
        except OSError:
            pass
        # Generate QR code if enabled
        if qr_emit:
            qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_Q)
            qr.add_data(text)
            qr.make(fit=True)
            # Diagonal/linear gradient approximation: left (purple) -> right (blue) with rounded modules
            color_mask = HorizontalGradiantColorMask(
                back_color=(255, 255, 255),
                left_color=(128, 0, 255),   # purple
                right_color=(0, 123, 255),  # blue
            )
            img = qr.make_image(
                image_factory=StyledPilImage,
                module_drawer=RoundedModuleDrawer(),
                color_mask=color_mask,
            )
            img_path = os.path.join(clients_dir, f"{c.name}.png")
            img.save(img_path)
    return rc


def _render_server_conf(cfg: RootConfig, cfg_path: str) -> str:
    s = cfg.server
    lines: list[str] = []

    lines.append("[Interface]\n")
    # Address: ensure single IP or comma-separated are supported (config has single CIDR string)
    lines.append(f"Address = {s.address}\n")
    if s.mtu:
        lines.append(f"MTU = {int(s.mtu)}\n")
    if s.listen_port:
        lines.append(f"ListenPort = {int(s.listen_port)}\n")
    if s.private_key:
        lines.append(f"PrivateKey = {s.private_key}\n")
    if s.dns:
        # WireGuard supports DNS in interface; split list
        dns_str = ", ".join(s.dns)
        lines.append(f"DNS = {dns_str}\n")
    # AmneziaWG parameters (must be same on server and clients except Jc/Jmin/Jmax may vary)
    if cfg.amnezia.enabled:
        for key in (
            "Jc",
            "Jmin",
            "Jmax",
            "S1",
            "S2",
            "H1",
            "H2",
            "H3",
            "H4",
            "I1",
            "I2",
            "I3",
            "I4",
            "I5",
        ):
            val = getattr(cfg.amnezia, key)
            if val is not None:
                lines.append(f"{key} = {val}\n")
    # Hooks
    if s.pre_up:
        lines.append(f"PreUp = {s.pre_up}\n")
    if s.post_up:
        lines.append(f"PostUp = {s.post_up}\n")
    if s.pre_down:
        lines.append(f"PreDown = {s.pre_down}\n")
    if s.post_down:
        lines.append(f"PostDown = {s.post_down}\n")
    # Addition for automation systems
    lines.append("# INTERFACE CUSTOM SECTION START\n")
    lines.append("# INTERFACE CUSTOM SECTION END\n")

    # Peers from clients
    for c in cfg.clients:
        if not c.enabled:
            continue
        if not c.public_key:
            continue
        lines.append("\n[Peer]\n")
        lines.append(f"PublicKey = {c.public_key}\n")
        if c.preshared_key:
            lines.append(f"PresharedKey = {c.preshared_key}\n")
        if c.address:
            allowed = c.address if "/" in c.address else f"{c.address}/32"
            lines.append(f"AllowedIPs = {allowed}\n")

    return "".join(lines)


def _render_client_conf(
    cfg: RootConfig,
    cfg_path: str,
    c,
    *,
    client_dns: list[str] | None,
    client_allowed_ips: str | None,
    endpoint_override: str | None,
) -> str | None:
    s = cfg.server
    # Required fields check
    if not c.private_key or not c.address or not s.public_key:
        missing = []
        if not c.private_key:
            missing.append("client.private_key")
        if not c.address:
            missing.append("client.address")
        if not s.public_key:
            missing.append("server.public_key")
        print(f"Skipping client '{getattr(c, 'name', '?')}': missing {', '.join(missing)}", file=sys.stderr)
        return None
    endpoint = None
    if endpoint_override:
        endpoint = endpoint_override
    elif s.public_host and s.listen_port:
        endpoint = f"{s.public_host}:{int(s.listen_port)}"

    lines: list[str] = []
    lines.append("[Interface]\n")
    lines.append(f"PrivateKey = {c.private_key}\n")
    addr = c.address if "/" in c.address else f"{c.address}/32"
    lines.append(f"Address = {addr}\n")
    selected_dns = client_dns if client_dns is not None else cfg.server.dns
    if selected_dns:
        dns_str = ", ".join(selected_dns)
        lines.append(f"DNS = {dns_str}\n")
    # AmneziaWG parameters (copy from global config; Jc/Jmin/Jmax allowed to vary if configured)
    if cfg.amnezia.enabled:
        for key in (
            "Jc",
            "Jmin",
            "Jmax",
            "S1",
            "S2",
            "H1",
            "H2",
            "H3",
            "H4",
            "I1",
            "I2",
            "I3",
            "I4",
            "I5",
        ):
            val = getattr(cfg.amnezia, key)
            if val is not None:
                lines.append(f"{key} = {val}\n")
    # Custom interface section for automation systems
    lines.append("# INTERFACE CUSTOM SECTION START\n")
    lines.append("# INTERFACE CUSTOM SECTION END\n")

    lines.append("\n[Peer]\n")
    lines.append(f"PublicKey = {s.public_key}\n")
    if c.preshared_key:
        lines.append(f"PresharedKey = {c.preshared_key}\n")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}\n")
    allowed_ips = client_allowed_ips or "0.0.0.0/0, ::/0"
    lines.append(f"AllowedIPs = {allowed_ips}\n")
    if c.persistent_keepalive is not None:
        lines.append(f"PersistentKeepalive = {int(c.persistent_keepalive)}\n")
    return "".join(lines)
