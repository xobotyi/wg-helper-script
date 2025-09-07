import base64
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, NewType, Optional
import yaml  # type: ignore
import random
import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


ENV_PREFIX = "WGHS_"

# Granular type aliases
InterfaceName = NewType("InterfaceName", str)
CIDR = NewType("CIDR", str)
WireGuardKey = NewType("WireGuardKey", str)
PortNumber = NewType("PortNumber", int)
Mtu = NewType("Mtu", int)
CommandLine = NewType("CommandLine", str)

DnsList = list[str]


@dataclass()
class AmneziaConfig:
    enabled: bool = True
    Jc: Optional[str] = None
    Jmin: Optional[str] = None
    Jmax: Optional[str] = None
    S1: Optional[str] = None
    S2: Optional[str] = None
    H1: Optional[str] = None
    H2: Optional[str] = None
    H3: Optional[str] = None
    H4: Optional[str] = None
    I1: Optional[str] = None
    I2: Optional[str] = None
    I3: Optional[str] = None
    I4: Optional[str] = None
    I5: Optional[str] = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "AmneziaConfig":
        reader = EnvReader(env)
        enabled = reader.get_bool("AMNEZIA_ENABLED", True)
        am = reader.with_prefix("AMNEZIA_")
        return cls(
            enabled=enabled,
            Jc=am.get("JC"),
            Jmin=am.get("JMIN"),
            Jmax=am.get("JMAX"),
            S1=am.get("S1"),
            S2=am.get("S2"),
            H1=am.get("H1"),
            H2=am.get("H2"),
            H3=am.get("H3"),
            H4=am.get("H4"),
            I1=am.get("I1"),
            I2=am.get("I2"),
            I3=am.get("I3"),
            I4=am.get("I4"),
            I5=am.get("I5"),
        )

    def apply_args_overrides(self, args: object) -> None:
        if getattr(args, "amnezia_enabled", None) is not None:
            self.enabled = bool(getattr(args, "amnezia_enabled"))
        for attr, flag in (
            ("Jc", "amnezia_jc"),
            ("Jmin", "amnezia_jmin"),
            ("Jmax", "amnezia_jmax"),
            ("S1", "amnezia_s1"),
            ("S2", "amnezia_s2"),
            ("H1", "amnezia_h1"),
            ("H2", "amnezia_h2"),
            ("H3", "amnezia_h3"),
            ("H4", "amnezia_h4"),
            ("I1", "amnezia_i1"),
            ("I2", "amnezia_i2"),
            ("I3", "amnezia_i3"),
            ("I4", "amnezia_i4"),
            ("I5", "amnezia_i5"),
        ):
            val = getattr(args, flag, None)
            if val is not None:
                setattr(self, attr, val)

    def ensure_recommended_defaults(self) -> None:
        if not self.enabled:
            return
        # Fill only missing values with randomized values in recommended ranges
        if self.Jc is None:
            self.Jc = str(random.randint(4, 12))  # recommended 4..12

        # Jmin/Jmax with constraints (Jmax > Jmin, both below 1280)
        if self.Jmin is None:
            self.Jmin = str(random.randint(8, 64))  # around recommended 8
        jmin = _to_int(self.Jmin) or 8
        if self.Jmax is None:
            low = max(jmin + 1, 40)
            high = 120
            if low > high:
                low = jmin + 1
                high = max(low, 150)
            self.Jmax = str(random.randint(low, high))

        # S1/S2 with constraints and recommended range 15..150
        if self.S1 is None:
            self.S1 = str(random.randint(15, 150))
        s1 = _to_int(self.S1) or 64
        if self.S2 is None:
            # choose S2 avoiding S1 + 56
            choices = [x for x in range(15, 151) if x != s1 + 56]
            self.S2 = str(random.choice(choices))

        # H1..H4 unique, within recommended domain (use a modest range)
        hs = [self.H1, self.H2, self.H3, self.H4]
        if any(h is None for h in hs):
            uniq = random.sample(range(5, 1000), 4)
            if self.H1 is None:
                self.H1 = str(uniq[0])
            if self.H2 is None:
                self.H2 = str(uniq[1])
            if self.H3 is None:
                self.H3 = str(uniq[2])
            if self.H4 is None:
                self.H4 = str(uniq[3])
    
    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.enabled:
            return errs
        jc = _to_int(self.Jc)
        if jc is None or jc < 1 or jc > 128:
            errs.append("amnezia.Jc must be an integer in [1,128]")
        jmin = _to_int(self.Jmin)
        jmax = _to_int(self.Jmax)
        if jmin is None or jmax is None:
            errs.append("amnezia.Jmin and amnezia.Jmax must be set")
        else:
            if not (jmin < 1280):
                errs.append("amnezia.Jmin must be < 1280")
            if not (jmin < jmax):
                errs.append("amnezia.Jmax must be > Jmin")
            if not (jmax <= 1280):
                errs.append("amnezia.Jmax must be ≤ 1280")
        s1 = _to_int(self.S1)
        s2 = _to_int(self.S2)
        if s1 is None:
            errs.append("amnezia.S1 must be set")
        else:
            if not (s1 <= 1132):
                errs.append("amnezia.S1 must be ≤ 1132")
        if s2 is None:
            errs.append("amnezia.S2 must be set")
        else:
            if not (s2 <= 1188):
                errs.append("amnezia.S2 must be ≤ 1188")
        if s1 is not None and s2 is not None and (s1 + 56 == s2):
            errs.append("amnezia.S1 + 56 must not equal S2")
        hs = [self.H1, self.H2, self.H3, self.H4]
        ints: List[int] = []
        for idx, hv in enumerate(hs, start=1):
            iv = _to_int(hv)
            if iv is None:
                errs.append(f"amnezia.H{idx} must be set and integer")
            else:
                ints.append(iv)
        if len(set(ints)) != len(ints):
            errs.append("amnezia.H1..H4 must be unique")
        return errs


@dataclass()
class ServerConfig:
    name: InterfaceName = InterfaceName("wg0")
    private_key: Optional[WireGuardKey] = None
    public_key: Optional[WireGuardKey] = None
    public_host: Optional[str] = None
    address: CIDR = CIDR("10.10.10.1/24")
    listen_port: PortNumber = PortNumber(51821)
    mtu: Mtu = Mtu(1380)
    dns: DnsList = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    pre_up: Optional[CommandLine] = None
    post_up: Optional[CommandLine] = None
    pre_down: Optional[CommandLine] = None
    post_down: Optional[CommandLine] = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "ServerConfig":
        r = EnvReader(env)
        name = InterfaceName(r.get("SERVER_NAME", "wg0") or "wg0")
        priv = r.get("SERVER_PRIVATE_KEY")
        pub = r.get("SERVER_PUBLIC_KEY")
        pub_host = r.get("SERVER_PUBLIC_HOST")
        addr = CIDR(r.get("SERVER_ADDRESS", "10.10.10.1/24") or "10.10.10.1/24")
        port = PortNumber(r.get_int("SERVER_LISTEN_PORT", 51821))
        mtu = Mtu(r.get_int("SERVER_MTU", 1380))
        dns_raw = r.get("SERVER_DNS", "1.1.1.1, 8.8.8.8") or "1.1.1.1, 8.8.8.8"
        dns_list = _parse_dns(dns_raw)
        pre_up = r.get("SERVER_PRE_UP")
        post_up = r.get("SERVER_POST_UP")
        pre_down = r.get("SERVER_PRE_DOWN")
        post_down = r.get("SERVER_POST_DOWN")
        return cls(
            name=name,
            private_key=WireGuardKey(priv) if priv else None,
            public_key=WireGuardKey(pub) if pub else None,
            public_host=pub_host,
            address=addr,
            listen_port=port,
            mtu=mtu,
            dns=dns_list,
            pre_up=CommandLine(pre_up) if pre_up else None,
            post_up=CommandLine(post_up) if post_up else None,
            pre_down=CommandLine(pre_down) if pre_down else None,
            post_down=CommandLine(post_down) if post_down else None,
        )

    def apply_args_overrides(self, args: object) -> None:
        if getattr(args, "server_name", None) is not None:
            self.name = InterfaceName(getattr(args, "server_name"))
        if getattr(args, "server_private_key", None) is not None:
            v = getattr(args, "server_private_key")
            self.private_key = WireGuardKey(v) if v else None
        if getattr(args, "server_public_key", None) is not None:
            v = getattr(args, "server_public_key")
            self.public_key = WireGuardKey(v) if v else None
        if getattr(args, "server_public_host", None) is not None:
            v = getattr(args, "server_public_host")
            self.public_host = v if v else None
        if getattr(args, "server_address", None) is not None:
            self.address = CIDR(getattr(args, "server_address"))
        if getattr(args, "server_listen_port", None) is not None:
            self.listen_port = PortNumber(int(getattr(args, "server_listen_port")))
        if getattr(args, "server_mtu", None) is not None:
            self.mtu = Mtu(int(getattr(args, "server_mtu")))
        if getattr(args, "server_dns", None) is not None:
            self.dns = _parse_dns(getattr(args, "server_dns"))
        if getattr(args, "server_pre_up", None) is not None:
            v = getattr(args, "server_pre_up")
            self.pre_up = CommandLine(v) if v else None
        if getattr(args, "server_post_up", None) is not None:
            v = getattr(args, "server_post_up")
            self.post_up = CommandLine(v) if v else None
        if getattr(args, "server_pre_down", None) is not None:
            v = getattr(args, "server_pre_down")
            self.pre_down = CommandLine(v) if v else None
        if getattr(args, "server_post_down", None) is not None:
            v = getattr(args, "server_post_down")
            self.post_down = CommandLine(v) if v else None

    def validate(self) -> List[str]:
        errs: List[str] = []
        name = str(self.name)
        if not name:
            errs.append("server.name must be non-empty")
        elif not _valid_iface_name(name):
            errs.append(f"server.name invalid: {name}")
        # public_host if provided must be a valid hostname or IP
        if self.public_host:
            if not _valid_host_or_ip(self.public_host):
                errs.append(f"server.public_host invalid: {self.public_host}")
        try:
            ipaddress.ip_interface(str(self.address))
        except Exception:
            errs.append(f"server.address invalid CIDR: {self.address}")
        port = int(self.listen_port)
        if port < 1 or port > 65535:
            errs.append(f"server.listen_port out of range: {port}")
        mtu = int(self.mtu)
        if mtu < 576 or mtu > 9000:
            errs.append(f"server.mtu out of range: {mtu}")
        for d in self.dns:
            try:
                ipaddress.ip_address(d)
            except Exception:
                errs.append(f"server.dns contains invalid IP: {d}")
        for label, keyval in (
            ("server.private_key", self.private_key),
            ("server.public_key", self.public_key),
        ):
            if keyval is not None and not _looks_like_wg_key(keyval):
                errs.append(f"{label} appears invalid format")
        # If both keys are present and look valid, ensure they match
        try:
            if self.private_key and self.public_key and _looks_like_wg_key(self.private_key) and _looks_like_wg_key(self.public_key):
                import base64 as _b64
                priv_raw = _b64.b64decode(self.private_key)
                derived_pub = (
                    X25519PrivateKey.from_private_bytes(priv_raw)
                    .public_key()
                    .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
                )
                derived_pub_b64 = codecs.encode(derived_pub, "base64").decode("utf8").strip()
                if derived_pub_b64 != self.public_key:
                    errs.append("server.public_key does not match server.private_key")
        except Exception:
            # Do not raise, just report mismatch via validation if derivation fails
            pass
        return errs


@dataclass()
class ClientConfig:
    name: str = ""
    enabled: bool = True
    address: Optional[str] = None
    private_key: Optional[WireGuardKey] = None
    public_key: Optional[WireGuardKey] = None
    preshared_key: Optional[WireGuardKey] = None
    persistent_keepalive: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    expires_at: Optional[str] = None

    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.name:
            errs.append("name must be non-empty")
        if self.address:
            try:
                ipaddress.ip_address(self.address)
            except Exception:
                errs.append(f"address invalid IP: {self.address}")
        if self.persistent_keepalive is not None and (
            self.persistent_keepalive < 0 or self.persistent_keepalive > 65535
        ):
            errs.append(
                f"persistent_keepalive out of range: {self.persistent_keepalive}"
            )
        for label, keyval in (
            ("private_key", self.private_key),
            ("public_key", self.public_key),
            ("preshared_key", self.preshared_key),
        ):
            if keyval is not None and not _looks_like_wg_key(keyval):
                errs.append(f"{label} appears invalid format")
        return errs


@dataclass()
class RootConfig:
    clients_path: str = "clients"
    server_path: str = "server"
    emit_qr: bool = True
    amnezia: AmneziaConfig = field(default_factory=AmneziaConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    clients: List[ClientConfig] = field(default_factory=list)

    # File IO
    @classmethod
    def read_file(cls, path: str) -> "RootConfig":
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        data = load_yaml(text)
        return parse_root_config(data)

    def write_file(self, path: str, overwrite: bool = False) -> None:
        if os.path.exists(path) and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {path}")
        parent = os.path.dirname(os.path.abspath(path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        text = dump_yaml(to_yaml_dict(self))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    # Paths resolution relative to the config file location
    def resolve_server_dir(self, config_path: str) -> str:
        base = os.path.dirname(os.path.abspath(config_path))
        return os.path.abspath(os.path.join(base, self.server_path))

    def resolve_clients_dir(self, config_path: str) -> str:
        base = os.path.dirname(os.path.abspath(config_path))
        return os.path.abspath(os.path.join(base, self.clients_path))

    # Validation
    def validate(self) -> List[str]:
        errs: List[str] = []
        if not self.clients_path:
            errs.append("clients_path must be non-empty")
        if not self.server_path:
            errs.append("server_path must be non-empty")

        # Delegate to subcomponents
        errs.extend(self.server.validate())
        errs.extend(self.amnezia.validate())

        # Clients: validate individually and check duplicates
        seen_names: set[str] = set()
        seen_addrs: set[str] = set()
        try:
            server_iface = ipaddress.ip_interface(str(self.server.address))
            server_ip = str(server_iface.ip)
            server_net = server_iface.network
        except Exception:
            server_net = None
            server_ip = None
        for idx, c in enumerate(self.clients):
            for e in c.validate():
                errs.append(f"clients[{idx}].{e}")
            if c.name in seen_names:
                errs.append(f"clients[{idx}].name duplicated: {c.name}")
            seen_names.add(c.name)
            if c.address:
                if c.address in seen_addrs:
                    errs.append(f"clients[{idx}].address duplicated: {c.address}")
                seen_addrs.add(c.address)
                # Ensure client address belongs to server subnet and is not equal to server IP
                try:
                    addr_ip = ipaddress.ip_address(c.address)
                    if server_net is not None and addr_ip not in server_net:
                        errs.append(f"clients[{idx}].address not in server subnet: {c.address}")
                    if server_ip is not None and c.address == server_ip:
                        errs.append(f"clients[{idx}].address equals server IP: {c.address}")
                except Exception:
                    # ClientConfig.validate will already flag invalid IP format
                    pass

        return errs

    def validate_or_raise(self) -> None:
        errs = self.validate()
        if errs:
            raise ValueError("Config validation failed:\n- " + "\n- ".join(errs))

    # Fill from env/args
    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "RootConfig":
        r = EnvReader(env)
        clients_path = r.get("CLIENTS_PATH", "clients") or "clients"
        server_path = r.get("SERVER_PATH", "server") or "server"
        emit_qr = r.get_bool("EMIT_QR", True)
        amn = AmneziaConfig.from_env(env)
        srv = ServerConfig.from_env(env)
        return cls(
            clients_path=clients_path,
            server_path=server_path,
            emit_qr=emit_qr,
            amnezia=amn,
            server=srv,
            clients=[],
        )

    def apply_args_overrides(self, args: object) -> None:
        if getattr(args, "clients_path", None) is not None:
            self.clients_path = str(getattr(args, "clients_path"))
        if getattr(args, "server_path", None) is not None:
            self.server_path = str(getattr(args, "server_path"))
        if getattr(args, "emit_qr", None) is not None:
            self.emit_qr = bool(getattr(args, "emit_qr"))
        self.amnezia.apply_args_overrides(args)
        self.server.apply_args_overrides(args)


class EnvReader:
    def __init__(self, env: Mapping[str, str], prefix: str = ENV_PREFIX) -> None:
        self._env = env
        self._prefix = prefix

    def with_prefix(self, more: str) -> "EnvReader":
        return EnvReader(self._env, self._prefix + more)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._env.get(self._prefix + key, default)

    def get_bool(self, key: str, default: bool) -> bool:
        val = self._env.get(self._prefix + key)
        if val is None:
            return default
        val_lower = val.strip().lower()
        if val_lower in {"1", "true", "yes", "y", "on"}:
            return True
        if val_lower in {"0", "false", "no", "n", "off"}:
            return False
        return default

    def get_int(self, key: str, default: int) -> int:
        val = self._env.get(self._prefix + key)
        if val is None:
            return default
        try:
            return int(val)
        except Exception:
            return default


def _parse_dns(value: str) -> DnsList:
    parts = [p.strip() for p in value.replace("\n", ",").split(",")]
    return [p for p in parts if p]


def _valid_iface_name(name: str) -> bool:
    import re

    return re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None


def _looks_like_wg_key(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32
    except Exception:
        return False


def _valid_host_or_ip(value: str) -> bool:
    # Accept IPs
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        pass
    # Accept hostnames: RFC 1035-like, labels of [A-Za-z0-9-], no leading/trailing hyphens, dot-separated
    import re
    if len(value) > 253:
        return False
    label_re = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
    parts = value.split(".")
    if any(not part for part in parts):
        return False
    return all(label_re.match(part) for part in parts)


def generate_wg_keypair() -> tuple[str, str]:
    """Generate a WireGuard (X25519) keypair as base64 strings using cryptography.

    Matches `wg genkey | wg pubkey` semantics: 32-byte raw keys, Base64 encoded.
    """
    private_key = X25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_b64 = codecs.encode(priv_bytes, "base64").decode("utf8").strip()
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = codecs.encode(pub_bytes, "base64").decode("utf8").strip()
    return priv_b64, pub_b64


def generate_preshared_key() -> str:
    """Generate a WireGuard preshared key: 32 random bytes, Base64-encoded."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None



def to_yaml_dict(cfg: RootConfig) -> Dict[str, Any]:
    amn = cfg.amnezia
    srv = cfg.server
    data: Dict[str, Any] = {
        "clients-path": cfg.clients_path,
        "server-path": cfg.server_path,
        "emit-qr": cfg.emit_qr,
        "amnezia": {},
        "server": {},
    }
    # Amnezia: include only non-None fields
    amn_map: Dict[str, Any] = {"enabled": amn.enabled}
    for k in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"):
        v = getattr(amn, k)
        if v is not None:
            amn_map[k] = v
    data["amnezia"] = amn_map

    # Server: include required + non-None optional
    srv_map: Dict[str, Any] = {
        "name": srv.name,
        "address": srv.address,
        "listen-port": int(srv.listen_port),
        "mtu": int(srv.mtu),
        "dns": ", ".join(srv.dns),
    }
    if srv.private_key is not None:
        srv_map["private-key"] = srv.private_key
    if srv.public_key is not None:
        srv_map["public-key"] = srv.public_key
    if srv.public_host is not None:
        srv_map["public-host"] = srv.public_host
    if srv.pre_up is not None:
        srv_map["pre-up"] = srv.pre_up
    if srv.post_up is not None:
        srv_map["post-up"] = srv.post_up
    if srv.pre_down is not None:
        srv_map["pre-down"] = srv.pre_down
    if srv.post_down is not None:
        srv_map["post-down"] = srv.post_down
    data["server"] = srv_map
    # Clients list
    clients_yaml: List[Dict[str, Any]] = []
    for c in cfg.clients:
        item: Dict[str, Any] = {
            "name": c.name,
            "enabled": bool(c.enabled),
        }
        if c.address is not None:
            item["address"] = c.address
        if c.private_key is not None:
            item["private-key"] = c.private_key
        if c.public_key is not None:
            item["public-key"] = c.public_key
        if c.preshared_key is not None:
            item["preshared-key"] = c.preshared_key
        if c.persistent_keepalive is not None:
            item["persistent-keepalive"] = c.persistent_keepalive
        if c.created_at is not None:
            item["created-at"] = c.created_at
        if c.updated_at is not None:
            item["updated-at"] = c.updated_at
        if c.expires_at is not None:
            item["expires-at"] = c.expires_at
        clients_yaml.append(item)
    data["clients"] = clients_yaml
    return data


def dump_yaml(data: Dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def load_yaml(text: str) -> Dict[str, Any]:
    obj = yaml.safe_load(text)
    if not isinstance(obj, dict):
        raise ValueError("Invalid YAML root: expected mapping")
    return obj


def parse_root_config(data: Dict[str, Any]) -> RootConfig:
    clients_path = str(data.get("clients-path", "clients"))
    server_path = str(data.get("server-path", "server"))
    emit_qr = bool(data.get("emit-qr", True))

    amn_map = data.get("amnezia", {}) or {}
    amn = AmneziaConfig(
        enabled=bool(amn_map.get("enabled", True)),
        Jc=amn_map.get("Jc"),
        Jmin=amn_map.get("Jmin"),
        Jmax=amn_map.get("Jmax"),
        S1=amn_map.get("S1"),
        S2=amn_map.get("S2"),
        H1=amn_map.get("H1"),
        H2=amn_map.get("H2"),
        H3=amn_map.get("H3"),
        H4=amn_map.get("H4"),
        I1=amn_map.get("I1"),
        I2=amn_map.get("I2"),
        I3=amn_map.get("I3"),
        I4=amn_map.get("I4"),
        I5=amn_map.get("I5"),
    )

    srv_map = data.get("server", {}) or {}
    dns_val = srv_map.get("dns", [])
    if isinstance(dns_val, str):
        dns_list = _parse_dns(dns_val)
    else:
        dns_list = [str(x) for x in (dns_val or [])]

    srv = ServerConfig(
        name=InterfaceName(str(srv_map.get("name", "wg0"))),
        private_key=WireGuardKey(srv_map["private-key"]) if srv_map.get("private-key") else None,
        public_key=WireGuardKey(srv_map["public-key"]) if srv_map.get("public-key") else None,
        public_host=str(srv_map.get("public-host")) if srv_map.get("public-host") else None,
        address=CIDR(str(srv_map.get("address", "10.10.10.1/24"))),
        listen_port=PortNumber(int(srv_map.get("listen-port", 51821))),
        mtu=Mtu(int(srv_map.get("mtu", 1380))),
        dns=dns_list,
        pre_up=CommandLine(srv_map["pre-up"]) if srv_map.get("pre-up") else None,
        post_up=CommandLine(srv_map["post-up"]) if srv_map.get("post-up") else None,
        pre_down=CommandLine(srv_map["pre-down"]) if srv_map.get("pre-down") else None,
        post_down=CommandLine(srv_map["post-down"]) if srv_map.get("post-down") else None,
    )

    clients_list: List[ClientConfig] = []
    raw_clients = data.get("clients") or []
    try:
        iter_clients = list(raw_clients)
    except Exception:
        iter_clients = []
    for item in iter_clients:
        if not isinstance(item, dict):
            continue
        clients_list.append(
            ClientConfig(
                name=str(item.get("name", "")),
                enabled=bool(item.get("enabled", True)),
                address=item.get("address"),
                private_key=item.get("private-key"),
                public_key=item.get("public-key"),
                preshared_key=item.get("preshared-key"),
                persistent_keepalive=item.get("persistent-keepalive"),
                created_at=item.get("created-at"),
                updated_at=item.get("updated-at"),
                expires_at=item.get("expires-at"),
            )
        )
    return RootConfig(
        clients_path=clients_path,
        server_path=server_path,
        emit_qr=emit_qr,
        amnezia=amn,
        server=srv,
        clients=clients_list,
    )
