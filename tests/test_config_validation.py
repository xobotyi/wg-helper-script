from types import SimpleNamespace

from wg_helper_script import (
    RootConfig,
    ClientConfig,
    InterfaceName,
    CIDR,
)
from wg_helper_script.commands.validate_cfg_cmd import run_validate_cfg_cmd
from wg_helper_script.config import _to_int
from wg_helper_script.commands.init_cmd import run_init_cmd


def make_valid_cfg() -> RootConfig:
    return RootConfig.from_env({})


# Root-level validation
def test_root_paths_non_empty():
    cfg = make_valid_cfg()
    cfg.clients_path = ""
    cfg.server_path = ""
    errs = cfg.validate()
    assert any("clients_path must be non-empty" in e for e in errs)
    assert any("server_path must be non-empty" in e for e in errs)


def test_clients_duplicates_and_ranges():
    cfg = make_valid_cfg()
    cfg.clients = [
        ClientConfig(name="dup", address="10.0.0.2", persistent_keepalive=-1),
        ClientConfig(name="dup", address="10.0.0.2"),
    ]
    errs = cfg.validate()
    assert any("clients[1].name duplicated" in e for e in errs)
    assert any("clients[1].address duplicated" in e for e in errs)
    assert any("persistent_keepalive out of range" in e for e in errs)


def test_validate_cfg_command_valid_and_invalid(tmp_path):
    # Valid case
    cfg = make_valid_cfg()
    # Simulate init behavior: ensure amnezia defaults when enabled
    cfg.amnezia.ensure_recommended_defaults()
    valid_path = tmp_path / "valid.yml"
    cfg.write_file(str(valid_path), overwrite=True)
    args = SimpleNamespace(config=str(valid_path))
    rc = run_validate_cfg_cmd(args)
    assert rc == 0

    # Invalid case (bad DNS)
    cfg2 = make_valid_cfg()
    cfg2.server.dns = ["bad ip"]
    invalid_path = tmp_path / "invalid.yml"
    cfg2.write_file(str(invalid_path), overwrite=True)
    args2 = SimpleNamespace(config=str(invalid_path))
    rc2 = run_validate_cfg_cmd(args2)
    assert rc2 == 2


def test_init_generates_keys_when_missing(tmp_path):
    # Prepare args with no keys specified
    out = tmp_path / "generated.yml"
    args = SimpleNamespace(
        output=str(out),
        overwrite=True,
        # optional overrides not provided (left as None)
    )
    # run init command function directly
    rc = run_init_cmd(args)
    assert rc == 0
    # read and verify keys exist and look like base64 32-byte values
    cfg = RootConfig.read_file(str(out))
    assert cfg.server.private_key and cfg.server.public_key
    import base64
    priv_raw = base64.b64decode(cfg.server.private_key)
    pub_raw = base64.b64decode(cfg.server.public_key)
    assert len(priv_raw) == 32 and len(pub_raw) == 32


def test_paths_resolved_relative_to_config(tmp_path):
    # create nested directory with config
    nested = tmp_path / "nested/dir"
    nested.mkdir(parents=True)
    cfg = make_valid_cfg()
    # custom relative paths
    cfg.server_path = "server"
    cfg.clients_path = "clients"
    cfg_path = nested / "config.yml"
    cfg.write_file(str(cfg_path), overwrite=True)
    # reload and resolve
    cfg2 = RootConfig.read_file(str(cfg_path))
    server_abs = cfg2.resolve_server_dir(str(cfg_path))
    clients_abs = cfg2.resolve_clients_dir(str(cfg_path))
    assert server_abs == str((nested / "server").resolve())
    assert clients_abs == str((nested / "clients").resolve())


# Server validation (granular)
def test_server_iface_name_invalid():
    s = make_valid_cfg().server
    s.name = InterfaceName("bad name!")
    errs = s.validate()
    assert any("server.name invalid" in e for e in errs)


def test_server_address_invalid():
    s = make_valid_cfg().server
    s.address = CIDR("not-a-cidr")
    errs = s.validate()
    assert any("server.address invalid CIDR" in e for e in errs)


def test_server_port_mtu_ranges():
    s = make_valid_cfg().server
    s.listen_port = 0  # type: ignore[assignment]
    s.mtu = 100  # type: ignore[assignment]
    errs = s.validate()
    msg = "\n".join(errs)
    assert "listen_port out of range" in msg
    assert "server.mtu out of range" in msg


def test_server_dns_invalid_entry():
    s = make_valid_cfg().server
    s.dns = ["1.1.1.1", "not-an-ip"]
    errs = s.validate()
    assert any("server.dns contains invalid IP" in e for e in errs)


def test_server_wg_key_format():
    s = make_valid_cfg().server
    s.private_key = "not-base64"  # type: ignore[assignment]
    errs = s.validate()
    assert any("server.private_key appears invalid format" in e for e in errs)


def test_server_public_host_validation():
    s = make_valid_cfg().server
    s.public_host = "bad host!"  # space and exclamation invalid
    errs = s.validate()
    assert any("server.public_host invalid" in e for e in errs)
    s.public_host = "example.com"
    assert not any("server.public_host invalid" in e for e in s.validate())
    s.public_host = "203.0.113.10"
    assert not any("server.public_host invalid" in e for e in s.validate())


# Client validation (granular)
def test_client_validation_fields():
    c = ClientConfig()
    c.name = ""  # invalid name
    c.address = "not-an-ip"  # invalid IP
    c.persistent_keepalive = -1  # invalid range
    c.private_key = "badkey"  # invalid base64/len
    errs = c.validate()
    text = "\n".join(errs)
    assert "name must be non-empty" in text
    assert "address invalid IP" in text
    assert "persistent_keepalive out of range" in text
    assert "private_key appears invalid format" in text


def test_client_validation_ok():
    c = ClientConfig(name="ok")
    errs = c.validate()
    assert errs == []


# Amnezia validation (granular)
def test_amnezia_defaults_generation_on_init_like():
    cfg = make_valid_cfg()
    cfg.amnezia.enabled = True
    cfg.amnezia.Jc = None
    cfg.amnezia.Jmin = None
    cfg.amnezia.Jmax = None
    cfg.amnezia.S1 = None
    cfg.amnezia.S2 = None
    cfg.amnezia.H1 = None
    cfg.amnezia.H2 = None
    cfg.amnezia.H3 = None
    cfg.amnezia.H4 = None
    cfg.amnezia.ensure_recommended_defaults()
    jc = _to_int(cfg.amnezia.Jc)
    assert jc is not None and 1 <= jc <= 128 and 4 <= jc <= 12
    jmin = _to_int(cfg.amnezia.Jmin)
    jmax = _to_int(cfg.amnezia.Jmax)
    assert jmin is not None and jmax is not None and jmin < jmax and jmin < 1280 and jmax <= 1280
    s1 = _to_int(cfg.amnezia.S1)
    s2 = _to_int(cfg.amnezia.S2)
    assert s1 is not None and 15 <= s1 <= 1132
    assert s2 is not None and 15 <= s2 <= 1188 and s1 + 56 != s2
    hs = [cfg.amnezia.H1, cfg.amnezia.H2, cfg.amnezia.H3, cfg.amnezia.H4]
    his = [_to_int(h) for h in hs]
    assert all(h is not None and 5 <= h <= 2147483647 for h in his)
    assert len(set(his)) == 4


def test_amnezia_validation_rules():
    cfg = make_valid_cfg()
    cfg.amnezia.enabled = True
    cfg.amnezia.Jc = "0"
    cfg.amnezia.Jmin = "8"
    cfg.amnezia.Jmax = "80"
    cfg.amnezia.S1 = "64"
    cfg.amnezia.S2 = "120"  # equal to 64 + 56 -> invalid
    cfg.amnezia.H1 = "5"
    cfg.amnezia.H2 = "5"  # duplicate
    cfg.amnezia.H3 = "7"
    cfg.amnezia.H4 = "8"
    errs = cfg.amnezia.validate()
    text = "\n".join(errs)
    assert "amnezia.Jc" in text
    assert "S1 + 56" in text
    assert "must be unique" in text
