from types import SimpleNamespace
from wg_helper_script import (
    RootConfig,
    InterfaceName,
    CIDR,
)


def test_from_env_parsing():
    env = {
        "WGHS_CLIENTS_PATH": "c",
        "WGHS_SERVER_PATH": "s",
        "WGHS_EMIT_QR": "false",
        "WGHS_AMNEZIA_ENABLED": "1",
        "WGHS_SERVER_NAME": "wg-test",
        "WGHS_SERVER_ADDRESS": "10.9.0.1/24",
        "WGHS_SERVER_LISTEN_PORT": "51280",
        "WGHS_SERVER_MTU": "1420",
        "WGHS_SERVER_DNS": "9.9.9.9, 1.1.1.1",
    }
    cfg = RootConfig.from_env(env)
    assert cfg.clients_path == "c"
    assert cfg.server_path == "s"
    assert cfg.emit_qr is False
    assert cfg.server.name == InterfaceName("wg-test")
    assert cfg.server.address == CIDR("10.9.0.1/24")
    assert int(cfg.server.listen_port) == 51280
    assert int(cfg.server.mtu) == 1420
    assert cfg.server.dns == ["9.9.9.9", "1.1.1.1"]


def test_apply_args_overrides():
    cfg = RootConfig.from_env({})
    args = SimpleNamespace(
        clients_path="clientsX",
        server_path="serverX",
        emit_qr=False,
        amnezia_enabled=False,
        amnezia_jc="A",
        amnezia_jmin=None,
        amnezia_jmax=None,
        amnezia_s1=None,
        amnezia_s2=None,
        amnezia_h1=None,
        amnezia_h2=None,
        amnezia_h3=None,
        amnezia_h4=None,
        amnezia_i1=None,
        amnezia_i2=None,
        amnezia_i3=None,
        amnezia_i4=None,
        amnezia_i5=None,
        server_name="wgX",
        server_private_key=None,
        server_public_key=None,
        server_address="10.10.20.1/24",
        server_listen_port=55555,
        server_mtu=1300,
        server_dns="8.8.4.4,8.8.8.8",
        server_pre_up=None,
        server_post_up=None,
        server_pre_down=None,
        server_post_down=None,
    )
    cfg.apply_args_overrides(args)
    assert cfg.clients_path == "clientsX"
    assert cfg.server_path == "serverX"
    assert cfg.emit_qr is False
    assert cfg.amnezia.enabled is False
    assert cfg.amnezia.Jc == "A"
    assert cfg.server.name == InterfaceName("wgX")
    assert cfg.server.address == CIDR("10.10.20.1/24")
    assert int(cfg.server.listen_port) == 55555
    assert int(cfg.server.mtu) == 1300
    assert cfg.server.dns == ["8.8.4.4", "8.8.8.8"]


def test_validation_catches_errors():
    cfg = RootConfig.from_env({})
    cfg.server.dns = ["not-an-ip"]
    errors = cfg.validate()
    assert any("dns" in e for e in errors)


def test_dump_yaml_shape_contains_keys():
    cfg = RootConfig.from_env({})
    from wg_helper_script.config import dump_yaml, to_yaml_dict
    text = dump_yaml(to_yaml_dict(cfg))
    assert "clients-path:" in text
    assert "server:" in text
    assert "clients: []" in text


def test_load_yaml_roundtrip():
    cfg = RootConfig.from_env({})
    from wg_helper_script.config import dump_yaml, to_yaml_dict, load_yaml, parse_root_config
    text = dump_yaml(to_yaml_dict(cfg))
    data = load_yaml(text)
    cfg2 = parse_root_config(data)
    assert cfg2.server.address == cfg.server.address
    assert cfg2.clients == []


def test_write_and_read_file_roundtrip(tmp_path):
    cfg = RootConfig.from_env({})
    p = tmp_path / "config.yml"
    cfg.write_file(str(p), overwrite=True)
    cfg2 = RootConfig.read_file(str(p))
    assert cfg2.server.address == cfg.server.address
    assert cfg2.clients_path == cfg.clients_path
    assert cfg2.server.dns == cfg.server.dns


def test_validate_or_raise_raises_on_invalid():
    cfg = RootConfig.from_env({})
    cfg.server.dns = ["bad ip"]
    import pytest
    with pytest.raises(ValueError):
        cfg.validate_or_raise()
