from types import SimpleNamespace

from wg_helper_script import RootConfig
from wg_helper_script.commands.emit_configs_cmd import run_emit_configs_cmd
from wg_helper_script.config import generate_wg_keypair


def make_cfg_with_keys() -> RootConfig:
    cfg = RootConfig.from_env({})
    if cfg.server.private_key is None or cfg.server.public_key is None:
        priv, pub = generate_wg_keypair()
        cfg.server.private_key = priv
        cfg.server.public_key = pub
    return cfg


def test_emit_server_config(tmp_path):
    cfg = make_cfg_with_keys()
    cfg.server_path = "server"
    cfg.clients_path = "clients"
    cfg_path = tmp_path / "config.yml"
    cfg.write_file(str(cfg_path), overwrite=True)

    args = SimpleNamespace(config=str(cfg_path), only_server=True, only_clients=False)
    rc = run_emit_configs_cmd(args)
    assert rc == 0
    server_dir = tmp_path / cfg.server_path
    conf = server_dir / f"{cfg.server.name}.conf"
    assert conf.exists()
    text = conf.read_text()
    assert "[Interface]" in text
    assert "PrivateKey" in text
    assert str(int(cfg.server.listen_port)) in text


def test_emit_client_config_and_qr(tmp_path):
    cfg = make_cfg_with_keys()
    cfg.clients_path = "clients"
    cfg.server_path = "server"
    # add a client with minimal required fields
    from wg_helper_script import ClientConfig
    from wg_helper_script.config import generate_wg_keypair

    priv, pub = generate_wg_keypair()
    cfg.server.public_key = cfg.server.public_key or pub
    cfg.clients = [ClientConfig(name="alice", enabled=True, address="10.10.10.2", private_key=priv, preshared_key=generate_wg_keypair()[0])]
    cfg_path = tmp_path / "config.yml"
    cfg.write_file(str(cfg_path), overwrite=True)
    args = SimpleNamespace(config=str(cfg_path), only_server=False, only_clients=True)
    rc = run_emit_configs_cmd(args)
    assert rc == 0
    clients_dir = tmp_path / cfg.clients_path
    f = clients_dir / "alice.conf"
    assert f.exists()
    text = f.read_text()
    assert "[Interface]" in text
    assert "# INTERFACE CUSTOM SECTION START" in text
    # QR code PNG present when emit-qr is true by default
    png = clients_dir / "alice.png"
    assert png.exists()
