from types import SimpleNamespace
import base64
import ipaddress

from wg_helper_script import RootConfig
from wg_helper_script.commands.client_add_cmd import run_client_add_cmd
from wg_helper_script.commands.client_disable_cmd import run_client_disable_cmd
from wg_helper_script.commands.client_remove_cmd import run_client_remove_cmd
from wg_helper_script.config import generate_wg_keypair


def make_cfg(tmp_path) -> str:
    cfg = RootConfig.from_env({})
    # ensure server keys present for any future usage
    if cfg.server.private_key is None or cfg.server.public_key is None:
        priv, pub = generate_wg_keypair()
        cfg.server.private_key = priv
        cfg.server.public_key = pub
    p = tmp_path / "config.yml"
    cfg.write_file(str(p), overwrite=True)
    return str(p)


def test_client_add_auto_fields(tmp_path):
    cfg_path = make_cfg(tmp_path)
    args = SimpleNamespace(config=cfg_path, name="alice")
    rc = run_client_add_cmd(args)
    assert rc == 0
    cfg = RootConfig.read_file(cfg_path)
    assert any(c.name == "alice" for c in cfg.clients)
    alice = next(c for c in cfg.clients if c.name == "alice")
    # Keys base64 32-byte
    assert len(base64.b64decode(alice.private_key)) == 32
    assert len(base64.b64decode(alice.public_key)) == 32
    assert len(base64.b64decode(alice.preshared_key)) == 32
    # Address within network and not server address
    net = ipaddress.ip_interface(str(cfg.server.address)).network
    assert ipaddress.ip_address(alice.address) in net
    assert str(ipaddress.ip_interface(str(cfg.server.address)).ip) != alice.address
    assert alice.enabled is True


def test_client_disable_and_remove(tmp_path):
    cfg_path = make_cfg(tmp_path)
    run_client_add_cmd(SimpleNamespace(config=cfg_path, name="alice"))
    run_client_add_cmd(SimpleNamespace(config=cfg_path, name="bob"))

    # disable alice
    rc = run_client_disable_cmd(SimpleNamespace(config=cfg_path, name="alice"))
    assert rc == 0
    cfg = RootConfig.read_file(cfg_path)
    alice = next(c for c in cfg.clients if c.name == "alice")
    assert alice.enabled is False

    # remove bob
    rc = run_client_remove_cmd(SimpleNamespace(config=cfg_path, name="bob"))
    assert rc == 0
    cfg = RootConfig.read_file(cfg_path)
    assert not any(c.name == "bob" for c in cfg.clients)

