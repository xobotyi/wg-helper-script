import os
import sys
from typing import Optional, Tuple

from .config import RootConfig


def resolve_config_path(args) -> str:
    path = getattr(args, "config", None) or os.environ.get("WGHS_CONFIG") or "config.yml"
    return path


def require_and_load_config(args) -> Tuple[Optional[RootConfig], Optional[str]]:
    path = resolve_config_path(args)
    if not os.path.exists(path):
        print(f"Config file not found: {path}", file=sys.stderr)
        return None, None
    try:
        cfg = RootConfig.read_file(path)
    except Exception as e:
        print(f"Failed to parse config: {e}", file=sys.stderr)
        return None, None
    return cfg, path

