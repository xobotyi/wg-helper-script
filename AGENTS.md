# Repository Guidelines

## Project Structure & Module Organization

- `wg_helper_script/`: Python package with CLI (`cli.py`), domain models and I/O (`config.py`), helpers (`common.py`),
  subcommands in `commands/`.
- `tests/`: Pytest suite covering config parsing/validation, command behavior, and emission.
- `example/`: Sample `config.yml` and generated assets (do not use real secrets in VCS).
- Root files: `pyproject.toml` (deps, entry point), `LICENSE`, `uv.lock`.

## Build, Test, and Development Commands

- Install (pip): `python -m pip install -e .` (dev: `python -m pip install -e . pytest`).
- Install (uv): `uv sync` then `uv run pytest`.
- Run CLI: `wg-helper-script ...` or `python -m wg_helper_script ...`.
- Run tests: `pytest -q`.

## Coding Style & Naming Conventions

- Python 3.11 baseline. Use modern types (`list[str]`, `dict[str, T]`, `X | None`).
- Follow PEP 8, 4‑space indentation, descriptive names; modules/functions: `snake_case`, classes: `PascalCase`.
- CLI subcommands: kebab‑case (e.g., `emit-configs`, `client-add`).
- Keep `config.py` logic cohesive; consider future split into `model/validation/io` if expanding.

## Testing Guidelines

- Framework: `pytest`. Place tests under `tests/` with `test_*.py` naming.
- Add tests for new commands, validation rules, and I/O paths. Aim to cover error paths and edge cases.
- Quick run example: `pytest -q tests/test_emit_configs.py::test_emit_server_config`.

## Commit & Pull Request Guidelines

- Commit style (observed): concise, imperative subjects (e.g., `feat: initial implementation`). Prefer Conventional
  Commits: `feat|fix|docs|refactor(scope): message`.
- PRs should include: summary, rationale, screenshots/logs for CLI changes, updated tests/docs, and mention of breaking
  changes.
- Link related issues; keep diffs focused and cohesive.
- In case there ase several independent scopes\features - better to split them to different changes.
- Commit message:
    - Subject line limit - Maximum 72 characters
    - Scope specificity - Use the most specific applicable scope
    - Imperative mood - "add feature" not "added feature" or "adds feature"
    - No capitalization - Subject should be lowercase
    - No trailing period - Subject should not end with a period

## Security & Configuration Tips

- Never commit real private keys. Use placeholders in `example/` or generate locally.
- Ensure emitted `.conf` and `config.yml` with secrets are `chmod 600` on POSIX.
- Configuration can be provided via YAML and/or `WGHS_*` env vars (e.g., `WGHS_CONFIG`, `WGHS_SERVER_*`).
