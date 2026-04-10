# Repository Guidelines

## Project Structure & Module Organization
`red.py` is the CLI entrypoint. Shared shell, session, config, and utility logic lives in `redsploit/core/`. Operator-facing tool catalogs and module behavior live in `redsploit/modules/` (`infra.py`, `web.py`, `file.py`, `system.py`). Tests live in `tests/` and mirror the feature area they cover, for example `test_web_module.py` and `test_session.py`. Automation assets live in `playbooks/`, shell completion scripts live in `completions/`, and `config.yaml` holds local defaults.

## Build, Test, and Development Commands
`python3 -m venv .venv && source .venv/bin/activate` creates a local environment.
`pip install -r requirements.txt` installs RedSploit dependencies.
`python3 red.py -h` checks CLI wiring and help output.
`python3 red.py` launches the interactive shell.
`python3 -m pytest -q` runs the test suite.
`sudo ./install.sh` installs the `red` symlink and completion scripts for local use.

## Coding Style & Naming Conventions
Use Python with 4-space indentation and PEP 8-style spacing. Keep functions, variables, and tests in `snake_case`; classes use `PascalCase`; constant command registries such as `TOOLS` stay uppercase. Prefer small helper methods over large inline command builders, and reuse existing `Session`, `BaseModule`, and shell utilities before adding new abstractions. No formatter or linter config is committed, so match the surrounding file style and keep imports tidy.

## Testing Guidelines
Write tests with `pytest` under `tests/test_*.py`. Add regression coverage for new CLI flags, session behavior, command resolution, and playbook flows. Reuse fixtures from `tests/conftest.py` instead of hardcoding temp paths. Keep tests isolated and fast; mock external binaries, network calls, and offensive tooling rather than running them directly.

## Commit & Pull Request Guidelines
Recent history uses short imperative subjects such as `fix bug` and `improve TUI: ...`. Keep commit subjects imperative and specific. For substantial changes, prefer intent-first messages and include useful trailers such as `Constraint:`, `Confidence:`, and `Tested:`. Pull requests should summarize operator impact, link related issues, list verification commands, and include terminal screenshots when changing prompts, help text, or table rendering.

## Security & Configuration Tips
Never commit real targets, credentials, hashes, or captured loot. Treat `config.yaml`, `playbooks/*.yaml`, and sample files as templates only, and keep machine-specific wordlist paths local.
