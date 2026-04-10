# RedSploit Setup

## Quick Install

```bash
git clone https://github.com/Thongheng/RedSploit.git
cd RedSploit
./install.sh
```

The installer:

- installs `red` to `/usr/bin` when run with `sudo`, or to `~/.local/bin/red` when run as a normal user
- configures shell completion automatically
- adds `~/.local/bin` to PATH automatically when needed
- asks once whether you want to store AI-summary API keys
- optionally writes AI-summary API key exports to your shell rc file

## AI Summary Providers

RedSploit uses this provider order for supported post-run summaries:

1. OpenRouter
2. ChatAnywhere

Environment variables:

- `OPENROUTER_API_KEY`
- `CHATANYWHERE_API_KEY`

These keys are read from the environment only. They are not stored in `config.yaml`, workspaces, or session variables.

## Installer-Based API Key Setup

If you answer `y` when `install.sh` asks whether to configure API keys, it will:

- prompt silently for `OPENROUTER_API_KEY`
- prompt silently for `CHATANYWHERE_API_KEY`
- detect whether your login shell is `zsh` or `bash`
- write an idempotent managed export block to `~/.zshrc` or `~/.bashrc`

Reload your shell after installation:

```bash
source ~/.zshrc
# or
source ~/.bashrc
```

## Manual API Key Setup

If you skip the installer prompt or prefer manual configuration, add exports to your shell rc file yourself.

### Zsh

```bash
export OPENROUTER_API_KEY="your-openrouter-key"
export CHATANYWHERE_API_KEY="your-chatanywhere-key"
```

Then reload:

```bash
source ~/.zshrc
```

### Bash

```bash
export OPENROUTER_API_KEY="your-openrouter-key"
export CHATANYWHERE_API_KEY="your-chatanywhere-key"
```

Then reload:

```bash
source ~/.bashrc
```

## Config Defaults

`config.yaml` now includes a `summary` section for runtime behavior:

```yaml
summary:
  enabled: true
  warn_on_unsupported: true
  timeout_seconds: 12
  max_capture_chars: 12000
  max_prompt_chars: 6000
```

Provider URLs and model names also live under this section.

## Disable Summaries Per Run

Use this flag if you want raw tool output only:

```bash
red -T 10.10.10.10 -i -nmap --no-summary
```

## Supported Summary Tools

- Infra: `nmap`, `rustscan`
- Web: `subfinder`, `dnsrecon`, `subzy`, `gobuster_dns`, `dir_ffuf`, `dir_ferox`, `dir_dirsearch`, `gobuster_dir`, `nuclei`, `waf`, `screenshots`

Interactive or sensitive tools continue to run in raw passthrough mode.
