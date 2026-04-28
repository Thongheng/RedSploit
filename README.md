# RedSploit

Red Team penetration testing CLI tool with interactive shell and automation capabilities.

## Features

- 🔧 **Interactive Shell** - Full-featured console with tab completion
- 🚀 **Quick CLI Mode** - Run commands directly from terminal
- 🎯 **Module System** - Infrastructure, Active Directory, Web, and Transfer modules
- ⚡ **Shell Completion** - Native bash/zsh completion support
- 📝 **Variable Management** - Session-based environment variables
- ✨ **Post-Run Cleanup Summaries** - Optional AI-assisted summaries appended after supported scanner output

## Quick Start

Want to explore commands interactively? Open [`index.html`](index.html) in your browser for a visual command builder and scenario walkthroughs.

### Installation

```bash
git clone https://github.com/Thongheng/RedSploit.git
cd RedSploit
./setup.sh
```

This will:
- Install Python dependencies and the RedSploit package
- Install `red` to `/usr/bin` when run with `sudo`, or to `~/.local/bin/red` when run as a normal user
- Automatically set up shell completion and PATH updates when needed
- Ask once whether you want to configure AI-summary API keys
- Optionally configure AI-summary API keys for the installing user
- Make the tool accessible from anywhere

**Manual install (no sudo):**
```bash
chmod +x red.py
./red.py
```

### Configuration
RedSploit uses a `config.yaml` file located in the project root. It is automatically created on first run if missing.

To verify both AI providers after setup:

```bash
./setup.sh --test
```

### Wordlists
Configure default wordlist paths in `config.yaml` to match your system (e.g., if you are using macOS vs Kali).
```yaml
web:
  wordlists:
    directory: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    subdomain: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    vhost: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
infra:
  defaults:
    payload: windows/x64/shell_reverse_tcp
    payload_file: beacon.exe
transfer:
  port: 8000
summary:
  enabled: true
  warn_on_unsupported: true
```

### AI Summary Setup

The installer can configure AI-summary API keys for you. It will:

- ask once whether you want to store AI-summary API keys
- prompt for `OPENROUTER_API_KEY`
- prompt for `CHATANYWHERE_API_KEY`
- detect whether your shell is `zsh` or `bash`
- write an idempotent managed export block to your shell rc file

You can test provider access after setup with:

```bash
./setup.sh --test
```

Manual setup also works:

```bash
export OPENROUTER_API_KEY="your-openrouter-key"
export CHATANYWHERE_API_KEY="your-chatanywhere-key"
```

Then reload your shell:

```bash
source ~/.zshrc
# or
source ~/.bashrc
```

### Command History
Command history is automatically saved to `~/.redsploit_history`. You can recall commands from previous sessions using the Up Arrow key.

### Shell Completion

RedSploit supports native shell completion for bash and zsh.

Recommended one-file setup:

```bash
./setup.sh
```

Manual install examples:

```bash
# zsh, system-wide
sudo cp completions/_red /usr/share/zsh/site-functions/_red

# bash, system-wide
sudo cp completions/red.bash /etc/bash_completion.d/red
```

Quick test:

```bash
red -<TAB><TAB>
```

## Development
RedSploit is designed to be easily extensible. 

### Adding New Tools
Tools are defined in a data-driven structure within their respective module files (`infra.py`, `web.py`, `file.py`).

**Example (adding a tool to `TOOLS`):**
```python
"my_tool": {
    "cmd": "mytool -t {target} --scan",
    "category": "My Category",
    "requires": ["target"]
}
```
The command template automatically injects variables like `{target}`, `{domain}`, `{url}`, and authenticates if `{auth}` is present.

### Usage

**Interactive Mode:**
```bash
red
# or with preset values
red -set -T 10.10.10.10
red -set target 10.10.10.10
```

**CLI Mode:**
```bash
red -T 10.10.10.10 -i -nmap -p
red -T 10.10.10.10 -D corp.local -U admin:pass -a -bloodhound -p
red -T https://example.com -w -gobuster --preview
red -w -headerscan https://example.com --detailed
red -f -download linpeas.sh -c
red -i -P 4444 -msfvenom -p
red -i -P 4444 -msf
```

**Command Flags:**

When running commands, you can use these flags to modify behavior:

| Flag | Description | Example |
|------|-------------|---------|
| `-c` / `--copy` | Copy command to clipboard without executing | `red -T 10.10.10.10 -w -dir_ferox -c` |
| `-p` / `--preview` | Preview the command without executing | `red -T 10.10.10.10 -i -nmap -p` |
| `-e` / `--edit` | Edit the command before execution | `red -T 10.10.10.10 -w -nuclei -e` |
| `-nosummary` / `--no-summary` | Disable the post-run summary section for this run | `red -T 10.10.10.10 -i -nmap --no-summary` |
| `-noauth` | Skip credentials for this run | `red -T 10.10.10.10 -U admin:pass -i -smbclient -noauth` |

**Set Variables:**
```bash
red -set -T 10.10.10.10      # Start interactive mode with target preset
red -set -U admin:pass       # Start interactive mode with credentials preset
red -set -D WORKGROUP        # Start interactive mode with domain preset
red -set -H <ntlm_hash>      # Start interactive mode with hash preset
```

## Available Modules

| Flag | Module | Description |
|------|--------|-------------|
| `-i` | infra | Infrastructure enumeration (nmap, rustscan) |
| `-a` | ad | Active Directory and authenticated Windows tooling |
| `-w` | web | Web reconnaissance (gobuster, nuclei, etc.) |
| `-f` | file | File transfer and utility helpers |

## Variables

| Name | Description |
|------|-------------|
| `target` | Target IP/hostname/CIDR |
| `user` | User credentials (auto-splits on `:` to username and password) |
| `username` | Username (auto-set from user variable) |
| `password` | Password (auto-set from user variable) |
| `domain` | Domain name (default: .) |
| `hash` | NTLM hash (alternative to password) |
| `interface` | Network interface |
| `lhost` | Listener host override (used by Metasploit helpers) |
| `lport` | Local port for reverse shells (default: 4444) |
| `workspace` | Workspace name (default: default) |
| `summary` | Cleaner output mode (`on` or `off`) |

Uncommon settings like payload defaults, output filenames, transfer port, and wordlists now live in `config.yaml` instead of normal session variables.

## AI Summaries

Supported scanner-style tools keep their original raw output and then append a `Summary` section at the end of the run. The first implementation covers:

- Infra: `nmap`, `rustscan`
- Web: `subfinder`, `dnsrecon`, `subzy`, `gobuster_dns`, `dir_ffuf`, `dir_ferox`, `dir_dirsearch`, `gobuster_dir`, `nuclei`, `waf`, `screenshots`

RedSploit uses this provider order for AI cleanup summaries:

1. OpenRouter (`OPENROUTER_API_KEY`)
2. ChatAnywhere (`CHATANYWHERE_API_KEY`)

If no provider is available or the request fails, the underlying tool output still succeeds and RedSploit falls back to a local summary when possible.

To disable the cleaner globally for the current session:

```bash
set summary off
```

## Credential Handling

RedSploit supports flexible credential management with automatic splitting and mode-based authentication:

**Auto-Split Credentials:**
```bash
# Set username and password in one command
red -set user admin:password123
# Automatically creates: username=admin, password=password123

# Or set username only
red -set user admin
```

**Mode-Based Authentication:**

- **CLI Mode**: Automatically uses credentials when available
  ```bash
  # With credentials - auto-applied
  red -T 10.10.10.10 -U admin:pass -i -smb-c
  
  # Without credentials - uses NULL session
  red -T 10.10.10.10 -i -smb-c
  ```

- **Interactive Mode**: set session values once, then run the tool
  ```bash
  > set target 10.10.10.10
  > set user admin:pass
  > use infra
  > smbclient
  > smbclient -noauth
  ```

## Loot Locker (Credential Management)

RedSploit includes a built-in **Loot Locker** to manage credentials found during engagements. It allows you to store, organize, and active credentials on the fly.

**Commands:**

- `loot add <content> [service] [type]`: Add new loot
- `loot show`: List captured loot
- `loot use <id>`: **Load loot into session variables** (sets user/password/hash)
- `loot rm <id>`: Remove loot

**Usage Example:**

```bash
# 1. Capture a credential
> loot add admin:Secret123 smb cred
[+] Added loot: admin:Secret123 (cred)

# 2. List available loot
> loot show
ID   Type       Target          Service    Content                                  
----------------------------------------------
1    cred                       smb        admin:Secret123                        

# 3. Use the credential (Populates session variables)
> loot use 1
[+] Loaded loot #1 into session variables.

# 4. Run tools with the loaded credential
> smbclient
```

> **Note**: The `service` and `target` fields in `loot add` are optional metadata to help you organize your loot. They do not restrict usage.

## Examples

```bash
# Quick nmap scan
red -T 10.10.10.10 -i -nmap

# Active Directory collection
red -T 10.10.10.10 -D corp.local -U admin:pass -a -bloodhound

# Web directory enumeration
red -T example.com -w -dir_ffuf

# Header security scan using the current session target
red -set target https://example.com
red -w -headerscan --json

# Header security scan for an explicit URL
red -w -headerscan https://example.com --detailed

# SMB enumeration with credentials (CLI auto-auth)
red -T 10.10.10.10 -U admin:pass -i -smb-c

# SMB enumeration without credentials (NULL session)
red -T 10.10.10.10 -i -smb-c

# Generate a payload that matches your handler
# Configure uncommon payload defaults in config.yaml, then run:
red -set lhost 10.10.14.7
red -i -msfvenom -p

# Start a matching Metasploit listener
red -set lhost 10.10.14.7
red -i -P 4444 -msf

# Interactive mode with credentials
red
> set target 10.10.10.10
> set user admin:password
> use ad
> bloodhound
> nxc
> back
> use web
> headerscan --json
```

## License

MIT
