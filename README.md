# RedSploit

Red Team penetration testing CLI tool with interactive shell and automation capabilities.

## Features

- 🔧 **Interactive Shell** - Full-featured console with tab completion
- 🚀 **Quick CLI Mode** - Run commands directly from terminal
- 🎯 **Module System** - Infrastructure, Web, and File modules
- ⚡ **Shell Completion** - Native bash/zsh completion support
- 📝 **Variable Management** - Session-based environment variables

## Quick Start

### Installation

```bash
git clone https://github.com/Thongheng/RedSploit.git
cd RedSploit
sudo ./install.sh
```

This will:
- Install `red` command to `/usr/bin`
- Setup shell completion automatically
- Make the tool accessible from anywhere

**Manual install (no sudo):**
```bash
chmod +x red.py
./red.py
```

### Usage

**Interactive Mode:**
```bash
red
# or with preset values
red -set -T 10.10.10.10
```

**CLI Mode:**
```bash
red -T 10.10.10.10 -U admin:pass123 -i nmap -p-
red -w -T example.com -gobuster
red -f -T 10.10.10.10 -download /etc/passwd
```

**Set Variables:**
```bash
red -T 10.10.10.10      # Set target
red -U admin:pass       # Set user credentials
red -D WORKGROUP        # Set domain
red -H <ntlm_hash>      # Set NTLM hash
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
| `user` | User credentials (username or username:password) |
| `domain` | Domain name (default: .) |
| `hash` | NTLM hash (alternative to password) |
| `interface` | Network interface |
| `lport` | Local port for reverse shells (default: 4444) |
| `workspace` | Workspace name (default: default) |

## Examples

```bash
# Quick nmap scan
red -T 10.10.10.10 -i nmap

# Web directory enumeration
red -T example.com -w -dir

# Download file via SMB
red -T 10.10.10.10 -U admin:pass -f -smb -download /path/to/file

# Interactive mode with preset variables
red -set -T 10.10.10.10 -U admin:pass
```

## License

MIT
