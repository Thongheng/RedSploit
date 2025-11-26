# 🔴 Red Team Pentest Helper

A powerful, user-friendly command-line tool for penetration testing and red team operations. Streamlines common reconnaissance, enumeration, and exploitation tasks with an intuitive interface.

## ✨ Features

- **🎯 Infrastructure Enumeration** - Network scanning, SMB enumeration, Active Directory reconnaissance
- **📁 File Transfer Helper** - Quick file server setup with command generation for victim machines
- **🌐 Web Reconnaissance** - Subdomain discovery, directory bruteforce, vulnerability scanning
- **📚 Built-in Cheat Sheet** - Comprehensive examples at your fingertips
- **🚀 Smart Error Messages** - Contextual hints when something goes wrong

## 🚀 Quick Start

### Basic Usage

```bash
# View main help
./red.sh

# View examples and cheat sheet
./red.sh --examples  # or use alias: ./red.sh -e
```

### Using Aliases (Faster Typing) ⚡

All main commands support short aliases for speed:

```bash
# Long form
./red.sh --infra -nmap 10.10.10.10
./red.sh --file tun0 linpeas.sh
./red.sh --web example.com --all

# Short form (aliases)
./red.sh -i -nmap 10.10.10.10
./red.sh -f tun0 linpeas.sh
./red.sh -w example.com --all
```

**Available Aliases:**
- `-i` = `--infra`
- `-f` = `--file`
- `-w` = `--web`
- `-e` = `--examples`

### Common Commands

```bash
# Scan a target with Nmap
./red.sh --infra -nmap 10.10.10.10
# Or using alias:
./red.sh -i -nmap 10.10.10.10

# Transfer a file to victim machine
./red.sh --file tun0 linpeas.sh
# Or using alias:
./red.sh -f tun0 linpeas.sh

# Discover subdomains
./red.sh --web example.com --all
# Or using alias:
./red.sh -w example.com --all
```

## 📖 Modules

### 1. Infrastructure Enumeration (`--infra`)

Perform network and service enumeration:

```bash
# Quick Nmap scan
./red.sh --infra -nmap 10.10.10.10

# SMB enumeration with credentials
./red.sh --infra -smb-c -U admin:password123 10.10.10.10

# Multiple tools at once
./red.sh --infra -nmap -smb-c -enum4 10.10.10.10

# BloodHound data collection
./red.sh --infra -bloodhound -U user:pass -d domain.local 10.10.10.10

# RDP connection
./red.sh --infra -rdp -U administrator:password 10.10.10.10
```

**Available Tools:**
- `-nmap` - Nmap scan
- `-rust` - Rustscan
- `-smb-c` - SMBClient
- `-smb-m` - SMBMap
- `-enum4` - enum4linux-ng
- `-nxc` - NetExec
- `-bloodhound` - BloodHound-CE
- `-ftp` - FTP enumeration
- `-rdp` - RDP connection
- `-ssh` - SSH connection
- `-msf` - Metasploit handler

### 2. File Transfer (`--file`)

Set up file servers and generate download commands:

```bash
# HTTP server with wget command
./red.sh --file tun0 linpeas.sh

# PowerShell download command
./red.sh --file -t iwr tun0 winPEAS.exe

# SMB server
./red.sh --file -s smb tun0 payload.exe

# Certutil for Windows
./red.sh --file -t certutil eth0 nc.exe
```

**Supported Tools:**
- `wget` - Linux (default)
- `curl` - Linux/Mac
- `iwr` - PowerShell
- `certutil` - Windows

**Server Types:**
- `http` - Python HTTP server (default)
- `smb` - Impacket SMB server

### 3. Web Reconnaissance (`--web`)

Perform web application reconnaissance:

```bash
# Full subdomain workflow
./red.sh --web example.com --all

# Passive subdomain enumeration
./red.sh --web example.com -subfinder -output

# Directory bruteforce
./red.sh --web https://example.com -dir

# Vulnerability scan
./red.sh --web https://example.com -nuclei -output

# Virtual host discovery
./red.sh --web example.com -ffuf-vhost
```

**Available Scans:**
- `--all` - Full workflow (Subfinder → HTTPX)
- `-subfinder` - Passive subdomain discovery
- `-gobuster-dns` - Active DNS bruteforce
- `-httpx` - Web server validation
- `-dir` - Directory bruteforce
- `-ffuf-vhost` - Virtual host discovery
- `-nuclei` - Vulnerability scanning
- `-dns` - DNS reconnaissance
- `-katana` - Web crawling
- `-tech` - Technology detection
- `-screenshots` - Screenshot capture
- `-waf` - WAF detection

## 📚 Examples & Cheat Sheet

Access the comprehensive cheat sheet:

```bash
./red.sh --examples
```

This displays categorized examples for all modules with copy-paste ready commands.

## ⚙️ Options

### Global Options

- `-c` - Copy command only (dry run, don't execute)
- `-output` - Save results to file (web module)
- `-h` / `--help` - Show help for specific module

### Infrastructure Options

- `-U user:pass` - Credentials
- `-d domain` - Domain name
- `-i iface` - Network interface (default: tun0)
- `-p port` - Port number (default: 4444)

### File Transfer Options

- `-w` - Add output flag to download command
- `-t tool` - Download tool (wget/curl/iwr/certutil)
- `-s server` - Server type (http/smb)

## 🛠️ Installation

### Prerequisites

Install the tools you plan to use:

```bash
# Core tools
sudo apt install nmap smbclient smbmap enum4linux-ng

# Optional tools
sudo apt install rustscan netexec bloodhound-ce-python
sudo apt install subfinder httpx ffuf gobuster nuclei
sudo apt install impacket-scripts xfreerdp3 sshpass
```

### Setup

```bash
# Clone or download
git clone <repository-url>
cd RedToy-CLI

# Make executable
chmod +x red.sh

# Run
./red.sh
```

### Bash Completion (Optional)

Enable tab completion:

```bash
# Generate completion script
./red.sh --install-completion > ~/.red-completion.sh

# Add to your .bashrc
echo "source ~/.red-completion.sh" >> ~/.bashrc
source ~/.bashrc
```

## 💡 Pro Tips

1. **Dry Run First** - Use `-c` flag to preview commands before execution
   ```bash
   ./red.sh --infra -nmap -c 10.10.10.10
   ```

2. **Save Output** - Use `-output` flag for web scans to save results
   ```bash
   ./red.sh --web example.com -subfinder -output
   ```

3. **Combine Tools** - Run multiple tools in one command
   ```bash
   ./red.sh --infra -nmap -smb-c -enum4 10.10.10.10
   ```

4. **Quick Reference** - Keep the cheat sheet handy
   ```bash
   ./red.sh --examples | less
   ```

## 📝 Configuration

### Wordlist Paths

Default wordlist paths (customize via environment variables):

```bash
export SECLISTS_DIR="/usr/share/seclists"
export WORDLIST_DIR="$SECLISTS_DIR/Discovery/Web-Content/directory-list-2.3-medium.txt"
export WORDLIST_SUBDOMAIN="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-5000.txt"
export WORDLIST_VHOST="$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-20000.txt"
```

## 🔍 Examples by Use Case

### Initial Reconnaissance
```bash
# Quick port scan
./red.sh --infra -rust 10.10.10.10

# Detailed Nmap scan
./red.sh --infra -nmap 10.10.10.10
```

### SMB Enumeration
```bash
# Anonymous enumeration
./red.sh --infra -smb-c -smb-m -enum4 10.10.10.10

# With credentials
./red.sh --infra -smb-c -smb-m -enum4 -U admin:pass 10.10.10.10
```

### Active Directory
```bash
# BloodHound collection
./red.sh --infra -bloodhound -U user:pass -d corp.local 10.10.10.10

# NetExec enumeration
./red.sh --infra -nxc -U admin:pass 10.10.10.10
```

### Web Application Testing
```bash
# Full subdomain discovery
./red.sh --web example.com --all

# Directory enumeration
./red.sh --web https://example.com -dir -output

# Vulnerability scanning
./red.sh --web https://example.com -nuclei -output
```

### File Exfiltration/Transfer
```bash
# Linux target
./red.sh --file tun0 linpeas.sh

# Windows target
./red.sh --file -t iwr tun0 winPEAS.exe
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always ensure you have explicit permission before testing any systems you do not own.

## 📄 License

This project is provided as-is for educational and professional security testing purposes.

## 🆘 Getting Help

```bash
# Main help
./red.sh

# Module-specific help
./red.sh --infra -h
./red.sh --file -h
./red.sh --web -h

# Interactive mode
./red.sh --interactive

# Examples and cheat sheet
./red.sh --examples
```

---

**Version:** 2.0  
**Author:** Red Team Operations  
**Last Updated:** 2025-11-26
