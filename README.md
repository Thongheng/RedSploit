# 🔴 RedSploit

A command-line tool for penetration testing and red team operations.

## 🚀 Quick Start

```bash
# Interactive mode
python red.py

# Run with flags
python red.py -i -nmap 10.10.10.10          # Infra scan
python red.py -w example.com -subfinder     # Web recon
python red.py -f tun0 linpeas.sh            # File transfer
```

**Aliases:** `-i` (infra), `-w` (web), `-f` (file)  
**Variables:** `-T` (target), `-U` (user), `-D` (domain), `-H` (hash)

## 📖 Modules

### Infrastructure (`-i`)
Network scanning, SMB, Active Directory

**Tools:** `-nmap`, `-rust`, `-smb-c`, `-smb-m`, `-enum4`, `-nxc`, `-bloodhound`, `-ftp`, `-rdp`, `-ssh`, `-msf`

```bash
python red.py -i -nmap -smb-c 10.10.10.10
python red.py -i -bloodhound -U user:pass -D domain.local 10.10.10.10
```

### Web (`-w`)
Subdomain discovery, directory bruteforce, vulnerability scanning

**Tools:** `-subfinder`, `-httpx`, `-dir`, `-nuclei`, `-wpscan`, `-katana`, `-tech`, `-waf`, `-screenshots`, `-subzy`, `-arjun`

```bash
python red.py -w example.com --all
python red.py -w https://example.com -dir -nuclei
```

### File Transfer (`-f`)
Generate download commands and start servers

**Tools:** `wget`, `curl`, `iwr`, `certutil` | **Servers:** `http`, `smb`

```bash
python red.py -f tun0 linpeas.sh              # wget command
python red.py -f -t iwr tun0 winPEAS.exe      # PowerShell
python red.py -f -s smb tun0 payload.exe      # SMB server
```

## 🛠️ Installation

```bash
git clone <repo-url>
cd RedSploit
python red.py
```

**Prerequisites:**
```bash
sudo apt install nmap smbclient subfinder httpx ffuf gobuster nuclei
```

## 💡 Tips

- **Dry run:** Add `-c` to preview commands
- **Save output:** Use `-output` for web scans
- **Get help:** `python red.py -i -h`, `python red.py -w -h`, `python red.py -f -h`

## ⚠️ Disclaimer

For authorized security testing and educational purposes only.

---

**Version:** 3.0 | **Updated:** 2025-12-02
