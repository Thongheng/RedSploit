# Bash completion for red command

_red_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Global options
    local global_opts="-h -T -U -D -H -i -w -f -set"
    
    # Common flags for all modules
    local common_opts="-c --copy -p --preview -e --edit"
    
    # Infrastructure module flags
    local infra_opts="-nmap -rustscan -smbclient -smbmap -enum4linux -netexec -bloodhound -ftp -msf -rdp -ssh -evil_winrm -psexec -wmiexec -secretsdump -kerbrute"
    
    # Web module flags
    local web_opts="-subfinder -gobuster_dns -httpx -dir_ffuf -vhost -dir_ferox -dir_dirsearch -nuclei -wpscan -arjun -dns -subzy -katana -waf -screenshots -tech"
    
    # File module flags
    local file_opts="-download -base64 -http -smb"
    
    # Start with global options
    opts="$global_opts"
    
    # Check if any module flag is present in the command line
    if [[ " ${COMP_WORDS[@]} " =~ " -i " ]]; then
        # Infrastructure module active
        opts="$opts $infra_opts $common_opts"
    elif [[ " ${COMP_WORDS[@]} " =~ " -w " ]]; then
        # Web module active
        opts="$opts $web_opts $common_opts"
    elif [[ " ${COMP_WORDS[@]} " =~ " -f " ]]; then
        # File module active
        opts="$opts $file_opts $common_opts"
    fi
    
    # Handle specific option values
    case "${prev}" in
        -T|-U|-D|-H)
            # No completion for these (user input)
            return 0
            ;;
        -t|--tool)
            # Tool options for file module
            COMPREPLY=( $(compgen -W "wget curl iwr certutil scp base64" -- ${cur}) )
            return 0
            ;;
        -s|--server)
            # Server type options
            COMPREPLY=( $(compgen -W "http smb" -- ${cur}) )
            return 0
            ;;
        *)
            ;;
    esac
    
    # Check if we should fallback to file completion (only for file module and when not starting a flag)
    if [[ " ${COMP_WORDS[@]} " =~ " -f " ]] && [[ ! "${cur}" =~ ^- ]]; then
         COMPREPLY=( $(compgen -f -- ${cur}) )
         return 0
    fi
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _red_completion red
