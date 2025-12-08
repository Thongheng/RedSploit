# Bash completion for red command

_red_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main options (short flags only)
    opts="-h -T -U -D -H -i -w -f -set"
    
    case "${prev}" in
        -T|-U|-D|-H)
            # No completion for these (user input)
            return 0
            ;;
        *)
            ;;
    esac
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _red_completion red
