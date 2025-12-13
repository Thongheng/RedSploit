# Shell Completion Installation

RedSploit supports native shell completion (like nmap) for both bash and zsh.

## Quick Setup (Recommended)

Run the automated setup script:

```bash
./setup_completion.sh
```

This will:
- Detect your shell (bash/zsh)
- Install completion to the appropriate location
- Configure your shell rc file
- Tell you how to activate

## Manual Setup

### For Zsh (Recommended for Linux)

**System-wide:**
```bash
sudo cp completions/_red /usr/share/zsh/site-functions/_red
```

**User-only:**
```bash
mkdir -p ~/.zsh/completion
cp completions/_red ~/.zsh/completion/_red

# Add to ~/.zshrc
fpath=(~/.zsh/completion $fpath)
autoload -U compinit && compinit
```

**Reload:**
```bash
source ~/.zshrc
```

### For Bash

**System-wide:**
```bash
sudo cp completions/red.bash /etc/bash_completion.d/red
```

**User-only:**
```bash
mkdir -p ~/.bash_completion.d
cp completions/red.bash ~/.bash_completion.d/red

# Add to ~/.bashrc
for f in ~/.bash_completion.d/*; do source $f; done
```

**Reload:**
```bash
source ~/.bashrc
```

## Testing

```bash
red -<TAB><TAB>
```

### Expected Output (Zsh)
```
-D  -- Set domain name
-H  -- Set NTLM hash
-T  -- Set target IP/hostname/CIDR
-U  -- Set credentials (username:password - auto-splits)
-f  -- File transfer module
...
```

### Expected Output (Bash)
```
-D  -H  -T  -U  -f  -h  -i  -set  -w  --domain  --file  --hash  --help  --infra  --interactive  --target  --user  --web
```
