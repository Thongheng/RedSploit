RedSploit
- [ ] Playbook 

```
# 1. Subfinder
subfinder -d $TARGET -silent -o subfinder.txt
# 2. Assetfinder
assetfinder --subs-only $TARGET > assetfinder.txt
# 3. Dig AXFR (Zone Transfer)
dig axfr @$TARGET $TARGET > dig_axfr.txt
# 4. FFUF VHost
ffuf -u http://$TARGET -H "Host: FUZZ.$TARGET" -w $WORDLIST_SUBDOMAIN -ic -mc all -s -o ffuf_vhost.txt
# 5. Combine & Sort
cat subfinder.txt assetfinder.txt dig_axfr.txt ffuf_vhost.txt> all_raw.txt
sort -u all_raw.txt
```

- [ ] add config to each submodule for configuration 
      - [ ] nmap config : -sU
      - [ ] smbclient config : -N for no auth 
      - [ ] add https config for target 
- [ ] add

```
wappybird -u http://$TARGET 
# for tech fingerprint 
```