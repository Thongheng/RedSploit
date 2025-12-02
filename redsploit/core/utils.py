import subprocess
import os

def get_ip_address(iface):
    try:
        # Try using 'ip' command
        result = subprocess.check_output(["ip", "-4", "addr", "show", iface], stderr=subprocess.DEVNULL).decode()
        for line in result.split('\n'):
            if "inet" in line:
                return line.strip().split()[1].split('/')[0]
    except:
        pass
    
    try:
        # Try using 'ifconfig'
        result = subprocess.check_output(["ifconfig", iface], stderr=subprocess.DEVNULL).decode()
        import re
        match = re.search(r'inet (?:addr:)?([\d.]+)', result)
        if match:
            return match.group(1)
    except:
        pass
    
    return None
