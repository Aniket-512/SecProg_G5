import subprocess
import ipaddress
import os

def get_wg_details(interface="wg0"):
    # Get public key
    pub_key = subprocess.check_output(['wg', 'show', interface, 'public-key']).strip()
 
    # Get interface config (for IP and port)
    config = subprocess.check_output(['wg', 'show', interface, 'listen-port']).decode().strip()
    listen_port = int(config)

    # Get IP address (assumes it's already configured with `ip addr`)
    ip_output = subprocess.check_output(['ip', 'addr', 'show', interface]).decode()
    priv_ip = None
    for line in ip_output.split('\n'):
        line = line.strip()
        if line.startswith('inet '):
            priv_ip = line.split()[1].split('/')[0]
            break

    # Convert IP to 16-byte format
    pub_ip = "103.6.170.137"
    priv_ip_bytes = ipaddress.ip_address(priv_ip).packed
    pub_ip_bytes = ipaddress.ip_address(pub_ip).packed


    return {
	"public_ip": pub_ip_bytes,     # 103.6.170.137
        "pub_key": pub_key,
        "private_ip": priv_ip_bytes,   # 10.5.0.1
        "listen_port": listen_port     # 51820
    }
