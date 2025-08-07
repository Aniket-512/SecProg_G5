import subprocess
import ipaddress
import os

def get_wg_details(interface="wg0"):
    """Mock WireGuard details for testing purposes"""
    try:
        # Try to get real WireGuard details first
        pub_key = subprocess.check_output(['wg', 'show', interface, 'public-key']).strip()
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
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        # Fallback to mock data for testing
        print("[WARNING] WireGuard not found, using mock data for testing")
        pub_ip = "103.6.170.137"
        priv_ip = "10.0.5.1"
        
        return {
            "public_ip": ipaddress.ip_address(pub_ip).packed,
            "pub_key": b"mock_public_key_32_bytes_long!!",
            "private_ip": ipaddress.ip_address(priv_ip).packed,
            "listen_port": 51820
        }
