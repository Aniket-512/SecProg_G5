#!/usr/bin/env python3
"""
Group 5 WireGuard Module
WireGuard interface detection and configuration
Network: 10.0.5.0/24 (Group 5)
"""

import subprocess
import ipaddress
import os

# Server configuration
SERVER_PUBLIC_IP = "103.6.170.137"
WIREGUARD_PORT = 51820

# WireGuard network configuration for Group 5
WIREGUARD_SERVER_IP = "10.0.5.1"
WIREGUARD_NETWORK = "10.0.5.0/24"

def get_wg_details(interface="wg0"):
    """
    Get actual WireGuard details from running interface
    """
    try:
        # Get real WireGuard public key
        pub_key_result = subprocess.check_output(['wg', 'show', interface, 'public-key'], 
                                                stderr=subprocess.DEVNULL)
        pub_key = pub_key_result.decode().strip()
        
        # Get listen port
        try:
            port_result = subprocess.check_output(['wg', 'show', interface, 'listen-port'],
                                                stderr=subprocess.DEVNULL)
            listen_port = int(port_result.decode().strip())
        except:
            listen_port = WIREGUARD_PORT
        
        # Get actual IP address from interface
        ip_output = subprocess.check_output(['ip', 'addr', 'show', interface],
                                          stderr=subprocess.DEVNULL).decode()
        priv_ip = None
        for line in ip_output.split('\n'):
            line = line.strip()
            if line.startswith('inet '):
                priv_ip = line.split()[1].split('/')[0]
                break
        
        if not priv_ip:
            raise ValueError("No IP address found on interface")
        
        # Convert to bytes format per specification
        priv_ip_bytes = ipaddress.ip_address(priv_ip).packed
        pub_ip_bytes = ipaddress.ip_address(SERVER_PUBLIC_IP).packed
        
        return {
            "public_ip": pub_ip_bytes,      # Server public IP
            "pub_key": pub_key.encode(),    # Real WireGuard public key
            "private_ip": priv_ip_bytes,    # Real interface IP
            "listen_port": listen_port,     # Real WireGuard port
            "interface": interface,
            "status": "active"
        }
        
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        # Return None when WireGuard not available
        return None

def get_wg_interface_ip(interface="wg0"):
    """
    Get actual IP address from WireGuard interface
    """
    try:
        result = subprocess.run(['ip', 'addr', 'show', interface], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('inet '):
                    return line.split()[1].split('/')[0]
                    
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    return None

def validate_group5_ip(ip_address):
    """
    Validate IP address is in Group 5 WireGuard network (10.0.5.0/24)
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        network = ipaddress.ip_network(WIREGUARD_NETWORK)
        
        result = {
            "valid": ip in network,
            "ip": str(ip),
            "network": WIREGUARD_NETWORK,
            "message": ""
        }
        
        if result["valid"]:
            result["message"] = f"Valid Group 5 WireGuard IP"
        else:
            result["message"] = f"IP not in Group 5 network ({WIREGUARD_NETWORK})"
        
        return result
        
    except ValueError as e:
        return {
            "valid": False,
            "ip": ip_address,
            "network": WIREGUARD_NETWORK,
            "message": f"Invalid IP format: {e}"
        }

def detect_client_group5_ip():
    """
    Detect client's Group 5 WireGuard IP from actual interface
    """
    wg_ip = get_wg_interface_ip("wg0")
    
    result = {
        "wg_interface_found": wg_ip is not None,
        "wg_ip": wg_ip,
        "validation": None
    }
    
    if wg_ip:
        validation = validate_group5_ip(wg_ip)
        result["validation"] = validation
    
    return result

def generate_wg_config_client(client_ip, private_key=None, server_public_key=None):
    """
    Generate WireGuard client configuration for Group 5
    """
    config = f"""# GuardedIM Group 5 Client Configuration
# Client IP: {client_ip}
# Network: {WIREGUARD_NETWORK}

[Interface]
PrivateKey = {private_key or 'CLIENT_PRIVATE_KEY_HERE'}
Address = {client_ip}/24
DNS = 8.8.8.8

[Peer]
PublicKey = {server_public_key or 'SERVER_PUBLIC_KEY_HERE'}
Endpoint = {SERVER_PUBLIC_IP}:{WIREGUARD_PORT}
AllowedIPs = {WIREGUARD_NETWORK}
PersistentKeepalive = 25
"""
    return config

def generate_wg_config_server(private_key=None):
    """
    Generate WireGuard server configuration for Group 5
    """
    config = f"""# GuardedIM Group 5 Server Configuration
# Server IP: {WIREGUARD_SERVER_IP}

[Interface]
PrivateKey = {private_key or 'SERVER_PRIVATE_KEY_HERE'}
Address = {WIREGUARD_SERVER_IP}/24
ListenPort = {WIREGUARD_PORT}
SaveConfig = true

# Firewall rules
PostUp = iptables -A INPUT -p udp --dport {WIREGUARD_PORT} -j ACCEPT
PostUp = iptables -A INPUT -p tcp --dport 8089 -j ACCEPT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT

PostDown = iptables -D INPUT -p udp --dport {WIREGUARD_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 8089 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT

# Client peers
[Peer]
# Client A
PublicKey = CLIENT_A_PUBLIC_KEY_HERE
AllowedIPs = 10.0.5.2/32

[Peer]
# Client B  
PublicKey = CLIENT_B_PUBLIC_KEY_HERE
AllowedIPs = 10.0.5.3/32
"""
    return config

def get_group_network(group_number):
    """
    Get network information for Group 5 only
    """
    if group_number == 5:
        return {
            "network": WIREGUARD_NETWORK,
            "server_ip": WIREGUARD_SERVER_IP,
            "client_range": "10.0.5.2 - 10.0.5.254"
        }
    else:
        raise ValueError(f"Only Group 5 is supported, got Group {group_number}")

def get_next_available_ip(group_number):
    """
    Suggest next available IP for Group 5
    """
    if group_number == 5:
        # Return suggested client IPs for Group 5
        return "10.0.5.2"  # Client A
    else:
        raise ValueError(f"Only Group 5 is supported, got Group {group_number}")

def setup_wireguard_keys():
    """
    Generate WireGuard key pair
    """
    try:
        private_result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, timeout=10)
        if private_result.returncode != 0:
            return None, None
        
        private_key = private_result.stdout.strip()
        
        public_result = subprocess.run(['wg', 'pubkey'], 
                                     input=private_key, 
                                     capture_output=True, text=True, timeout=10)
        if public_result.returncode != 0:
            return None, None
        
        public_key = public_result.stdout.strip()
        return private_key, public_key
        
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None, None

def get_client_public_key(interface="wg0"):
    """
    Get the current client's WireGuard public key
    """
    try:
        result = subprocess.run(['wg', 'show', interface, 'public-key'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return None

def add_wireguard_peer(peer_ip, peer_public_key, peer_endpoint=None, interface="wg0"):
    """
    Dynamically add a WireGuard peer for direct P2P communication
    
    Args:
        peer_ip: IP address of the peer (e.g., "10.0.5.3")
        peer_public_key: WireGuard public key of the peer
        peer_endpoint: External endpoint of peer (e.g., "203.0.113.1:51820")
        interface: WireGuard interface name (default: wg0)
    
    Returns:
        bool: True if peer was added successfully
    """
    try:
        # Use wg set to add peer dynamically
        cmd = [
            'sudo', 'wg', 'set', interface, 
            'peer', peer_public_key,
            'allowed-ips', f"{peer_ip}/32",
            'persistent-keepalive', '25'
        ]
        
        # Use server endpoint for hub-based P2P communication
        server_endpoint = f"{SERVER_PUBLIC_IP}:{WIREGUARD_PORT}"
        cmd.extend(['endpoint', server_endpoint])
        print(f"[INFO] Adding peer with server endpoint for P2P routing: {server_endpoint}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"[OK] Added WireGuard peer: {peer_ip} ({peer_public_key[:20]}...)")
            return True
        else:
            print(f"[ERROR] Failed to add peer: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Exception adding WireGuard peer: {e}")
        return False

def remove_wireguard_peer(peer_public_key, interface="wg0"):
    """
    Remove a WireGuard peer
    
    Args:
        peer_public_key: WireGuard public key of the peer to remove
        interface: WireGuard interface name (default: wg0)
    
    Returns:
        bool: True if peer was removed successfully
    """
    try:
        cmd = ['sudo', 'wg', 'set', interface, 'peer', peer_public_key, 'remove']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"[OK] Removed WireGuard peer: {peer_public_key[:20]}...")
            return True
        else:
            print(f"[ERROR] Failed to remove peer: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Exception removing WireGuard peer: {e}")
        return False

def list_wireguard_peers(interface="wg0"):
    """
    List current WireGuard peers
    
    Returns:
        list: List of peer information dictionaries
    """
    try:
        result = subprocess.run(['wg', 'show', interface], 
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            peers = []
            current_peer = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('peer:'):
                    current_peer = {'public_key': line.split(':', 1)[1].strip()}
                    peers.append(current_peer)
                elif line.startswith('allowed ips:') and current_peer:
                    current_peer['allowed_ips'] = line.split(':', 1)[1].strip()
                elif line.startswith('endpoint:') and current_peer:
                    current_peer['endpoint'] = line.split(':', 1)[1].strip()
                    
            return peers
    except:
        pass
    return []

def check_peer_exists(peer_public_key, interface="wg0"):
    """
    Check if a peer already exists in WireGuard configuration
    
    Args:
        peer_public_key: Public key to check for
        interface: WireGuard interface name
        
    Returns:
        bool: True if peer exists
    """
    peers = list_wireguard_peers(interface)
    for peer in peers:
        if peer.get('public_key') == peer_public_key:
            return True
    return False