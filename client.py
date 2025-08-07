import socket
import sqlite3
import uuid
import threading
import hashlib
import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from messages import dump_message, load_message
#from database import get_all_servers
from crypto import encrypt, decrypt, load_key, generate_key

WG_PORT = 8089
SQLITE_DB = 'messages.db'
BUFFER_SIZE = 4096


#def select_server():
    #servers = get_all_servers()
    #if not servers:
        #print("No servers found. Is CockroachDB running?")
        #return None
   # print("Available servers:")
    #for idx, srv in enumerate(servers):
        #print(f"{idx}: {srv['server_name']} ({srv['server_privip']})")
    #choice = int(input("Select server number: "))
    #return servers[choice]



def lookup_user(username, server_ip):
    """Look up a user's IP address via server"""
    try:
        request_id = str(uuid.uuid4())
        lookup_request = {
            "type": "user_lookup_request",
            "request_id": request_id,
            "from_server": "client",
            "target_user_id": username,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        # Send lookup request to server
        request_data = dump_message(lookup_request)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, WG_PORT))
            sock.sendall(request_data)
            
            # Wait for response
            response_data = sock.recv(BUFFER_SIZE)
            if response_data:
                response = load_message(response_data)
                if response.get("type") == "user_lookup_response" and response.get("request_id") == request_id:
                    return response.get("online", False)
        
        return False
    except Exception as e:
        print(f"Error looking up user {username}: {e}")
        return False


def ping_test(target_ip):
    """Perform ping test to check if target is reachable"""
    try:
        # Use ping command (works on Windows/Linux)
        result = subprocess.run(['ping', '-c', '1', '-W', '2000', target_ip], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        try:
            # Windows ping format
            result = subprocess.run(['ping', '-n', '1', '-w', '2000', target_ip], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False


def get_user_ip_from_server(username, server_ip):
    """Get user IP address from server via HTTP API"""
    try:
        import urllib.request
        import urllib.error
        
        # Query the server's HTTP API for online users
        url = f"http://103.6.170.137:8091/online_users"
        
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            # Find the user in the online users list
            for user in data:
                if user.get("username") == username:
                    # Convert bytes to IP string if needed
                    latest_ip = user.get("latest_ip")
                    if isinstance(latest_ip, str) and latest_ip.startswith("\\x"):
                        # Convert hex string to IP
                        import ipaddress
                        ip_bytes = bytes.fromhex(latest_ip.replace("\\x", ""))
                        return str(ipaddress.ip_address(ip_bytes))
                    elif isinstance(latest_ip, list):
                        # Convert byte array to IP
                        import ipaddress
                        return str(ipaddress.ip_address(bytes(latest_ip)))
                    return latest_ip
                    
        return None
        
    except Exception as e:
        print(f"Error getting user IP from server: {e}")
        return None


def compose_message_with_lookup(username, recipient, server_ip):
    """Enhanced message composition with user lookup"""
    
    # Look up recipient's IP address
    print(f"Looking up user {recipient}...")
    recipient_ip = get_user_ip_from_server(recipient, server_ip)
    
    if not recipient_ip:
        print(f"User {recipient} not found or offline.")
        return None, None
    
    # Perform ping test
    print(f"Testing connectivity to {recipient} at {recipient_ip}...")
    if not ping_test(recipient_ip):
        print(f"User {recipient} appears to be offline (ping failed).")
        return None, None
    
    print(f"User {recipient} is online at {recipient_ip}. You can send messages!")

    message = input("Message: ")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    msg = {
        "type": "message",
        "from": username,
        "to": recipient,
        "to_type": "user",
        "payload": message,
        "payload_type": "text",
        "timestamp": timestamp
    }
    return dump_message(msg), recipient_ip  # Validated + UTF-8 encoded, target IP


def send_over_tcp(encrypted_bytes, target_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((target_ip, WG_PORT))
            sock.sendall(encrypted_bytes)
            print("Message sent via TCP.")
    except Exception as e:
        print(f"Error sending message: {e}")


def store_locally(raw_msg_bytes):
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        msg = json.loads(raw_msg_bytes.decode("utf-8"))

        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                type TEXT, from_user TEXT, to_user TEXT,
                to_type TEXT, payload TEXT, payload_type TEXT,
                timestamp TEXT, payload_id TEXT
            )
        """)

        cur.execute("""
            INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            msg.get("type"),
            msg.get("from"),
            msg.get("to"),
            msg.get("to_type"),
            msg.get("payload"),
            msg.get("payload_type"),
            msg.get("timestamp"),
            msg.get("payload_id")
        ))
        conn.commit()
        print("Message stored locally in SQLite.")
    except Exception as e:
        print("SQLite error:", e)
    finally:
        conn.close()


def listen_for_incoming_messages(key, listen_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', listen_port))
        server_sock.listen(5)
        print(f"Listening for incoming messages on port {listen_port}...")
        
        while True:
            try:
                client_sock, addr = server_sock.accept()
                threading.Thread(target=handle_incoming_connection, args=(client_sock, addr, key), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

def handle_incoming_connection(client_sock, addr, key):
    try:
        with client_sock:
            data = client_sock.recv(BUFFER_SIZE)
            if data:
                plaintext = decrypt(data, key)
                msg = load_message(plaintext)
                print(f"\nMessage received from {msg['from']}: {msg['payload']}\n")
                store_locally(plaintext)
    except Exception as e:
        print(f"Error handling connection from {addr}: {e}")

def register_with_server(username, server_ip, key):
    """Register this client with the server"""
    try:
        # Send a registration message to the server
        registration = {
            "type": "message",
            "from": username,
            "to": "server_registration",
            "to_type": "user", 
            "payload": "client_registration",
            "payload_type": "text",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        msg_bytes = dump_message(registration)
        encrypted = encrypt(msg_bytes, key)
        
        # Send to server to register
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_ip, 8089))
            sock.sendall(encrypted)
            print(f"✓ Registered user '{username}' with server")
            
    except Exception as e:
        print(f"✗ Failed to register with server: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-ip', type=str, help='Server private IP address')
    parser.add_argument('--listen-port', type=int, default=8089, help='Local listening port')
    parser.add_argument('--username', type=str, help='Your username')
    args = parser.parse_args()

    ip = args.server_ip or input("Enter server IP: ").strip()
    listen_port = args.listen_port
    username = args.username or input("Your username: ").strip()

    # Load or generate encryption key
    try:
        key = load_key()
        print("Loaded existing encryption key.")
    except FileNotFoundError:
        print("No encryption key found. Generating new key...")
        key = generate_key()
        print("New encryption key generated and saved.")
    
    # Start listener with custom port
    threading.Thread(target=listen_for_incoming_messages, args=(key, listen_port), daemon=True).start()

    # Register with server
    register_with_server(username, ip, key)
    
    print(f"\nWelcome {username}! You can now send messages.")
    print("=" * 50)
    
    while True:
        print(f"\n[{username}]")
        recipient = input("Recipient username (or 'quit' to exit): ").strip()
        
        if recipient.lower() == 'quit':
            break
            
        raw_msg, target_ip = compose_message_with_lookup(username, recipient, ip)
        if raw_msg is None:
            continue
        encrypted = encrypt(raw_msg, key)
        send_over_tcp(encrypted, target_ip)
        store_locally(raw_msg)

if __name__ == '__main__':
    main()