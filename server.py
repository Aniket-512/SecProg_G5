# External Libraries
import socket
import json
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import ipaddress
import urllib.parse

# Local .py files
import wireguard
import database
import messages

# Server bind config
WG_INTERFACE_IP = "10.0.5.1"  # Use WireGuard IP for production

CONTROL_PORT = 8089  # Port for HTTP control plane
DATA_PORT = 8091  # Port for chat messages

BUFFER_SIZE = 4096

server = {
    "server_name": "group5",
    "server_port": CONTROL_PORT
}


def handle_packet(data, addr, sock):
    try:
        message = messages.load_message(data)
        msg_type = message.get("type")

        # Register user session when they send a message
        if "from" in message:
            database.register_user_session(message["from"], addr[0])

        if msg_type == "message":
            target_username = message["to"]
            forward_message_to_user(target_username, message, sock)

        elif msg_type == "group_message":
            forward_message_to_all(message, sock)

        elif msg_type == "message_file":
            target_username = message["to"]
            forward_message_to_user(target_username, message, sock)
            
        elif msg_type == "group_file":
            forward_message_to_all(message, sock)
            
        elif msg_type == "user_lookup_request":
            handle_user_lookup_request(message, addr, sock)
            
        elif msg_type == "online_user_request":
            handle_online_user_request(message, addr, sock)
        
        else:
            print("Unknown message type:", msg_type)

    except Exception as e:
        print(f"Error handling message from {addr}: {e}")


def forward_message_to_user(username, message, target_sock):
    try:
        with database.get_connection() as conn:
            with conn.cursor() as cur:
                # fetch target users's IP
                cur.execute("SELECT latest_ip FROM user_info_table WHERE username = %s;", (username,))
                row = cur.fetchone()
                if row:
                    target_ip = row[0]
                    # Convert bytes to string if needed
                    if isinstance(target_ip, bytes):
                        target_ip = str(ipaddress.ip_address(target_ip))
                    
                    # Send via TCP to the target user
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_sock:
                            target_sock.connect((target_ip, DATA_PORT))
                            target_sock.sendall(json.dumps(message).encode())
                            print(f"Forwarded message to {username} at {target_ip}")
                    except Exception as e:
                        print(f"Failed to forward to {username}: {e}")
                else:
                    print(f"User '{username}' not found in database")
    except Exception as e:
        print(f"Database error forwarding to {username}: {e}")


def forward_message_to_all(message, target_sock):
    try:
        users = database.get_online_users()
        successful_sends = 0
        for user in users:
            ip = user["latest_ip"]
            # Convert bytes to string if needed
            if isinstance(ip, bytes):
                import ipaddress
                ip = str(ipaddress.ip_address(ip))
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_sock:
                    target_sock.connect((ip, DATA_PORT))
                    target_sock.sendall(json.dumps(message).encode())
                    successful_sends += 1
            except Exception as e:
                print(f"Failed to send to {user['username']} at {ip}: {e}")
                
        print(f"Broadcasted group message to {successful_sends}/{len(users)} users.")
    except Exception as e:
        print("Error broadcasting message:", e)


def handle_user_lookup_request(message, addr, client_sock):
    """Handle user lookup request from other servers"""
    try:
        target_user = message.get("target_user_id")
        request_id = message.get("request_id")
        
        # Check if user is online
        with database.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT user_id FROM user_info_table 
                    WHERE username = %s AND last_seen > NOW() - INTERVAL '5 minutes'
                """, (target_user,))
                user_found = cur.fetchone() is not None
        
        response = {
            "type": "user_lookup_response",
            "request_id": request_id,
            "user_id": target_user,
            "online": user_found,
            "response_server": "group5",
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        client_sock.sendall(json.dumps(response).encode())
        
    except Exception as e:
        print(f"Error handling user lookup request: {e}")


def handle_online_user_request(message, addr, client_sock):
    """Handle request for online users list"""
    try:
        users = database.get_online_users()
        user_list = [{"user_id": user["username"], "name": user["display_name"] or user["username"]} 
                    for user in users]
        
        response = {
            "type": "online_user_response", 
            "server_id": "group5",
            "online_users": user_list
        }
        
        client_sock.sendall(json.dumps(response).encode())
        
    except Exception as e:
        print(f"Error handling online user request: {e}")


class HTTPControlHandler(BaseHTTPRequestHandler):
    """HTTP handler for control plane requests"""
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            if self.path == '/servers':
                # Return server information table
                servers = database.get_all_servers()
                response = json.dumps(servers, default=str)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response.encode())
                
            elif self.path == '/online_users':
                # Return online users
                users = database.get_online_users()
                response = json.dumps(users, default=str)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response.encode())
                
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'Not Found')
                
        except Exception as e:
            print(f"HTTP handler error: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Internal Server Error')
    
    def log_message(self, format, *args):
        """Override to reduce logging noise"""
        pass


def start_http_server():
    """Start the HTTP control plane server"""
    try:
        httpd = HTTPServer((WG_INTERFACE_IP, CONTROL_PORT), HTTPControlHandler)
        print(f"[+] HTTP control server started on {WG_INTERFACE_IP}:{CONTROL_PORT}")
        httpd.serve_forever()
    except Exception as e:
        print(f"HTTP server error: {e}")


def handle_client(client_sock, addr):
    """Handle individual client connections"""
    try:
        data = client_sock.recv(BUFFER_SIZE)
        if data:
            handle_packet(data, addr, client_sock)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        client_sock.close()


def server_loop():
    wg_info = wireguard.get_wg_details()
    print(f"[+] Starting GuardedIM server on {WG_INTERFACE_IP}:{DATA_PORT}")
    
    # Start HTTP control server in background
    threading.Thread(target=start_http_server, daemon=True).start()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((WG_INTERFACE_IP, DATA_PORT))
        sock.listen(10)
        
        # Initialize tables in DB
        database.initialize_tables()

        server["server_pubip"] = wg_info["public_ip"]
        server["server_pubkey"] = wg_info["pub_key"]
        server["server_privip"] = wg_info["private_ip"]
        server["server_presharedkey"] = database.get_preshared_key()

        # Add/update row in CockroachDB server_info_table
        database.upsert_server(server)
        print("[+] Database connection and setup complete")

        # Loop to listen for connections
        print("[+] Listening...\n")
        while True:
            try:
                client_sock, addr = sock.accept()
                threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")


if __name__ == "__main__":
    server_loop()
