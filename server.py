#!/usr/bin/env python3
"""
Group 5 P2P Chat Server
HTTP-only server for user lookup and presence tracking
Provides user discovery service for P2P client communication
"""

import json
import logging
import socket
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Local modules
import database
import wireguard

# Server configuration per specification section 2.1
# Group 5 server: 10.0.5.1/32 with HTTP server on port 8089 of WireGuard interface
WG_INTERFACE_IP = "10.0.5.1"  # WireGuard interface IP for Group 5
HTTP_PORT = 8089  # HTTP control plane per specification

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GuardedIMHTTPHandler(BaseHTTPRequestHandler):
    """
    HTTP Control Plane per specification section 2.1:
    "HTTP server listening to port 8089 of the wireguard interface that is 
    responsible for control plane requests"
    """
    
    def do_GET(self):
        """Handle GET requests for user lookup"""
        try:
            parsed_path = urlparse(self.path)
            
            if parsed_path.path == '/user_lookup':
                # User lookup request: /user_lookup?username=bob
                query_params = parse_qs(parsed_path.query)
                if 'username' in query_params:
                    username = query_params['username'][0]
                    user_info = self.lookup_user(username)
                    
                    if user_info:
                        # Per specification: Return IP for direct P2P connection
                        response = {
                            "type": "user_lookup_response", 
                            "user_id": username,
                            "online": True,
                            "ip_address": user_info["latest_ip"],
                            "listen_port": user_info.get("listen_port", 8090),
                            "user_pubkey": user_info.get("user_pubkey", ""),
                            "response_server": "group5",
                            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                        logger.info(f"User lookup: {username} -> {user_info['latest_ip']}:{user_info.get('listen_port', 8090)}")
                    else:
                        response = {
                            "type": "user_lookup_response",
                            "user_id": username, 
                            "online": False,
                            "response_server": "group5",
                            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                        logger.info(f"User lookup: {username} -> offline/not found")
                    
                    self.send_json_response(response)
                else:
                    self.send_error(400, "Missing username parameter")
                    
            elif parsed_path.path == '/get_group_ip':
                # Suggest available IP for any group: /get_group_ip?group=5
                query_params = parse_qs(parsed_path.query)
                group_number = int(query_params.get('group', [5])[0])  # Default to Group 5
                
                try:
                    group_info = wireguard.get_group_network(group_number)
                    suggested_ip = wireguard.get_next_available_ip(group_number)
                    
                    response = {
                        "type": "group_ip_suggestion",
                        "group_number": group_number,
                        "suggested_ip": suggested_ip,
                        "network": group_info["network"],
                        "server_ip": group_info["server_ip"],
                        "client_range": group_info["client_range"],
                        "server_endpoint": f"{wireguard.SERVER_PUBLIC_IP}:{wireguard.WIREGUARD_PORT}",
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                    self.send_json_response(response)
                except ValueError as e:
                    self.send_error(400, f"Invalid group number: {e}")
            
            elif parsed_path.path == '/get_group5_ip':
                # Legacy endpoint for Group 5 compatibility
                suggested_ip = wireguard.get_next_available_ip(5)
                response = {
                    "type": "group5_ip_suggestion", 
                    "suggested_ip": suggested_ip,
                    "ip_range": "10.0.5.2 - 10.0.5.254",
                    "server_endpoint": f"{wireguard.SERVER_PUBLIC_IP}:{wireguard.WIREGUARD_PORT}",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                self.send_json_response(response)
                
            elif parsed_path.path == '/online_users':
                # Get all online users
                users = database.get_online_users()
                
                # Convert to specification format
                online_users = []
                for user in users:
                    ip = user['latest_ip']
                    if isinstance(ip, bytes):
                        import ipaddress
                        ip = str(ipaddress.ip_address(ip))
                    
                    online_users.append({
                        "user_id": user['username'],
                        "ip_address": ip
                    })
                
                response = {
                    "type": "online_user_response",
                    "server_id": "group5", 
                    "online_users": online_users
                }
                self.send_json_response(response)
                
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"HTTP handler error: {e}")
            self.send_error(500, "Internal server error")
    
    def do_POST(self):
        """Handle POST requests for user registration"""
        try:
            if self.path == '/register':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                
                try:
                    user_data = json.loads(post_data.decode())
                    username = user_data.get('username')
                    ip_address = user_data.get('ip_address')
                    listen_port = user_data.get('listen_port', 8090)
                    
                    if username and ip_address:
                        # Get WireGuard public key for P2P peer management
                        user_pubkey = user_data.get('user_pubkey', '')
                        
                        # Validate WireGuard IP with Group 5 support
                        validation = wireguard.validate_group5_ip(ip_address)
                        group_number = user_data.get('group_number')
                        wg_status = user_data.get('wg_status', 'unknown')
                        
                        if validation["valid"]:
                            logger.info(f"Valid Group 5 WireGuard IP: {ip_address}")
                        else:
                            logger.warning(f"Invalid WireGuard IP: {ip_address} - {validation['message']}")
                            if ip_address != "127.0.0.1":  # Don't spam localhost warnings
                                logger.info(f"Client should configure WireGuard with Group 5 IP")
                        
                        # Register user in database with listening port and public key
                        database.register_user_session(username, ip_address, listen_port, user_pubkey)
                        
                        response = {
                            "status": "registered",
                            "username": username,
                            "ip_address": ip_address,
                            "listen_port": listen_port,
                            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                        self.send_json_response(response)
                        logger.info(f"User {username} registered from {ip_address}:{listen_port}")
                    else:
                        self.send_error(400, "Missing username or ip_address")
                        
                except json.JSONDecodeError:
                    self.send_error(400, "Invalid JSON")
            else:
                self.send_error(404, "Endpoint not found")
                
        except Exception as e:
            logger.error(f"POST handler error: {e}")
            self.send_error(500, "Internal server error")
    
    def lookup_user(self, username):
        """Look up user in database"""
        try:
            users = database.get_online_users()
            for user in users:
                if user.get('username') == username:
                    # Convert bytes IP to string if needed
                    ip = user['latest_ip']
                    if isinstance(ip, bytes):
                        import ipaddress
                        ip = str(ipaddress.ip_address(ip))
                    
                    # Decode WireGuard public key if stored as bytes
                    user_pubkey = user.get('user_pubkey', b'')
                    if isinstance(user_pubkey, bytes):
                        user_pubkey = user_pubkey.decode() if user_pubkey != b'placeholder_key' else ''
                    
                    return {
                        "username": username,
                        "latest_ip": ip,
                        "listen_port": user.get('listen_port', 8090),
                        "user_pubkey": user_pubkey,
                        "last_seen": user.get('last_seen')
                    }
            return None
        except Exception as e:
            logger.error(f"User lookup error: {e}")
            return None
    
    def send_json_response(self, data):
        """Send JSON response"""
        response = json.dumps(data, indent=2)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Override to reduce HTTP logging noise"""
        logger.info(f"HTTP {format % args}")

class GuardedIMServer:
    """GuardedIM HTTP-only server for user lookup within WireGuard network"""
    
    def __init__(self):
        self.running = True
    
    def run_server(self):
        """Start HTTP server for user lookup (WireGuard interface only)"""
        logger.info(f"Starting GuardedIM Group 5 HTTP Server")
        logger.info(f"Server IP: {WG_INTERFACE_IP}:{HTTP_PORT}")
        logger.info(f"Network: WireGuard VPN (10.0.5.0/24)")
        logger.info("TRUE P2P MODE: Server only provides user lookup, clients communicate directly")
        
        # Initialize database
        database.TEST_MODE = True  # Use SQLite for testing
        database.initialize_tables()
        logger.info("Database initialized")
        
        # Start HTTP server - bind to all interfaces for production
        try:
            # Bind to all interfaces for server deployment
            server_ip = "0.0.0.0"  # All interfaces for production deployment
            httpd = HTTPServer((server_ip, HTTP_PORT), GuardedIMHTTPHandler)
            logger.info(f"HTTP server listening on {server_ip}:{HTTP_PORT} (all interfaces for testing)")
            logger.info(f"Production: Should bind to {WG_INTERFACE_IP}:{HTTP_PORT}")
            logger.info("Ready for user lookup requests")
            logger.info("Endpoints: /user_lookup?username=X, /online_users, /register")
            logger.info("Process: Client A -> Server (lookup) -> Direct P2P to Client B")
            
            httpd.serve_forever()
            
        except Exception as e:
            logger.error(f"Server error: {e}")
            logger.error("Make sure WireGuard is configured with IP 10.0.5.1")

def main():
    """Main server entry point"""
    try:
        server = GuardedIMServer()
        server.run_server()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Fatal server error: {e}")

if __name__ == "__main__":
    main()