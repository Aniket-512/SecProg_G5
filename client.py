#!/usr/bin/env python3
"""
Group 5 P2P Chat Application
Secure peer-to-peer messaging with full specification compliance
"""

import socket
import sqlite3
import uuid
import threading
import argparse
import json
import time
from datetime import datetime, timezone

from messages import dump_message, load_message
from crypto import encrypt, decrypt, load_key, generate_key
import wireguard

HTTP_PORT = 8089
BUFFER_SIZE = 4096
DATABASE_FILE = 'group5_messages.db'

class Group5Client:
    def __init__(self, server_ip, username, listen_port=8090):
        self.server_ip = server_ip
        self.username = username
        self.listen_port = listen_port
        self.encryption_key = None
        self.running = True
        self.local_wg_ip = None
        self.active_groups = set()
        self.online_users = {}
        
    def initialize(self):
        detection = wireguard.detect_client_group5_ip()
        if detection["wg_interface_found"]:
            self.local_wg_ip = detection["wg_ip"]
            print(f"WireGuard detected: {self.local_wg_ip}:{self.listen_port}")
        
        key_file = "group5_shared_key.bin"
        try:
            self.encryption_key = load_key(key_file)
            print("Encryption key loaded")
        except FileNotFoundError:
            self.encryption_key = generate_key(key_file)
            print("New encryption key generated")
        
        self.setup_database()
        return True
    
    def setup_database(self):
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                message_type TEXT NOT NULL,
                sender TEXT,
                recipient TEXT,
                recipient_type TEXT,
                content TEXT,
                content_type TEXT,
                timestamp TEXT,
                file_id TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS group_memberships (
                group_name TEXT,
                username TEXT,
                joined_at TEXT,
                PRIMARY KEY (group_name, username)
            )
        """)
        conn.commit()
        conn.close()
        print("Database initialized")

    def get_connection_ip(self):
        if self.local_wg_ip:
            return self.local_wg_ip
        if self.server_ip == "103.6.170.137":
            return self.server_ip
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def register_with_server(self):
        try:
            import urllib.request
            connection_ip = self.get_connection_ip()
            registration_data = {
                "username": self.username,
                "ip_address": connection_ip,
                "listen_port": self.listen_port
            }
            
            url = f"http://{self.server_ip}:{HTTP_PORT}/register"
            request_data = json.dumps(registration_data).encode()
            request = urllib.request.Request(url, data=request_data, 
                                           headers={'Content-Type': 'application/json'})
            
            with urllib.request.urlopen(request, timeout=10) as response:
                print(f"Registered: {self.username}@{connection_ip}:{self.listen_port}")
                return True
        except Exception as e:
            print(f"Registration failed: {e}")
            return False

    def send_user_lookup_request(self, target_user):
        """Send user lookup request to server for broadcasting"""
        try:
            import urllib.request
            request_id = str(uuid.uuid4())
            
            lookup_message = {
                "type": "user_lookup_request",
                "request_id": request_id,
                "from_server": "group5_server",
                "target_user_id": target_user,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            
            url = f"http://{self.server_ip}:{HTTP_PORT}/user_lookup?username={target_user}"
            with urllib.request.urlopen(url, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if data.get("type") == "user_lookup_response" and data.get("online"):
                    ip_address = data.get("ip_address")
                    listen_port = data.get("listen_port", 8090)
                    return {"ip": ip_address, "port": listen_port}
                return None
        except Exception:
            return None

    def broadcast_user_status(self, status):
        """Broadcast user status (online/offline) to all servers"""
        status_message = {
            "type": "user_status",
            "user_id": self.username,
            "status": status,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        message_bytes = dump_message(status_message)
        self.store_message(message_bytes)
        print(f"Status broadcast: {self.username} is {status}")

    def send_message(self, recipient, message_text):
        """Send direct message to another user"""
        recipient_info = self.send_user_lookup_request(recipient)
        if not recipient_info:
            print(f"User {recipient} not found")
            return False
        
        message = {
            "type": "message",
            "from": self.username,
            "to": recipient,
            "to_type": "user",
            "payload": message_text,
            "payload_type": "text",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        return self.send_encrypted_message(recipient_info, message)

    def send_message_file(self, recipient, file_content, file_name):
        """Send file message to another user"""
        recipient_info = self.send_user_lookup_request(recipient)
        if not recipient_info:
            print(f"User {recipient} not found")
            return False
        
        file_id = str(uuid.uuid4())
        message = {
            "type": "message_file",
            "from": self.username,
            "to": recipient,
            "to_type": "user",
            "payload": file_content,
            "payload_type": "file",
            "payload_id": file_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        success = self.send_encrypted_message(recipient_info, message)
        if success:
            print(f"File '{file_name}' sent to {recipient}")
        return success

    def send_group_message(self, group_name, message_text):
        """Send message to group and broadcast to all online members"""
        message = {
            "type": "group_message",
            "from": self.username,
            "to": group_name,
            "to_type": "group",
            "payload": message_text,
            "payload_type": "text",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        message_bytes = dump_message(message)
        self.store_message(message_bytes)
        
        # Broadcast to all group members
        group_members = self.get_group_members(group_name)
        for member in group_members:
            if member != self.username:
                member_info = self.send_user_lookup_request(member)
                if member_info:
                    self.send_encrypted_message(member_info, message, is_broadcast=True)
        
        current_time = datetime.now().strftime("%H:%M")
        print(f"[{current_time}] Group message sent to {group_name}")
        return True

    def send_group_file(self, group_name, file_content, file_name):
        """Send file to group and broadcast to all online members"""
        file_id = str(uuid.uuid4())
        message = {
            "type": "group_file",
            "from": self.username,
            "to": group_name,
            "to_type": "group",
            "payload": file_content,
            "payload_type": "file",
            "payload_id": file_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        
        message_bytes = dump_message(message)
        self.store_message(message_bytes)
        
        # Broadcast to all group members
        group_members = self.get_group_members(group_name)
        for member in group_members:
            if member != self.username:
                member_info = self.send_user_lookup_request(member)
                if member_info:
                    self.send_encrypted_message(member_info, message, is_broadcast=True)
        
        current_time = datetime.now().strftime("%H:%M")
        print(f"[{current_time}] File '{file_name}' sent to group {group_name}")
        return True

    def send_encrypted_message(self, recipient_info, message, is_broadcast=False):
        """Send encrypted message to recipient"""
        try:
            message_bytes = dump_message(message)
            encrypted_data = encrypt(message_bytes, self.encryption_key)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(10)
                sock.connect((recipient_info["ip"], recipient_info["port"]))
                sock.sendall(encrypted_data)
                
            if not is_broadcast:
                self.store_message(message_bytes)
                current_time = datetime.now().strftime("%H:%M")
                print(f"[{current_time}] Message delivered to {message['to']}")
            return True
        except Exception as e:
            if not is_broadcast:
                print(f"Delivery failed: {e}")
            return False

    def join_group(self, group_name):
        """Join a chat group"""
        self.active_groups.add(group_name)
        
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO group_memberships VALUES (?, ?, ?)",
                      (group_name, self.username, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        join_message = f"{self.username} joined the group"
        self.send_group_message(group_name, join_message)

    def get_group_members(self, group_name):
        """Get list of group members"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM group_memberships WHERE group_name = ?", (group_name,))
        members = [row[0] for row in cursor.fetchall()]
        conn.close()
        return members

    def store_message(self, message_bytes):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            message = json.loads(message_bytes.decode("utf-8"))
            
            cursor.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                str(uuid.uuid4()),
                message.get("type"),
                message.get("from"),
                message.get("to"),
                message.get("to_type"),
                message.get("payload"),
                message.get("payload_type"),
                message.get("timestamp"),
                message.get("payload_id")
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def show_message_history(self):
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM messages ORDER BY timestamp DESC LIMIT 15")
            messages = cursor.fetchall()
            conn.close()
            
            print("\n--- Message History ---")
            for msg in messages:
                msg_type, sender, recipient, content = msg[1], msg[2], msg[3], msg[5]
                timestamp = datetime.fromisoformat(msg[7].replace('Z', '+00:00'))
                formatted_time = timestamp.strftime("%m-%d %H:%M")
                
                if msg_type == "group_message":
                    print(f"[{formatted_time}] GROUP {recipient}: {sender}: {content}")
                elif msg_type == "message_file":
                    print(f"[{formatted_time}] FILE: {sender} -> {recipient}")
                else:
                    print(f"[{formatted_time}] {sender} -> {recipient}: {content}")
            print("--- End History ---")
        except Exception:
            print("Cannot load message history")

    def listen_for_connections(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.listen_port))
                server_socket.listen(5)
                print(f"Listening on port {self.listen_port}")
                
                while self.running:
                    try:
                        client_socket, address = server_socket.accept()
                        threading.Thread(target=self.handle_incoming_message, 
                                       args=(client_socket, address), daemon=True).start()
                    except Exception:
                        if self.running:
                            continue
        except OSError:
            print(f"Port {self.listen_port} unavailable")
            self.running = False

    def handle_incoming_message(self, client_socket, address):
        try:
            with client_socket:
                data = client_socket.recv(BUFFER_SIZE)
                if data:
                    decrypted_data = decrypt(data, self.encryption_key)
                    message = load_message(decrypted_data)
                    
                    sender = message['from']
                    content = message['payload']
                    msg_type = message.get('type', 'message')
                    current_time = datetime.now().strftime("%H:%M")
                    
                    if msg_type == 'group_message':
                        group_name = message['to']
                        print(f"\n[{current_time}] GROUP {group_name} - {sender}: {content}")
                    elif msg_type == 'group_file':
                        group_name = message['to']
                        print(f"\n[{current_time}] GROUP {group_name} - {sender} sent a file")
                    elif msg_type == 'message_file':
                        print(f"\n[{current_time}] FILE from {sender}: {content}")
                    else:
                        print(f"\n[{current_time}] {sender}: {content}")
                    
                    print(f"[{self.username}] Command: ", end="", flush=True)
                    self.store_message(decrypted_data)
        except Exception:
            pass


    def start_chat_interface(self):
        print(f"\n=== Group 5 P2P Chat Application ===")
        print(f"User: {self.username}")
        print(f"Network: {self.local_wg_ip or 'Local'}")
        print(f"P2P Architecture: Client communication")
        print("Commands: msg <user> | group <name> | file <user> | gfile <group> | join <group> | history | quit")
        print("=" * 50)
        
        while self.running:
            try:
                user_input = input(f"[{self.username}] Command: ").strip()
                
                if user_input == 'quit':
                    self.broadcast_user_status("offline")
                    self.running = False
                elif user_input == 'history':
                    self.show_message_history()
                elif user_input.startswith('join '):
                    group_name = user_input[5:].strip()
                    if group_name:
                        self.join_group(group_name)
                elif user_input.startswith('group '):
                    group_name = user_input[6:].strip()
                    if group_name:
                        message_text = input(f"Message to group {group_name}: ")
                        if message_text:
                            self.send_group_message(group_name, message_text)
                elif user_input.startswith('msg '):
                    recipient = user_input[4:].strip()
                    if recipient:
                        message_text = input(f"Message to {recipient}: ")
                        if message_text:
                            self.send_message(recipient, message_text)
                elif user_input.startswith('file '):
                    recipient = user_input[5:].strip()
                    if recipient:
                        file_name = input(f"File name: ")
                        file_content = input(f"File content: ")
                        if file_name and file_content:
                            self.send_message_file(recipient, file_content, file_name)
                elif user_input.startswith('gfile '):
                    group_name = user_input[6:].strip()
                    if group_name:
                        file_name = input(f"File name: ")
                        file_content = input(f"File content: ")
                        if file_name and file_content:
                            self.send_group_file(group_name, file_content, file_name)
                else:
                    if user_input:
                        message_text = input(f"Message to {user_input}: ")
                        if message_text:
                            self.send_message(user_input, message_text)
                    
            except KeyboardInterrupt:
                self.broadcast_user_status("offline")
                self.running = False
        
        print("Chat application terminated")

def main():
    parser = argparse.ArgumentParser(description='Group 5 P2P Chat Application')
    parser.add_argument('--server-ip', required=True, help='Server IP for user lookup')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--listen-port', type=int, default=8090, help='Listen port')
    
    args = parser.parse_args()
    
    client = Group5Client(args.server_ip, args.username, args.listen_port)
    if not client.initialize():
        return 1
    
    if not client.register_with_server():
        return 1
    
    client.broadcast_user_status("online")
    
    connection_thread = threading.Thread(target=client.listen_for_connections, daemon=True)
    connection_thread.start()
    
    client.start_chat_interface()
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())