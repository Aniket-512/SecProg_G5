import socket
import sqlite3
import uuid
import threading
from datetime import datetime

from messages import dump_message, load_message
from database import get_all_servers
from crypto import encrypt, decrypt, load_key

# Configuration
WG_PORT = 8089  # Port server listens on
SQLITE_DB = 'messages.db'  # Local DB to store sent and received messages
BUFFER_SIZE = 4096


def select_server():
    servers = get_all_servers()
    if not servers:
        print("[!] No servers found. Is CockroachDB running and populated?")
        return None

    print("Available servers:")
    for idx, srv in enumerate(servers):
        ip_str = ".".join(str(b) for b in srv['server_privip'])
        print(f"{idx}: {srv['server_name']} ({ip_str})")

    try:
        choice = int(input("Select server number: "))
        return servers[choice]
    except (ValueError, IndexError):
        print("[!] Invalid choice.")
        return None


def compose_message():
    sender = input("Your username: ")
    recipient = input("Recipient username: ")
    message = input("Enter your message: ")
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    msg = {
        "type": "message",
        "from": sender,
        "to": recipient,
        "to_type": "user",
        "payload": message,
        "payload_type": "text",
        "timestamp": timestamp
    }
    return dump_message(msg)  # Validated and JSON-encoded bytes


def send_over_udp(encrypted_bytes, target_ip_bytes):
    ip_str = socket.inet_ntoa(target_ip_bytes)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(encrypted_bytes, (ip_str, WG_PORT))
        print(f"[+] Message sent to {ip_str} via UDP.")


def store_message_locally(msg_dict):
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                type TEXT,
                from_user TEXT,
                to_user TEXT,
                to_type TEXT,
                payload TEXT,
                payload_type TEXT,
                timestamp TEXT,
                payload_id TEXT
            );
        """)

        cur.execute("""
            INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4()),
            msg_dict.get("type"),
            msg_dict.get("from"),
            msg_dict.get("to"),
            msg_dict.get("to_type"),
            msg_dict.get("payload"),
            msg_dict.get("payload_type"),
            msg_dict.get("timestamp"),
            msg_dict.get("payload_id")
        ))

        conn.commit()
        print("[+] Message stored locally.")
    except Exception as e:
        print(f"[!] SQLite error: {e}")
    finally:
        conn.close()


def listen_for_messages(key):
    def handler():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("", WG_PORT))
            print("[+] Listening for incoming messages...")
            while True:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                try:
                    decrypted = decrypt(data, key)
                    msg = load_message(decrypted)
                    print(f"\n[+] Message received from {msg['from']}: {msg['payload']}")
                    store_message_locally(msg)
                except Exception as e:
                    print(f"[!] Failed to decrypt/parse message from {addr}: {e}")

    thread = threading.Thread(target=handler, daemon=True)
    thread.start()


def main():
    key = load_key()
    listen_for_messages(key)

    server = select_server()
    if not server:
        return

    target_ip = server["server_privip"]

    while True:
        print("\n--- Send New Message ---")
        raw_msg = compose_message()
        encrypted = encrypt(raw_msg, key)
        send_over_udp(encrypted, target_ip)
        store_message_locally(eval(raw_msg.decode("utf-8")))


if __name__ == "__main__":
    main()

# Final client.py with AES256-GCM encryption, UDP messaging, message receiving, and local SQLite storage
