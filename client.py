import socket
import sqlite3
import uuid
from datetime import datetime

from messages import dump_message
from database import get_all_servers
from crypto import encrypt, load_key

# Configuration
WG_PORT = 8089  # Port server listens on
SQLITE_DB = 'messages.db'  # Local DB to store sent messages


def select_server():
    """
    Allows the user to choose a server from CockroachDB.
    """
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
    """
    Prompt user to create a message following the GuardedIM spec.
    """
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
    """
    Sends encrypted bytes over UDP to the selected server.
    """
    ip_str = socket.inet_ntoa(target_ip_bytes)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(encrypted_bytes, (ip_str, WG_PORT))
        print(f"[+] Message sent to {ip_str} via UDP.")


def store_locally(raw_msg_bytes):
    """
    Stores the original (unencrypted) message in local SQLite DB.
    """
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

        msg = eval(raw_msg_bytes.decode("utf-8"))  # Only safe here because we validated with dump_message

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
            msg.get("payload_id")  # Will be None for text messages
        ))

        conn.commit()
        print("[+] Message stored locally.")
    except Exception as e:
        print(f"[!] SQLite error: {e}")
    finally:
        conn.close()


def main():
    """
    Main client loop.
    """
    server = select_server()
    if not server:
        return

    target_ip = server["server_privip"]
    raw_msg = compose_message()
    key = load_key()
    encrypted = encrypt(raw_msg, key)

    send_over_udp(encrypted, target_ip)
    store_locally(raw_msg)


if __name__ == "__main__":
    main()

# ✅ Finalized client.py using AES256-GCM + UDP + WireGuard IP + CockroachDB + SQLite
