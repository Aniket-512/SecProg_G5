import socket
import sqlite3
import uuid
from datetime import datetime
from messages import dump_message
from database import get_all_servers
from crypto import encrypt, load_key

WG_PORT = 8089  # Server listens here
SQLITE_DB = 'messages.db'

def select_server():
    servers = get_all_servers()
    if not servers:
        print("No servers found. Is CockroachDB running?")
        return None
    print("Available servers:")
    for idx, srv in enumerate(servers):
        print(f"{idx}: {srv['server_name']} ({srv['server_privip']})")
    choice = int(input("Select server number: "))
    return servers[choice]

def compose_message():
    sender = input("Your username: ")
    recipient = input("Recipient username: ")
    message = input("Message: ")
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
    return dump_message(msg)  # Validated + UTF-8 encoded

def send_over_udp(encrypted_bytes, target_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(encrypted_bytes, (target_ip, WG_PORT))
        print("[+] Message sent via UDP.")

def store_locally(raw_msg_bytes):
    try:
        conn = sqlite3.connect(SQLITE_DB)
        cur = conn.cursor()
        msg = eval(raw_msg_bytes.decode("utf-8"))

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
            msg.get("payload_id")  # could be None
        ))
        conn.commit()
        print("[+] Message stored locally in SQLite.")
    except Exception as e:
        print("[!] SQLite error:", e)
    finally:
        conn.close()

def main():
    server = select_server()
    if not server:
        return
    ip = server["server_privip"]

    raw_msg = compose_message()
    key = load_key()
    encrypted = encrypt(raw_msg, key)

    send_over_udp(encrypted, ip)
    store_locally(raw_msg)

if __name__ == '__main__':
    main()

# Final working client.py using UDP + AES256-GCM, adapted to team CockroachDB setup
