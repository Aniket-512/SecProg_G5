import socket
import json
import threading
from database import get_connection, initialize_tables
from messages import load_message

# Server bind config
WG_INTERFACE_IP = "10.5.0.1"  # IP assigned to server in WireGuard network
PORT = 8089  # Port for chat messages

BUFFER_SIZE = 4096


def handle_packet(data, addr, sock):
    try:
        message = load_message(data)
        msg_type = message.get("type")

        if msg_type == "private_message":
            target_username = message["to"]
            forward_message_to_user(target_username, message, sock)

        elif msg_type == "group_message":
            forward_message_to_all(message, sock)

        elif msg_type == "file_transfer":
            # Placeholder
            print("Received file_transfer request (not implemented)")
        
        else:
            print("Unknown message type:", msg_type)

    except Exception as e:
        print(f"Error handling message from {addr}: {e}")


def forward_message_to_user(username, message, sock):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT latest_ip FROM user_info_table WHERE username = %s;", (username,))
                row = cur.fetchone()
                if row:
                    target_ip = row[0]
                    sock.sendto(json.dumps(message).encode(), (target_ip, PORT))
                    print(f"Forwarded private message to {username} at {target_ip}")
                else:
                    print(f"User '{username}' not found in database")
    except Exception as e:
        print(f"Database error forwarding to {username}: {e}")


def forward_message_to_all(message, sock):
    try:
        users = get_online_users()
        for user in users:
            ip = user["latest_ip"]
            sock.sendto(json.dumps(message).encode(), (ip, PORT))
        print(f"Broadcasted group message to {len(users)} users.")
    except Exception as e:
        print("Error broadcasting message:", e)


def server_loop():
    print(f"[+] Starting GuardedIM server on {WG_INTERFACE_IP}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((WG_INTERFACE_IP, PORT))
	# Initialize tables in DB
	initialize_tables()
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            threading.Thread(target=handle_packet, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    server_loop()
