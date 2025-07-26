# External Libraries
import socket
import json
import threading

# Local .py files
import wireguard
import database
import messages

# Server bind config
WG_INTERFACE_IP = "10.5.0.1"
PORT = 8089  # Port for chat messages

BUFFER_SIZE = 4096

server = {
    "server_name": "group5",
    "server_port": PORT
}


def handle_packet(data, addr, sock):
    try:
        message = messages.load_message(data)
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
        with database.get_connection() as conn:
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
        users = database.get_online_users()
        for user in users:
            ip = user["latest_ip"]
            sock.sendto(json.dumps(message).encode(), (ip, PORT))
        print(f"Broadcasted group message to {len(users)} users.")
    except Exception as e:
        print("Error broadcasting message:", e)


def server_loop():
    wg_info = wireguard.get_wg_details()
    print(f"[+] Starting GuardedIM server on {WG_INTERFACE_IP}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((WG_INTERFACE_IP, PORT))
        # Initialize tables in DB
        database.initialize_tables()

        server["server_pubip"] = wg_info["public_ip"]
        server["server_pubkey"] = wg_info["pub_key"]
        server["server_privip"] = wg_info["private_ip"]
        server["server_presharedkey"] = database.get_preshared_key()

        # Add/update row in CockroachDB server_info_table
        database.upsert_server(server)
        print("[+] Database connection and setup complete")

        # Loop to listen for packets
        print("[+] Listening...\n")
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            threading.Thread(target=handle_packet, args=(data, addr, sock), daemon=True).start()


if __name__ == "__main__":
    server_loop()
