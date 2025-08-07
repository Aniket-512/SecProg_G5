from datetime import datetime, timedelta
import os

from database import (
    initialize_tables,
    upsert_server,
    upsert_user,
    get_all_servers,
    get_online_users,
    get_preshared_key
)

def test_initialize():
    print("[*] Testing table initialization...")
    initialize_tables()
    print("[+] Tables initialized.")

def test_upsert_server_and_fetch():
    print("[*] Testing upsert_server and get_all_servers...")

    server_data = {
        "server_id": 1,
        "server_name": "Relay1",
        "server_pubip": b"\xC0\xA8\x01\x01",  # 192.168.1.1
        "server_port": 51820,
        "server_privip": b"\x0A\x00\x00\x01",  # 10.0.0.1
        "server_pubkey": b"\x01" * 32,
        "server_presharedkey": b"\x02" * 32
    }

    upsert_server(server_data)
    servers = get_all_servers()
    assert any(s["server_name"] == "Relay1" for s in servers), "Server not found"
    print("[+] Server upsert and fetch passed.")

def test_upsert_user_and_fetch():
    print("[*] Testing upsert_user and get_online_users...")

    user_data = {
        "user_id": 12345,
        "username": "testuser",
        "display_name": "Test User",
        "last_seen": datetime.utcnow(),
        "user_pubkey": os.urandom(32),
        "invite_history": [datetime.utcnow() - timedelta(days=1)],
        "latest_ip": b"\xC0\xA8\x01\x50"  # 192.168.1.80
    }

    upsert_user(user_data)
    users = get_online_users()
    assert any(u["username"] == "testuser" for u in users), "User not found"
    print("[+] User upsert and fetch passed.")

def test_get_preshared_key():
    print("[*] Testing get_preshared_key...")

    psk = get_preshared_key()
    assert isinstance(psk, bytes) and len(psk) == 32, "Invalid preshared key"
    print("[+] Pre-shared key retrieved successfully.")

def run_all_tests():
    test_initialize()
    test_upsert_server_and_fetch()
    test_upsert_user_and_fetch()
    test_get_preshared_key()
    print("\n✅ All database function tests passed.")

if __name__ == "__main__":
    run_all_tests()
