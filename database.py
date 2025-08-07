import psycopg2
import psycopg2.extras
from datetime import datetime
import logging
import sqlite3
import os

# Test mode flag - set to True if CockroachDB is not available
TEST_MODE = True  # Force SQLite mode for communication testing

DB_CONFIG = {
    "host": "localhost",
    "port": 26257,
    "user": "group5",
    "dbname": "defaultdb",
    "sslmode": "verify-full",
    "sslrootcert": "/root/cockroach_certs/ca.crt",
    "sslcert": "/root/cockroach_certs/client.group5.crt",
    "sslkey": "/root/cockroach_certs/client.group5.key"
}

SQLITE_DB = "guardedim_test.db"


def get_connection():
    global TEST_MODE
    
    if not TEST_MODE:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            logging.info("Successfully connected to CockroachDB")
            return conn
        except Exception as e:
            logging.warning(f"CockroachDB connection failed: {e}, falling back to SQLite test mode")
            TEST_MODE = True
    
    if TEST_MODE:
        # Use SQLite for testing
        conn = sqlite3.connect(SQLITE_DB)
        conn.row_factory = sqlite3.Row  # Makes rows behave like dicts
        return conn

def initialize_tables():
    """
    Create the server_info_table and user_info_table if they don't exist.
    """
    if TEST_MODE:
        # SQLite schema
        create_server_table = """
        CREATE TABLE IF NOT EXISTS server_info_table (
            server_id          INTEGER PRIMARY KEY,
            server_name        TEXT,
            server_pubip       BLOB,
            server_port        INTEGER,
            server_privip      BLOB,
            server_pubkey      BLOB,
            server_presharedkey BLOB
        );
        """

        create_user_table = """
        CREATE TABLE IF NOT EXISTS user_info_table (
            user_id         INTEGER PRIMARY KEY,
            username        TEXT UNIQUE,
            display_name    TEXT,
            last_seen       TEXT,
            user_pubkey     BLOB,
            invite_history  TEXT,
            latest_ip       BLOB
        );
        """
    else:
        # CockroachDB schema
        create_server_table = """
        CREATE TABLE IF NOT EXISTS server_info_table (
            server_id          BIGINT PRIMARY KEY,
            server_name        STRING(64),
            server_pubip       BYTES,
            server_port        INT,
            server_privip      BYTES,
            server_pubkey      BYTES,
            server_presharedkey BYTES
        );
        """

        create_user_table = """
        CREATE TABLE IF NOT EXISTS user_info_table (
            user_id         BIGINT PRIMARY KEY,
            username        STRING(64) UNIQUE,
            display_name    STRING(256),
            last_seen       TIMESTAMP,
            user_pubkey     BYTES,
            invite_history  TIMESTAMP [],
            latest_ip       BYTES
        );
        """

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(create_server_table)
        cur.execute(create_user_table)
        conn.commit()


def upsert_server(server):
    """
    Insert or update a server record.
    server = {
        "server_id": int,
        "server_name": str,
        "server_pubip": bytes,
        "server_port": int,
        "server_privip": bytes,
        "server_pubkey": bytes,
        "server_presharedkey": bytes
    }
    """
    # Generate server_id from private IP if not provided
    if "server_id" not in server:
        # Use hash of private IP as server_id (smaller for SQLite compatibility)
        import hashlib
        if TEST_MODE:
            # Smaller ID for SQLite
            server_id = int.from_bytes(hashlib.sha256(server["server_privip"]).digest()[:4], 'big')
        else:
            server_id = int.from_bytes(hashlib.sha256(server["server_privip"]).digest()[:8], 'big')
        server["server_id"] = server_id
    
    if TEST_MODE:
        # SQLite syntax
        query = """
        INSERT OR REPLACE INTO server_info_table (
            server_id, server_name, server_pubip, server_port,
            server_privip, server_pubkey, server_presharedkey
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            server["server_id"],
            server["server_name"],
            server["server_pubip"],
            server["server_port"],
            server["server_privip"],
            server["server_pubkey"],
            server["server_presharedkey"]
        )
    else:
        # CockroachDB syntax
        query = """
        INSERT INTO server_info_table (
            server_id, server_name, server_pubip, server_port,
            server_privip, server_pubkey, server_presharedkey
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (server_id) DO UPDATE SET
            server_name = EXCLUDED.server_name,
            server_pubip = EXCLUDED.server_pubip,
            server_port = EXCLUDED.server_port,
            server_privip = EXCLUDED.server_privip,
            server_pubkey = EXCLUDED.server_pubkey,
            server_presharedkey = EXCLUDED.server_presharedkey
        """
        params = (
            server["server_id"],
            server["server_name"],
            server["server_pubip"],
            server["server_port"],
            server["server_privip"],
            server["server_pubkey"],
            server["server_presharedkey"]
        )

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()


def upsert_user(user):
    """
    Insert or update a user record.
    user = {
        "user_id": int,
        "username": str,
        "display_name": str,
        "last_seen": datetime,
        "user_pubkey": bytes,
        "invite_history": list[datetime],
        "latest_ip": bytes
    }
    """
    if TEST_MODE:
        # SQLite - convert datetime to string and list to JSON
        query = """
        INSERT OR REPLACE INTO user_info_table (
            user_id, username, display_name, last_seen,
            user_pubkey, invite_history, latest_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        import json
        last_seen_str = user["last_seen"].isoformat() if user["last_seen"] else None
        history_str = json.dumps([h.isoformat() if hasattr(h, 'isoformat') else str(h) for h in user["invite_history"]])
        
        params = (
            user["user_id"],
            user["username"],
            user["display_name"],
            last_seen_str,
            user["user_pubkey"],
            history_str,
            user["latest_ip"]
        )
    else:
        # CockroachDB
        query = """
        UPSERT INTO user_info_table (
            user_id, username, display_name, last_seen,
            user_pubkey, invite_history, latest_ip
        ) VALUES (%s, %s, %s, %s, %s, %s, %s);
        """
        params = (
            user["user_id"],
            user["username"],
            user["display_name"],
            user["last_seen"],
            user["user_pubkey"],
            user["invite_history"],
            user["latest_ip"]
        )
    
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()


def get_all_servers():
    """
    Fetch all servers in the relay server table.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM server_info_table;")
        rows = cur.fetchall()
        
        if TEST_MODE:
            return [dict(row) for row in rows]
        else:
            return [dict(row) for row in rows]


def get_online_users():
    """
    Fetch users whose last_seen is within the past X minutes.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        
        if TEST_MODE:
            # SQLite - use datetime() function
            from datetime import datetime, timedelta
            five_min_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
            cur.execute("""
                SELECT user_id, username, display_name, latest_ip FROM user_info_table
                WHERE last_seen > ?;
            """, (five_min_ago,))
        else:
            # CockroachDB
            cur.execute("""
                SELECT user_id, username, display_name, latest_ip FROM user_info_table
                WHERE last_seen > NOW() - INTERVAL '5 minutes';
            """)
        
        rows = cur.fetchall()
        return [dict(row) for row in rows]


def register_user_session(username, user_ip):
    """Register or update a user's session info"""
    try:
        import ipaddress
        import hashlib
        
        # Convert IP to bytes if it's a string
        if isinstance(user_ip, str):
            ip_bytes = ipaddress.ip_address(user_ip).packed
        else:
            ip_bytes = user_ip
            
        # Generate user_id from username hash
        if TEST_MODE:
            # Smaller ID for SQLite
            user_id = int.from_bytes(hashlib.sha256(username.encode()).digest()[:4], 'big')
        else:
            user_id = int.from_bytes(hashlib.sha256(username.encode()).digest()[:8], 'big')
        
        user_data = {
            "user_id": user_id,
            "username": username,
            "display_name": username,
            "last_seen": datetime.now(),
            "user_pubkey": b'dummy_key',  # Placeholder
            "invite_history": [],
            "latest_ip": ip_bytes
        }
        
        upsert_user(user_data)
        
    except Exception as e:
        logging.error(f"Error registering user session: {e}")


def get_preshared_key():
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT server_presharedkey FROM server_info_table LIMIT 1;")
        result = cur.fetchone()
        if not result:
            # Return a default PSK for testing
            return b"default_psk_32_bytes_long!!!!!!"
        return result[0]  # This is a bytes object
