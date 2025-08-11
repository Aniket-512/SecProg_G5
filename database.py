#!/usr/bin/env python3
"""
Group 5 Database Module  
User information and server data storage
SQLite implementation with CockroachDB support
"""

import psycopg2
import psycopg2.extras
from datetime import datetime
import logging
import sqlite3
import os

# Database configuration per specification
TEST_MODE = True  # Set False for CockroachDB in production

# CockroachDB configuration per specification section 2.1
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

# SQLite fallback database
SQLITE_DB = "guardedim_server.db"

def get_connection():
    """
    Get database connection - CockroachDB or SQLite fallback
    Per specification: "CockroachDB is chosen as the database solution, because it supports 
    distributed storage of the database, resilient to the single point failure"
    """
    global TEST_MODE
    
    if not TEST_MODE:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            logging.info("Connected to CockroachDB (distributed database)")
            return conn
        except Exception as e:
            logging.warning(f"CockroachDB connection failed: {e}, falling back to SQLite")
            TEST_MODE = True
    
    if TEST_MODE:
        conn = sqlite3.connect(SQLITE_DB)
        conn.row_factory = sqlite3.Row
        return conn

def initialize_tables():
    """
    Initialize database tables per specification section 2.1:
    Table 1: server_info_table (Relay Server Table)
    Table 2: user_info_table (User Information Table)
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
            latest_ip       BLOB,
            listen_port     INTEGER DEFAULT 8089
        );
        """
    else:
        # CockroachDB schema per specification
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
            latest_ip       BYTES,
            listen_port     INT DEFAULT 8089
        );
        """

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(create_server_table)
        cur.execute(create_user_table)
        conn.commit()
        logging.info("Database tables initialized per GuardedIM specification")

def upsert_server(server):
    """
    Insert or update server record in server_info_table
    Per specification Table 1: Relay Server Table
    
    server = {
        "server_name": str,
        "server_pubip": bytes,
        "server_port": int,
        "server_privip": bytes,
        "server_pubkey": bytes,
        "server_presharedkey": bytes
    }
    """
    # Generate server_id from private IP hash
    if "server_id" not in server:
        import hashlib
        if TEST_MODE:
            server_id = int.from_bytes(hashlib.sha256(str(server["server_privip"]).encode()).digest()[:4], 'big')
        else:
            server_id = int.from_bytes(hashlib.sha256(str(server["server_privip"]).encode()).digest()[:8], 'big')
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
            str(server["server_pubip"]) if server["server_pubip"] else None,
            server["server_port"],
            str(server["server_privip"]) if server["server_privip"] else None,
            str(server["server_pubkey"]) if server["server_pubkey"] else None,
            str(server["server_presharedkey"]) if server["server_presharedkey"] else None
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

def register_user_session(username, user_ip, listen_port=8090, user_pubkey=None):
    """
    Register or update user session in user_info_table
    Per specification Table 2: User Information Table
    Tracks user presence and latest IP for P2P routing
    """
    try:
        import ipaddress
        import hashlib
        
        # Convert IP to bytes format per specification
        if isinstance(user_ip, str):
            try:
                ip_bytes = ipaddress.ip_address(user_ip).packed
            except:
                ip_bytes = user_ip.encode()
        else:
            ip_bytes = user_ip
            
        # Generate user_id from username hash
        if TEST_MODE:
            user_id = int.from_bytes(hashlib.sha256(username.encode()).digest()[:4], 'big')
        else:
            user_id = int.from_bytes(hashlib.sha256(username.encode()).digest()[:8], 'big')
        
        user_data = {
            "user_id": user_id,
            "username": username,
            "display_name": username,  # Default to username
            "last_seen": datetime.now(),
            "user_pubkey": user_pubkey.encode() if user_pubkey else b'placeholder_key',
            "invite_history": [],
            "latest_ip": ip_bytes,
            "listen_port": listen_port
        }
        
        if TEST_MODE:
            query = """
            INSERT OR REPLACE INTO user_info_table (
                user_id, username, display_name, last_seen,
                user_pubkey, invite_history, latest_ip, listen_port
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                user_data["user_id"],
                user_data["username"],
                user_data["display_name"],
                user_data["last_seen"].isoformat(),
                user_data["user_pubkey"],
                "[]",  # Empty invite history
                user_data["latest_ip"],
                user_data["listen_port"]
            )
        else:
            query = """
            INSERT INTO user_info_table (
                user_id, username, display_name, last_seen,
                user_pubkey, invite_history, latest_ip, listen_port
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                last_seen = EXCLUDED.last_seen,
                user_pubkey = EXCLUDED.user_pubkey,
                invite_history = EXCLUDED.invite_history,
                latest_ip = EXCLUDED.latest_ip,
                listen_port = EXCLUDED.listen_port
            """
            params = (
                user_data["user_id"],
                user_data["username"],
                user_data["display_name"],
                user_data["last_seen"],
                user_data["user_pubkey"],
                user_data["invite_history"],
                user_data["latest_ip"],
                user_data["listen_port"]
            )
        
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            conn.commit()
            
        logging.info(f"Registered user session: {username} at {user_ip}")
        
    except Exception as e:
        logging.error(f"Error registering user session: {e}")

def get_online_users():
    """
    Get list of online users (last seen within 10 minutes for testing)
    Used for user lookup and presence tracking per specification section 3
    """
    with get_connection() as conn:
        cur = conn.cursor()
        
        if TEST_MODE:
            # SQLite version - use 10 minutes for testing
            from datetime import datetime, timedelta
            ten_min_ago = (datetime.now() - timedelta(minutes=10)).isoformat()
            cur.execute("""
                SELECT user_id, username, display_name, latest_ip, listen_port, user_pubkey 
                FROM user_info_table
                WHERE last_seen > ?
            """, (ten_min_ago,))
        else:
            # CockroachDB version
            cur.execute("""
                SELECT user_id, username, display_name, latest_ip, listen_port, user_pubkey 
                FROM user_info_table
                WHERE last_seen > NOW() - INTERVAL '10 minutes'
            """)
        
        rows = cur.fetchall()
        return [dict(row) for row in rows]

def get_all_servers():
    """
    Get all servers from server_info_table
    Per specification: "clients must fetch the latest Relay Server Table from the server"
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM server_info_table")
        rows = cur.fetchall()
        return [dict(row) for row in rows]

def get_preshared_key():
    """
    Get preshared key for WireGuard connections
    Per specification: "We also share a common PSK for extra security"
    """
    with get_connection() as conn:
        cur = conn.cursor()
        
        if TEST_MODE:
            cur.execute("SELECT server_presharedkey FROM server_info_table LIMIT 1")
        else:
            cur.execute("SELECT server_presharedkey FROM server_info_table LIMIT 1")
            
        result = cur.fetchone()
        if not result or not result[0]:
            # Return default PSK for Group 5
            return b"group5_preshared_key_32_bytes_!!"
        return result[0]

# Database initialization on module import
if __name__ == "__main__":
    # Test database functionality
    logging.basicConfig(level=logging.INFO)
    
    print("Testing GuardedIM database module...")
    initialize_tables()
    
    # Test user registration
    register_user_session("test_user", "10.0.5.2")
    
    # Test getting online users
    users = get_online_users()
    print(f"Online users: {len(users)}")
    
    # Test server operations
    servers = get_all_servers()
    print(f"Registered servers: {len(servers)}")
    
    print("[OK] Database module test completed")