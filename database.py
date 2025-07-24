import psycopg2
import psycopg2.extras
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",  # or CockroachDB server IP
    "port": 26257,
    "user": "youruser",
    "password": "yourpassword",
    "dbname": "guardedim",
    "sslmode": "disable",  # Use "require" for production with TLS
}


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def initialize_tables():
    """
    Create the server_info_table and user_info_table if they don't exist.
    """
    create_server_table = """
    CREATE TABLE IF NOT EXISTS server_info_table (
        server_id          BIGINT PRIMARY KEY,
        server_name        CHAR(64),
        server_pubip       BYTES(16),
        server_port        INT2,
        server_privip      BYTES(16),
        server_pubkey      BYTES(32),
        server_presharedkey BYTES(32)
    );
    """

    create_user_table = """
    CREATE TABLE IF NOT EXISTS user_info_table (
        user_id         BIGINT PRIMARY KEY,
        username        CHAR(64) UNIQUE,
        display_name    STRING,
        last_seen       TIMESTAMP,
        user_pubkey     BYTES(32),
        invite_history  ARRAY<TIMESTAMP>,
        latest_ip       BYTES(16)
    );
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(create_server_table)
            cur.execute(create_user_table)
        conn.commit()


def insert_or_update_server(server):
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
    query = """
    UPSERT INTO server_info_table (
        server_id, server_name, server_pubip, server_port,
        server_privip, server_pubkey, server_presharedkey
    ) VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (
                server["server_id"],
                server["server_name"],
                server["server_pubip"],
                server["server_port"],
                server["server_privip"],
                server["server_pubkey"],
                server["server_presharedkey"]
            ))
        conn.commit()


def insert_or_update_user(user):
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
    query = """
    UPSERT INTO user_info_table (
        user_id, username, display_name, last_seen,
        user_pubkey, invite_history, latest_ip
    ) VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (
                user["user_id"],
                user["username"],
                user["display_name"],
                user["last_seen"],
                user["user_pubkey"],
                user["invite_history"],
                user["latest_ip"]
            ))
        conn.commit()


def get_all_servers():
    """
    Fetch all servers in the relay server table.
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM server_info_table;")
            return [dict(row) for row in cur.fetchall()]


def get_online_users():
    """
    Fetch users whose last_seen is within the past X minutes.
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT user_id, username, display_name FROM user_info_table
                WHERE last_seen > NOW() - INTERVAL '5 minutes';
            """)
            return [dict(row) for row in cur.fetchall()]
