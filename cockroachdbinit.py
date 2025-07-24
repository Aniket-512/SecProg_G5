import psycopg2
from psycopg2 import sql, OperationalError

DB_URL = "postgresql://root@localhost:26257/guardedim?sslmode=disable"

def fetch_servers():
    """Fetch and print all servers from server_info_table."""
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("SELECT server_id, server_name, server_port FROM server_info_table")
        rows = cur.fetchall()
        if rows:
            print("\nServers in database:")
            for row in rows:
                print(f"ID: {row[0]}, Name: {row[1]}, Port: {row[2]}")
        else:
            print("No servers found in the database.")
    except OperationalError as e:
        print(f"Error fetching servers: {e}")
    finally:
        cur.close()
        conn.close()
      
if __name__ == "__main__":
    fetch_servers()

##comment
