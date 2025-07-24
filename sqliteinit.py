import sqlite3

DB_FILE = 'messages.db'

def insert_sample_message():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    sample_message = (
        "message",
        "Alice",
        "Bob",
        "user",
        "Hi Bob, this is a test message!",
        "text",
        "2025-07-22T20:00:00Z",
        None  # payload_id for file messages
    )

    cur.execute("""
    INSERT INTO messages (
        type, from_user, to_user, to_type,
        payload, payload_type, timestamp, payload_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_message)

    conn.commit()
    conn.close()
    print("Sample message inserted.")

insert_sample_message()
