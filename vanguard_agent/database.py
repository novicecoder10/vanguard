import sqlite3
import os

DB_NAME = "vanguard_logs.db"

def get_db_connection(db_path=DB_NAME):
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=DB_NAME):
    """Initializes the database and creates the necessary tables."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Create the logindexer table (matching the original MySQL schema)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logindexer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_image TEXT,
            return_id TEXT,
            return_date_time TEXT
        )
    """)
    
    # Create a table for alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            description TEXT,
            score INTEGER
        )
    """)
    
    conn.commit()
    conn.close()

def insert_log(image_path, process_id, timestamp, db_path=DB_NAME):
    """Inserts a sysmon event log into the logindexer table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO logindexer (return_image, return_id, return_date_time) VALUES (?, ?, ?)",
            (image_path, str(process_id), timestamp)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def insert_alert(alert_type, description, score, timestamp, db_path=DB_NAME):
    """Inserts a triggered alert into the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO alerts (timestamp, type, description, score) VALUES (?, ?, ?, ?)",
            (timestamp, alert_type, description, score)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def fetch_recent_logs(limit=100, db_path=DB_NAME):
    """Fetches the most recent logs from the logindexer table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, return_image, return_id, return_date_time FROM logindexer ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def fetch_recent_alerts(limit=50, db_path=DB_NAME):
    """Fetches the most recent alerts."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, type, description, score FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def clear_all_data(db_path=DB_NAME):
    """Clears both logs and alerts tables."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logindexer")
    cursor.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
