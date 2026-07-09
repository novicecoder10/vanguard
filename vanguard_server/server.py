from flask import Flask, request, jsonify, render_template
import sqlite3
import os
import datetime

app = Flask(__name__)
DB_PATH = "central_logs.db"

def init_server_db():
    """Initializes the central server database for log aggregation."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Logs table (with agent_id to identify which endpoint sent it)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            image_path TEXT,
            pid TEXT,
            timestamp TEXT,
            received_at TEXT
        )
    """)
    
    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            timestamp TEXT,
            type TEXT,
            description TEXT,
            score INTEGER,
            received_at TEXT
        )
    """)
    
    conn.commit()
    conn.close()

@app.route('/')
def dashboard():
    """Renders the central monitoring web dashboard."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Fetch consolidated stats
    cursor.execute("SELECT COUNT(distinct agent_id) as total_agents FROM endpoint_logs")
    total_agents = cursor.fetchone()['total_agents']
    
    cursor.execute("SELECT COUNT(*) as total_logs FROM endpoint_logs")
    total_logs = cursor.fetchone()['total_logs']
    
    cursor.execute("SELECT COUNT(*) as total_alerts FROM endpoint_alerts")
    total_alerts = cursor.fetchone()['total_alerts']
    
    # Fetch recent logs
    cursor.execute("SELECT agent_id, image_path, pid, timestamp FROM endpoint_logs ORDER BY id DESC LIMIT 50")
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Fetch recent alerts
    cursor.execute("SELECT agent_id, timestamp, type, description, score FROM endpoint_alerts ORDER BY id DESC LIMIT 30")
    alerts = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template(
        'index.html',
        total_agents=total_agents or 0,
        total_logs=total_logs or 0,
        total_alerts=total_alerts or 0,
        logs=logs,
        alerts=alerts
    )

@app.route('/api/logs', methods=['POST'])
def receive_logs():
    """API endpoint for agents to push system logs."""
    data = request.get_json()
    if not data or 'agent_id' not in data or 'logs' not in data:
        return jsonify({"status": "error", "message": "Invalid request payload"}), 400
        
    agent_id = data['agent_id']
    logs_list = data['logs']
    received_at = datetime.datetime.now().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        for log in logs_list:
            cursor.execute(
                "INSERT INTO endpoint_logs (agent_id, image_path, pid, timestamp, received_at) VALUES (?, ?, ?, ?, ?)",
                (agent_id, log.get('return_image'), log.get('return_id'), log.get('return_date_time'), received_at)
            )
        conn.commit()
        return jsonify({"status": "success", "message": f"Processed {len(logs_list)} logs"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/alerts', methods=['POST'])
def receive_alerts():
    """API endpoint for agents to push threat alerts."""
    data = request.get_json()
    if not data or 'agent_id' not in data or 'alerts' not in data:
        return jsonify({"status": "error", "message": "Invalid request payload"}), 400
        
    agent_id = data['agent_id']
    alerts_list = data['alerts']
    received_at = datetime.datetime.now().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        for alert in alerts_list:
            cursor.execute(
                "INSERT INTO endpoint_alerts (agent_id, timestamp, type, description, score, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, alert.get('timestamp'), alert.get('type'), alert.get('description'), alert.get('score'), received_at)
            )
        conn.commit()
        return jsonify({"status": "success", "message": f"Processed {len(alerts_list)} alerts"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_server_db()
    # Run server on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
