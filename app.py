from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import sqlite3
from functools import wraps
import os
import subprocess
import pandas as pd
from kaggle.api.kaggle_api_extended import KaggleApi

app = Flask(__name__, static_folder='static')
CORS(app)

app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(minutes=30)
DB_PATH = 'users.db'

import os
import sqlite3
import pandas as pd
from kaggle.api.kaggle_api_extended import KaggleApi

DB_PATH = "cyber_alerts.db"  

# ================= Kaggle Dataset Integration =================
def fetch_kaggle_alerts():
    """Download and return alerts from a Kaggle dataset."""
    dataset_name = "atharvasoundankar/global-cybersecurity-threats-2015-2024"  # Your Kaggle dataset
    download_dir = "kaggle_data"
    os.makedirs(download_dir, exist_ok=True)

    os.environ["KAGGLE_USERNAME"] = "aarohi9a5garwal1"
    os.environ["KAGGLE_KEY"] = "8bb1534bfacd9166aa3568e9c60ff7ea"

    api = KaggleApi()
    api.authenticate()
    api.dataset_download_files(dataset_name, path=download_dir, unzip=True)

    csv_files = [f for f in os.listdir(download_dir) if f.endswith('.csv')]
    if csv_files:
        csv_file = os.path.join(download_dir, csv_files[0])
        df = pd.read_csv(csv_file)
        #matching schema (if columns exist)
        required_cols = ['type', 'message', 'severity', 'timestamp', 'location', 'source']
        df_cols = df.columns.str.lower()
        mapped_cols = {}
        for col in required_cols:
            for df_col in df.columns:
                if df_col.lower() == col:
                    mapped_cols[col] = df_col
                    break
        # Keeping columns that exist in CSV
        df = df[[mapped_cols[c] for c in mapped_cols.keys() if c in mapped_cols]]
        df.columns = mapped_cols.keys() 
        return df.to_dict(orient="records")
    return []

# ================= Database Initialization =================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT, message TEXT, severity TEXT,
                        timestamp TEXT, location TEXT, source TEXT)''')

        # Inserting sample alerts if empty
        cur.execute('SELECT COUNT(*) FROM alerts')
        if cur.fetchone()[0] == 0:
            sample_alerts = [
                ("SQL Injection", "Unusual query pattern detected.", "High", "2025-06-16 14:05", "Checkout Page", "WAF"),
                ("Suspicious Login", "Login from unknown IP address.", "Medium", "2025-06-16 13:30", "Admin Panel", "SIEM"),
                ("Phishing Attempt", "Customer received fake invoice email.", "Low", "2025-06-16 12:50", "Email Gateway", "Spam Filter")
            ]
            cur.executemany("INSERT INTO alerts (type, message, severity, timestamp, location, source) VALUES (?, ?, ?, ?, ?, ?)", sample_alerts)

        # Merging Kaggle dataset alerts
        kaggle_alerts = fetch_kaggle_alerts()
        for alert in kaggle_alerts:
            cur.execute("""SELECT COUNT(*) FROM alerts WHERE 
                           type=? AND message=? AND severity=? AND timestamp=? AND location=? AND source=?""",
                        (alert.get('type',''), alert.get('message',''), alert.get('severity',''),
                         alert.get('timestamp',''), alert.get('location',''), alert.get('source','')))
            if cur.fetchone()[0] == 0:
                cur.execute("INSERT INTO alerts (type, message, severity, timestamp, location, source) VALUES (?, ?, ?, ?, ?, ?)",
                            (alert.get('type',''), alert.get('message',''), alert.get('severity',''),
                             alert.get('timestamp',''), alert.get('location',''), alert.get('source','')))
        conn.commit()

# Initializing and fetching kaggle dataset
init_db()


# ================= JWT Decorator =================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.replace("Bearer ", "")
        else:
            return jsonify({'message': 'Token is missing'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
            user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 403

        return f(current_user, user_role, *args, **kwargs)
    return decorated

# ================= Auth Routes =================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'viewer')

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            conn.commit()
        return jsonify({'message': f'User {username} registered successfully.'})
    except sqlite3.IntegrityError:
        return jsonify({'message': 'User already exists'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT password, role FROM users WHERE username=?", (username,))
        result = cur.fetchone()

        if result and check_password_hash(result[0], password):
            token = jwt.encode({
                'username': username,
                'role': result[1],
                'exp': datetime.datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
            }, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token})
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/user', methods=['GET'])
@token_required
def get_user(current_user, user_role):
    return jsonify({'user': current_user, 'role': user_role})

# ================= Alerts Route =================
@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user, user_role):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT type, message, severity, timestamp, location, source FROM alerts")
        rows = cur.fetchall()
        alerts = [
            {
                'type': r[0],
                'message': r[1],
                'severity': r[2],
                'timestamp': r[3],
                'location': r[4],
                'source': r[5]
            } for r in rows
        ]
    return jsonify(alerts)

# ================= Nmap Scan Route =================
@app.route('/api/scan', methods=['POST'])
@token_required
def scan_network(current_user, user_role):
    data = request.json
    target = data.get("target")
    if not target:
        return jsonify({"message": "Target IP/Domain required"}), 400

    try:
        result = subprocess.check_output(["nmap", "-F", target], universal_newlines=True)
        return jsonify({"scan_result": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"message": "Error running Nmap", "error": str(e)}), 500

# ================= Default & Error Routes =================
@app.route('/')
def serve_home():
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'message': 'Endpoint not found'}), 404

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
