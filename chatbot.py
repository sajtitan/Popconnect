import sqlite3
import re
import os
import requests
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from datetime import datetime
from functools import wraps
from collections import defaultdict
import time
import mimetypes
import hashlib
from flask_cors import CORS

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = "my-secure-key-123"  # Secure key for session management
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Enable CORS for requests from http://localhost:8000
CORS(app, origins=["http://localhost:8000"],
     supports_credentials=True,
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Cookie"])

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "attacks.db")

# Ensure the directory exists
os.makedirs(BASE_DIR, exist_ok=True)

# VirusTotal API key
VT_API_KEY = "fdc4b43d9a29913efe5b8fabbef445bf6d2a59938ffff81beecba334901f634e"

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

# Brute force detection settings
REQUEST_LIMIT = 10  # Max requests allowed in the time window
TIME_WINDOW = 60  # Time window in seconds (1 minute)
BLOCK_DURATION = 300  # Block duration in seconds (5 minutes)

# Track requests for brute force detection
request_counts = defaultdict(list)
blocked_ips = defaultdict(float)  # IP -> time when block expires

# DDoS detection settings
DDOS_THRESHOLD = 10  # Lowered for testing
DDOS_WINDOW_SECONDS = 60  # Time window in seconds (1 minute)
request_tracker_ddos = defaultdict(list)  # Track requests for DDoS detection

# SQL Injection blocking settings
sql_blocked_ips = defaultdict(float)  # IP -> time when block expires
SQL_BLOCK_DURATION = 24 * 60 * 60  # 24 hours in seconds


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            print(f"Session in login_required: {session}")
            if 'logged_in' not in session or not session['logged_in']:
                print("User not logged in, redirecting to login")
                return redirect(url_for('serve_login'))
            print("User is logged in, proceeding with request")
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Error in login_required decorator: {str(e)}")
            return jsonify({"status": "error", "message": f"Authentication error: {str(e)}"}), 500

    return decorated_function


# Serve static files
@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/login.html')
def serve_login():
    return send_from_directory(BASE_DIR, 'login.html')


@app.route('/chatbot.html')
@login_required
def serve_chatbot():
    return send_from_directory(BASE_DIR, 'chatbot.html')


# Login and logout endpoints
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get("username", "")
        password = data.get("password", "")

        print(f"Login attempt: username={username}, password={password}")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            print(f"Login successful, session: {session}")
            return jsonify({"status": "success", "message": "Logged in successfully"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid username or password"}), 401
    except Exception as e:
        print(f"Error in /login endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.pop('logged_in', None)
        print(f"Logout successful, session: {session}")
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"Error in /logout endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Initialize database
def init_db():
    conn = None
    try:
        print("Initializing database...")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DROP TABLE IF EXISTS attacks")
        conn.execute("""
            CREATE TABLE attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                source_ip TEXT,
                timestamp TEXT,
                details TEXT
            )
        """)
        conn.commit()
        print("Database initialized successfully")
    except sqlite3.Error as e:
        print(f"Error initializing database: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()


# Brute force detection middleware (skip for /traffic)
@app.before_request
def detect_brute_force():
    if request.path == '/traffic':  # Exempt /traffic from brute-force detection
        return None
    source_ip = request.remote_addr
    current_time = time.time()

    # Check if IP is blocked
    if source_ip in blocked_ips:
        if current_time < blocked_ips[source_ip]:
            return jsonify(
                {"status": "error", "message": "IP blocked due to excessive requests. Try again later."}), 429
        else:
            # Unblock the IP if the block duration has expired
            del blocked_ips[source_ip]
            request_counts[source_ip] = []

    # Update request counts
    request_counts[source_ip].append(current_time)
    # Remove requests older than the time window
    request_counts[source_ip] = [t for t in request_counts[source_ip] if current_time - t < TIME_WINDOW]

    # Check for brute force behavior
    if len(request_counts[source_ip]) > REQUEST_LIMIT:
        # Log the brute force attempt
        attack_type = "Brute Force Attack"
        details = f"Detected {len(request_counts[source_ip])} requests in {TIME_WINDOW} seconds"
        log_attack(attack_type, source_ip, details)

        # Block the IP
        blocked_ips[source_ip] = current_time + BLOCK_DURATION
        print(f"Blocked IP {source_ip} for {BLOCK_DURATION} seconds due to brute force attempt")

        return jsonify({"status": "error", "message": "Too many requests. Your IP has been temporarily blocked."}), 429


# DDoS detection function
def detect_ddos(source_ip):
    current_time = time.time()
    request_tracker_ddos[source_ip].append(current_time)
    # Remove requests older than the time window
    request_tracker_ddos[source_ip] = [t for t in request_tracker_ddos[source_ip] if
                                       current_time - t < DDOS_WINDOW_SECONDS]
    # Check if the request rate exceeds the threshold
    request_count = len(request_tracker_ddos[source_ip])
    print(
        f"DDoS Detection - IP: {source_ip}, Request Count: {request_count}, Window: {DDOS_WINDOW_SECONDS} seconds")  # Debug log
    if request_count > DDOS_THRESHOLD:
        print(f"DDoS Threshold Exceeded - IP: {source_ip}, Request Count: {request_count}")  # Debug log
        return True, f"Request rate: {request_count} requests in {DDOS_WINDOW_SECONDS} seconds"
    return False, None


# Malware detection
def detect_malware(request_data=None, file_content=None, filename=None):
    if request_data:
        request_data = request_data.lower()
        sql_patterns = [
            r"union.*select", r"--", r"or\s+1\s*=\s*1", r";\s*drop",
            r"'\s*or\s*''='", r"select.*from"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, request_data):
                print(f"SQL Injection detected: Pattern '{pattern}' matched in '{request_data}'")
                return "SQL Injection", None

    if file_content is not None:
        if not file_content:
            return "Invalid File", f"File {filename} is empty"

        if filename:
            mime_type, _ = mimetypes.guess_type(filename)
            file_type = mime_type if mime_type else "Unknown (mimetypes could not determine type)"
        else:
            file_type = "Unknown (no filename provided)"

        file_hash = hashlib.md5(file_content).hexdigest()

        vt_url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": VT_API_KEY,
            "resource": file_hash
        }
        try:
            response = requests.get(vt_url, params=params)
            response.raise_for_status()
            vt_result = response.json()

            if vt_result.get("response_code") == 1:
                positives = vt_result.get("positives", 0)
                total = vt_result.get("total", 0)
                if positives > 0:
                    return "Malware", f"VirusTotal detected {positives}/{total} positives for {filename} (Type: {file_type}, Hash: {file_hash})"
                else:
                    return None, f"File {filename} scanned by VirusTotal (Type: {file_type}, Hash: {file_hash}) - No threats detected"
            else:
                print(f"File {file_hash} not found in VirusTotal, falling back to local checks")
        except requests.RequestException as e:
            print(f"Error querying VirusTotal: {str(e)}")

        safe_file_types = [
            "text/plain",
            "image/png",
            "image/jpeg",
            "image/gif",
            "application/pdf",
        ]
        if file_type in safe_file_types:
            return None, f"File {filename} scanned (Type: {file_type}, Hash: {file_hash}) - Whitelisted as safe"

        malicious_signatures = [
            b'\xE8\x00\x00\x00\x00',
            b'\x90\x90\x90\x90\x90',
        ]
        for sig in malicious_signatures:
            if sig in file_content:
                return "Malware", f"Detected malicious signature in {filename} (Type: {file_type}, Hash: {file_hash})"

        suspicious_extensions = [".exe", ".bat", ".cmd", ".vbs", ".js"]
        if filename and any(filename.lower().endswith(ext) for ext in suspicious_extensions):
            return "Malware", f"Detected potentially malicious file extension in {filename} (Type: {file_type}, Hash: {file_hash})"

        return None, f"File {filename} scanned (Type: {file_type}, Hash: {file_hash})"

    return None, None


# Log attack or scan result
def log_attack(attack_type, source_ip, details=None):
    conn = None
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(DB_PATH)
        print(f"Logging attack: {attack_type} from {source_ip} at {timestamp} - {details}")
        conn.execute("INSERT INTO attacks (attack_type, source_ip, timestamp, details) VALUES (?, ?, ?, ?)",
                     (attack_type, source_ip, timestamp, details))
        conn.commit()
        print("Attack logged successfully")
    except sqlite3.Error as e:
        print(f"Database error in log_attack: {str(e)}")
    finally:
        if conn:
            conn.close()


# Generate report
def generate_report():
    conn = None
    try:
        print("Connecting to attacks.db...")
        conn = sqlite3.connect(DB_PATH)
        print("Executing query on attacks table...")
        attacks = conn.execute("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 5").fetchall()
        print(f"Fetched {len(attacks)} attacks: {attacks}")
        return [{"id": a[0], "type": a[1], "ip": a[2], "time": a[3], "details": a[4]} for a in
                attacks] if attacks else []
    except sqlite3.Error as e:
        print(f"SQLite error in generate_report: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in generate_report: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


@app.route('/analyze', methods=['POST'])
def analyze_request():
    try:
        data = request.json
        source_ip = data.get("source_ip", request.remote_addr)
        print(f"Received request from {source_ip}")

        # Check if IP is blocked due to previous SQL injection attempts
        current_time = time.time()
        if source_ip in sql_blocked_ips and current_time < sql_blocked_ips[source_ip]:
            return jsonify({
                "status": "blocked",
                "message": "Your IP is blocked for 24 hours due to a previous malicious input."
            }), 403

        # Check for DDoS
        is_ddos, ddos_details = detect_ddos(source_ip)
        if is_ddos:
            print(f"DDoS Attack Detected - Logging: {ddos_details}")
            log_attack("DDoS Attack", source_ip, ddos_details)
            return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200

        request_data = data.get("request_data", "")
        print(f"Received request from {source_ip} with data: {request_data}")

        # Check for SQL Injection and block if detected
        attack_type, details = detect_malware(request_data=request_data)
        if attack_type == "SQL Injection":
            log_attack(attack_type, source_ip, details)
            # Block the IP for 24 hours
            sql_blocked_ips[source_ip] = current_time + SQL_BLOCK_DURATION
            print(f"Blocked IP {source_ip} for {SQL_BLOCK_DURATION} seconds due to SQL injection")
            return jsonify({
                "status": "blocked",
                "type": attack_type,
                "message": "Malicious input, IP blocked for 24 hours."
            }), 403  # Forbidden status

        # If no attack, proceed as normal
        if attack_type:
            log_attack(attack_type, source_ip, details)
            return jsonify({"status": "attack_detected", "type": attack_type, "details": details}), 200
        return jsonify({"status": "clean"}), 200
    except Exception as e:
        print(f"Error in /analyze endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Upload endpoint
@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        source_ip = request.remote_addr
        print(f"Received /upload request from {source_ip}")

        # Check for DDoS
        is_ddos, ddos_details = detect_ddos(source_ip)
        if is_ddos:
            log_attack("DDoS Attack", source_ip, ddos_details)
            return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200

        if 'file' not in request.files:
            print("No file in request.files")
            return jsonify({"status": "error", "message": "No file uploaded"}), 400
        file = request.files['file']
        print(f"Processing file: {file.filename}")
        file_content = file.read()
        filename = file.filename

        print("Calling detect_malware...")
        attack_type, details = detect_malware(file_content=file_content, filename=filename)
        print(f"detect_malware result: attack_type={attack_type}, details={details}")

        # Block upload if malware is detected
        if attack_type == "Malware":
            log_attack(attack_type, source_ip, details)
            return jsonify({
                "status": "blocked",
                "type": attack_type,
                "message": "Malicious file detected, unable to upload."
            }), 403  # Forbidden status, file not processed further

        # If no attack, log as clean and proceed
        print("Logging clean scan...")
        log_attack("File Scan", source_ip, details)
        return jsonify({"status": "clean", "details": details}), 200
    except Exception as e:
        print(f"Error in /upload endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Report endpoint
@app.route('/report', methods=['GET'])
@login_required
def get_report():
    try:
        print("Fetching report...")
        report = generate_report()
        response = jsonify({"attacks": report})
        print(f"Response headers for /report: {response.headers}")
        return response, 200
    except Exception as e:
        print(f"Critical error in /report endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Debug endpoint to confirm server is running
@app.route('/debug', methods=['GET'])
def debug():
    return jsonify({"status": "success", "message": "Flask server is running"}), 200


# Endpoint for JMeter traffic with DDoS detection
@app.route('/traffic', methods=['GET'])
def log_traffic():
    source_ip = request.remote_addr
    print(f"Traffic received from {source_ip}")
    is_ddos, ddos_details = detect_ddos(source_ip)
    if is_ddos:
        log_attack("DDoS Attack", source_ip, ddos_details)
        return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200
    return jsonify({"status": "clean"}), 200


# Endpoint to get blocked IPs
@app.route('/blocked-ips', methods=['GET'])
@login_required
def get_blocked_ips():
    try:
        current_time = time.time()
        print(f"Checking blocked IPs at {current_time}")
        # Combine blocked_ips and sql_blocked_ips into a single response
        blocked = [
                      {"ip": ip, "reason": "Brute Force", "expires": expires}
                      for ip, expires in blocked_ips.items() if expires > current_time
                  ] + [
                      {"ip": ip, "reason": "SQL Injection", "expires": expires}
                      for ip, expires in sql_blocked_ips.items() if expires > current_time
                  ]
        print(f"Returning blocked IPs: {blocked}")
        return jsonify({"status": "success", "blocked_ips": blocked}), 200
    except Exception as e:
        print(f"Error in /blocked-ips endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Endpoint to unblock an IP
@app.route('/unblock-ip', methods=['POST'])
@login_required
def unblock_ip():
    try:
        data = request.json
        ip_to_unblock = data.get("ip")
        if not ip_to_unblock:
            return jsonify({"status": "error", "message": "No IP provided"}), 400

        current_time = time.time()
        if ip_to_unblock in blocked_ips and blocked_ips[ip_to_unblock] > current_time:
            del blocked_ips[ip_to_unblock]
            request_counts[ip_to_unblock] = []  # Reset request counts
            print(f"Unblocked IP {ip_to_unblock} from brute force block")
        if ip_to_unblock in sql_blocked_ips and sql_blocked_ips[ip_to_unblock] > current_time:
            del sql_blocked_ips[ip_to_unblock]
            print(f"Unblocked IP {ip_to_unblock} from SQL injection block")

        return jsonify({"status": "success", "message": f"IP {ip_to_unblock} unblocked"}), 200
    except Exception as e:
        print(f"Error in /unblock-ip endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


# Temporary: Simulate blocked IPs for testing (remove after testing)
current_time = time.time()
blocked_ips["192.168.1.100"] = current_time + 3600  # Blocked for 1 hour (Brute Force)
blocked_ips["10.0.0.50"] = current_time + 3600  # Blocked for 1 hour (Brute Force)
sql_blocked_ips["172.16.0.10"] = current_time + 86400  # Blocked for 24 hours (SQL Injection)

print("Simulated blocked IPs for testing:")
print(f"blocked_ips: {blocked_ips}")
print(f"sql_blocked_ips: {sql_blocked_ips}")

if __name__ == "__main__":
    # Ensure the database is initialized
    if not os.path.exists(DB_PATH):
        print(f"Database file {DB_PATH} does not exist. Initializing database...")
        init_db()
    else:
        print(f"Database file {DB_PATH} exists. Proceeding...")
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule.rule} ({', '.join(rule.methods)})")
    app.run(host="0.0.0.0", port=5001)