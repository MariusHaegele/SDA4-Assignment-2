from flask import Flask, request, jsonify
import sqlite3
import os
import base64  # Modul für Base64-Codierung

app = Flask(__name__)
DB_PATH = '/data/username_password_service.db'

# Ensure the database directory exists
if not os.path.exists('/data'):
    os.makedirs('/data')

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Verify username and password
def verify_credentials(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

# Decode Base64 credentials
def decode_credentials(encoded_credentials):
    try:
        decoded_bytes = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_bytes.split(':', 1)
        return username, password
    except (ValueError, base64.binascii.Error):
        return None, None

# Protected data route
@app.route('/data', methods=['GET'])
def get_data():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Basic "):
        return jsonify({"message": "Missing or invalid Authorization header!"}), 401

    # Extract and decode Base64 credentials
    base64_credentials = auth_header.split(" ")[1]
    username, password = decode_credentials(base64_credentials)

    if not username or not password:
        return jsonify({"message": "Invalid credentials format!"}), 401

    if not verify_credentials(username, password):
        return jsonify({"message": "Invalid username or password!"}), 401

    return jsonify({"data": "You have access to this data!"}), 200

# Add new user route
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    # Check if the user already exists
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": f"User {username} already exists!"}), 409

    # Add the new user
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

    return jsonify({"message": f"User {username} added successfully!"}), 201

# Get all users route
@app.route('/users', methods=['GET'])
def get_users():
    # Authentifizierung über Authorization-Header
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Basic "):
        return jsonify({"message": "Missing or invalid Authorization header!"}), 401

    # Base64-Daten decodieren
    base64_credentials = auth_header.split(" ")[1]
    username, password = decode_credentials(base64_credentials)

    if not username or not password:
        return jsonify({"message": "Invalid credentials format!"}), 401

    if not verify_credentials(username, password):
        return jsonify({"message": "Invalid username or password!"}), 401

    # Benutzer abrufen
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users')
    users = cursor.fetchall()
    conn.close()

    # Benutzer als JSON zurückgeben
    return jsonify({"users": [user[0] for user in users]}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)