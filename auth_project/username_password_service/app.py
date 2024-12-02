from flask import Flask, request, jsonify
import sqlite3
import os
import base64
import bcrypt  # Für sicheres Passwort-Hashing

app = Flask(__name__)
DB_PATH = '/data/username_password_service.db'

# Sicherstellen, dass der Datenbankordner existiert
if not os.path.exists('/data'):
    os.makedirs('/data')

# Initialisierung der SQLite-Datenbank
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Verifizierung von Benutzername und Passwort
def verify_credentials(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Hash mit eingegebenem Passwort vergleichen
        stored_password = user[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            return True
    return False

# Decodieren von Base64-Anmeldedaten
def decode_credentials(encoded_credentials):
    try:
        decoded_bytes = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_bytes.split(':', 1)
        return username, password
    except (ValueError, base64.binascii.Error):
        return None, None

# Prüfen, ob der Benutzer ein Administrator ist
def is_admin(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user[0] == "admin":
        return True
    return False

# Gesicherte Route für den Zugriff auf Daten
@app.route('/data', methods=['GET'])
def get_data():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Basic "):
        return jsonify({"message": "Missing or invalid Authorization header!"}), 401

    base64_credentials = auth_header.split(" ")[1]
    username, password = decode_credentials(base64_credentials)

    if not username or not password:
        return jsonify({"message": "Invalid credentials format!"}), 401

    if not verify_credentials(username, password):
        return jsonify({"message": "Invalid username or password!"}), 401

    return jsonify({"data": "You have access to this data!"}), 200

# Route zum Hinzufügen eines Benutzers
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Standardmäßig 'user'

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": f"User {username} already exists!"}), 409

    cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password.decode('utf-8'), role))
    conn.commit()
    conn.close()

    return jsonify({"message": f"User {username} added successfully with role {role}!"}), 201

# Route zum Abrufen aller Benutzer (nur für Admins)
@app.route('/users', methods=['GET'])
def get_users():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Basic "):
        return jsonify({"message": "Missing or invalid Authorization header!"}), 401

    base64_credentials = auth_header.split(" ")[1]
    username, password = decode_credentials(base64_credentials)

    if not username or not password:
        return jsonify({"message": "Invalid credentials format!"}), 401

    if not verify_credentials(username, password):
        return jsonify({"message": "Invalid username or password!"}), 401

    if not is_admin(username):
        return jsonify({"message": "Access denied! Admins only."}), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT username, role FROM users')
    users = cursor.fetchall()
    conn.close()

    user_list = [{"username": user[0], "role": user[1]} for user in users]
    return jsonify({"users": user_list}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081)