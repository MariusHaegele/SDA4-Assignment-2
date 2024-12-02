from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime
import os
import bcrypt

app = Flask(__name__)
SECRET_KEY = "your_secret_key"
DB_PATH = '/data/auth_service.db'

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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Token-Generierung
def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Token-Verifizierungs-Decorator
def token_required(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Token is missing!"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({"message": "Invalid token format!"}), 401

        token = parts[1]

        # Überprüfen, ob das Token widerrufen wurde
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM revoked_tokens WHERE token = ?", (token,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"message": "Token has been revoked!"}), 401
        conn.close()

        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401

        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# Rollenprüfung
def is_admin(token):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = decoded_token["username"]

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and user[0] == "admin":
            return True
        return False
    except jwt.InvalidTokenError:
        return False

# Benutzerregistrierung
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

# Benutzer-Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        token = generate_token(username)
        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid username or password!"}), 401

# Route zum Widerrufen eines Tokens
@app.route('/revoke_token', methods=['POST'])
@token_required
def revoke_token():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split()[1]

    # Token zur Widerrufsliste hinzufügen
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO revoked_tokens (token) VALUES (?)", (token,))
    conn.commit()
    conn.close()

    return jsonify({"message": "Token has been revoked!"}), 200

# Geschützte Route, die Benutzer und Rollen anzeigt
@app.route('/users', methods=['GET'])
@token_required
def get_users():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split()[1]

    if not is_admin(token):
        return jsonify({"message": "Access denied! Admins only."}), 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT username, role FROM users')
    users = cursor.fetchall()
    conn.close()

    user_list = [{"username": user[0], "role": user[1]} for user in users]
    return jsonify({"users": user_list}), 200

# Geschützte Datenroute
@app.route('/data', methods=['GET'])
@token_required
def get_data():
    return jsonify({"data": "You have access to secured data!"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)