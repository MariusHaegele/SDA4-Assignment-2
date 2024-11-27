import sqlite3
from flask import Flask, request, jsonify
import jwt
import datetime
import os

app = Flask(__name__)

SECRET_KEY = "your_secret_key"
DB_PATH = '/data/auth_service.db'

# Ensure the database file exists
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

# Generate token
def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Token verification decorator
def token_required(f):
    def wrapper(*args, **kwargs):
        # Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Token is missing!"}), 401

        # Validate "Bearer" format
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({"message": "Invalid token format!"}), 401

        token = parts[1]  # Extract the token
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401

        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__  # Flask compatibility
    return wrapper

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = generate_token(username)
        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid username or password!"}), 401

# Add new user route
@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required!"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

    return jsonify({"message": f"User {username} added successfully!"}), 201

# Get all users route
@app.route('/users', methods=['GET'])
@token_required
def get_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users')  # Fetch only ID and username
    users = cursor.fetchall()
    conn.close()

    # Format the data as JSON
    return jsonify({"users": [{"id": user[0], "username": user[1]} for user in users]}), 200

# Protected route example
@app.route('/data', methods=['GET'])
@token_required
def get_data():
    return jsonify({"data": "Great. You have access to the secured data, which can only be accessed with a valid token!"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)