# routes/auth.py ######################################################
import uuid
from flask import Blueprint, request, jsonify, current_app
from flasgger.utils import swag_from
import hashlib
import sqlite3
from utils.db import get_db

auth_bp = Blueprint('auth', __name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#- REGISTER
@auth_bp.route('/register', methods=['POST'])
@swag_from('../docs/auth/register.yml')
def register():
    data = request.get_json()

    # Validasi input
    username = data.get('username') if data else None
    password = data.get('password') if data else None

    if not username or not password:
        return jsonify({"error": "Field 'username' dan 'password' wajib diisi"}), 400

    password_hashed = hash_password(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO tb_user (username, password) VALUES (?, ?)",
                (username, password_hashed)
            )
        return jsonify({"message": "Registrasi berhasil"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username sudah digunakan"}), 409
    except Exception as e:
        return jsonify({"error": f"Gagal mendaftar: {str(e)}"}), 500

#- LOGIN
@auth_bp.route('/login', methods=['POST'])
@swag_from('../docs/auth/login.yml')
def login():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
      return jsonify({'error': 'Field "username" dan "password" wajib diisi'}), 400

    username = data.get('username')
    password = hash_password(data.get('password'))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM tb_user WHERE username = ? AND password = ?", (username, password)).fetchone()
        if user:
            token = str(uuid.uuid4())
            conn.execute("UPDATE tb_user SET token = ? WHERE username = ?", (token, username))
            return jsonify({"message": "Login berhasil", "token": token}), 200
        return jsonify({"error": "Username atau password salah"}), 401

#- LOGOUT
@auth_bp.route('/logout', methods=['POST'])
@swag_from('../docs/auth/logout.yml')
def logout():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token tidak ditemukan"}), 401

    with get_db() as conn:
        cur = conn.execute("UPDATE tb_user SET token = NULL WHERE token = ?", (token,))
        if cur.rowcount:
            return jsonify({"message": "Logout berhasil"}), 200
        return jsonify({"error": "Token tidak valid"}), 401