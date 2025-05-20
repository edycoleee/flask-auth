# routes/auth.py ######################################################
from flask import Blueprint, request, jsonify, current_app
from flasgger.utils import swag_from
import hashlib
import sqlite3
from utils.db import get_db

auth_bp = Blueprint('auth', __name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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