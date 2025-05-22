#middleware/auth_middleware.py
from functools import wraps
from flask import request, jsonify
import sqlite3
from utils.db import get_db

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token diperlukan'}), 401
        with get_db() as conn:
            user = conn.execute("SELECT * FROM tb_user WHERE token = ?", (token,)).fetchone()
            if not user:
                return jsonify({'error': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated