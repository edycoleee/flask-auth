#utils/db.py
import sqlite3
from flask import current_app

def get_db():
    return sqlite3.connect(current_app.config['DB_PATH'], check_same_thread=False)
