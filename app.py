# app.py
import sqlite3
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger

# a. create object app
app = Flask(__name__)

# b. konfigurasi CORS dan Swagger
CORS(app)

app.config['SWAGGER'] = {
    'title': 'BELAJAR AUTH API',
    'uiversion': 3,
}

# c. atur path default untuk database
app.config['DB_PATH'] = 'siswa.db'

# d. inisialisasi Swagger
swagger = Swagger(app)

# e. Fungsi inisialisasi database
def init_db(db_path=None):
    if db_path is None:
        db_path = app.config['DB_PATH']
    with sqlite3.connect(db_path) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS tb_user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                token TEXT
            )
        ''')

# f. panggil init_db dengan path dari config
init_db()

# g. Register blueprint (seperti Router di Express)
from routes.auth import auth_bp

app.register_blueprint(auth_bp)

# h. Jalankan aplikasi
if __name__ == '__main__':
    app.run(debug=True)
    # Jika menggunakan Docker: app.run(host='0.0.0.0', port=5000, debug=True)