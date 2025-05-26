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
    'specs_route': '/apidocs/',# <-- penting reverse proxy
    'static_url_path': '/apidocs/flasgger_static',  # <-- penting reverse proxy
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
}

# c. atur path default untuk database
# app.config['DB_PATH'] = 'siswa.db'

# pastikan direktori ada dan writable
os.makedirs("instance", exist_ok=True)
app.config['DB_PATH'] = 'instance/siswa.db'

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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS tb_siswa (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nama TEXT NOT NULL,
                alamat TEXT NOT NULL
            )
        ''')

# f. panggil init_db dengan path dari config
init_db()

# g. Register blueprint (seperti Router di Express)
from routes.auth import auth_bp
from routes.siswa import siswa_bp

app.register_blueprint(auth_bp)
app.register_blueprint(siswa_bp)

# h. Jalankan aplikasi
if __name__ == '__main__':
    # app.run(debug=True)
    # Jika menggunakan Docker: 
    app.run(host='0.0.0.0', port=5000, debug=True)