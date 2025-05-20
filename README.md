### BELAJAR FLASK MAHIR 2

1. MEMBUAT API AUTH >> REGISTER, LOGIN, LOGOUT >> MIDDLEWARE UTK DECORATOR API DENGAN TOKEN >> MENGGUNAKAN SQLITE 2 DB UNTUK PRODUCTION DAN TESTING
2. DEPLOY KE DOCKER
3. MENGGUNAKAN SQLITE 2 DB UNTUK PRODUCTION DAN TESTING
4. MENGGUNAKAN POSTGRE 2 DB UNTUK PRODUCTION DAN TESTING

### GITHUB

## API AUTH SPESIFICATION

## 1. PERSIAPAN

```py
#project-folder/
#│
#├── app.py
#└── test_app.py

# 1. Membuat Virtual Environtment
python -m venv venv
source venv/bin/activate  #Linux / Macbook
venv\Scripts\activate # Windows

#2. Install Flask
pip install flask pytest flask_cors flasgger

#3. app.py
# import >> create object >> route >> funtion return response >> run
#a. import Flask
from flask import Flask, jsonify
#b. create object app
app = Flask(__name__)
#c. create route, method
#### GET, /halo, request:-, response:{ "message": "Belajar Flask" }
@app.route('/halo', methods=['GET'])
#d. create fungction with return as response
def halo():
    return jsonify({"message": "Belajar Flask"})
#e. runc object default/host,port
if __name__ == '__main__':
    app.run(debug=True)
#Jika dengan docker : app.run(host='0.0.0.0', port=5000, debug=True)

#4. Jalankan
python app.py

#5. Coba Di browser / Postman
http://127.0.0.1:5000/halo

{
    "message": "Belajar Flask"
}


#6. test_app.py
# import >> client >> function test >> assert response
import pytest
from app import app  # Import aplikasi Flask dari file app.py

@pytest.fixture
def client():
    # Setup Flask test client
    with app.test_client() as client:
        yield client

#### GET, /halo, request:-, response:{ "message": "Belajar Flask" }
def test_hallo_endpoint(client):
    # Kirim request GET ke endpoint /hallo
    response = client.get('/halo')
    # Pastikan status kode adalah 200
    assert response.status_code == 200
    # Pastikan respon JSON sesuai
    assert response.get_json() == {"message": "Belajar Flask"}

#7. Jalankan Test
pytest
```

## 2. DATABASE PROD DAN TEST >> API REGISTER

| No  | Method | URL       | Request JSON                                     | Response JSON (Berhasil)                              | Response JSON (Gagal)                                     |
| --- | ------ | --------- | ------------------------------------------------ | ----------------------------------------------------- | --------------------------------------------------------- |
| 1   | POST   | /register | `{ "username": "user1", "password": "pass123" }` | `201 Created`: `{ "message": "Registrasi berhasil" }` | `409 Conflict`: `{ "error": "Username sudah digunakan" }` |
| 2   | POST   | /register | `{ "username": "" }`                             |

```
project/
├── app.py
├── routes/
│   └── auth.py
├── utils/
│   └── db.py
├── test/
│   └── test_auth.py
└── docs/
    └── auth/
        └── register.yml
```

```yml
##docs/auth/register.yml ######################################################
tags:
  - Auth
summary: Registrasi akun baru
description: Endpoint untuk mendaftarkan akun pengguna baru.
consumes:
  - application/json
produces:
  - application/json
parameters:
  - in: body
    name: body
    required: true
    description: Data user baru
    schema:
      type: object
      required:
        - username
        - password
      properties:
        username:
          type: string
          example: johndoe
        password:
          type: string
          example: rahasia123
responses:
  201:
    description: Registrasi berhasil
    schema:
      type: object
      properties:
        message:
          type: string
          example: Registrasi berhasil
```

```PY
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

    return jsonify({"message": "Registrasi berhasil"}), 201

# app.py ######################################################
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
    'uiversion': 3
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

#utils/db.py ######################################################
import sqlite3
from flask import current_app

def get_db():
    return sqlite3.connect(current_app.config['DB_PATH'])

#test/test_auth.py ######################################################
import os
import pytest
from app import app, init_db

# Simpan token global
TOKEN = None

@pytest.fixture(scope='module')
def client():
    test_db_path = 'test_db.sqlite'
    app.config['TESTING'] = True
    app.config['DB_PATH'] = test_db_path

    # Inisialisasi database test
    init_db(test_db_path)

    with app.test_client() as client:
        yield client

    # Bersihkan database setelah testing
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


def test_register_success(client):
    response = client.post('/register', json={
        "username": "testuser",
        "password": "testpass"
    })
    assert response.status_code == 201
    assert response.get_json()["message"] == "Registrasi berhasil"

def test_register_missing_fields(client):
    response = client.post('/register', json={})
    assert response.status_code == 400
    assert "wajib diisi" in response.get_json()["error"]

##JALANKAN TEST ######################################################
# tambah file __init__.py pada folder test ****************************
pytest
```

## 3. REGISTER

| No  | Method | URL       | Request JSON                                     | Response JSON (Berhasil)                              | Response JSON (Gagal)                                                                                        |
| --- | ------ | --------- | ------------------------------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1   | POST   | /register | `{ "username": "user1", "password": "pass123" }` | `201 Created`: `{ "message": "Registrasi berhasil" }` | `409 Conflict`: `{ "error": "Username sudah digunakan" }`                                                    |
| 2   | POST   | /register | `{ "username": "" }`                             | —                                                     | `400 Bad Request`: `{ "error": "Field 'username' dan 'password' wajib diisi" }`                              |
| 3   | POST   | /register | `{ "password": "abc123" }`                       | —                                                     | `400 Bad Request`: `{ "error": "Field 'username' dan 'password' wajib diisi" }`                              |
| 4   | POST   | /register | `{}`                                             | —                                                     | `400 Bad Request`: `{ "error": "Field 'username' dan 'password' wajib diisi" }`                              |
| 5   | POST   | /register | invalid JSON (e.g., plain text)                  | —                                                     | `400 Bad Request`: `{ "error": "Field 'username' dan 'password' wajib diisi" }` _(jika tidak bisa di-parse)_ |
| 6   | POST   | /register | valid JSON tapi error server (jarang terjadi)    | —                                                     | `500 Internal Server Error`: `{ "error": "Gagal mendaftar: <pesan error>" }`                                 |

SQL QUERY

conn.execute( "INSERT INTO tb_user (username, password) VALUES (?, ?)", (username, password_hashed))

```yml
##docs/auth/register.yml ######################################################
tags:
  - Auth
summary: Registrasi akun baru
description: Endpoint untuk mendaftarkan akun pengguna baru.
consumes:
  - application/json
produces:
  - application/json
parameters:
  - in: body
    name: body
    required: true
    description: Data user baru
    schema:
      type: object
      required:
        - username
        - password
      properties:
        username:
          type: string
          example: johndoe
        password:
          type: string
          example: rahasia123
responses:
  201:
    description: Registrasi berhasil
    schema:
      type: object
      properties:
        message:
          type: string
          example: Registrasi berhasil
  400:
    description: Input tidak lengkap
    schema:
      type: object
      properties:
        error:
          type: string
          example: Field 'username' dan 'password' wajib diisi
  409:
    description: Username sudah digunakan
    schema:
      type: object
      properties:
        error:
          type: string
          example: Username sudah digunakan
```

```py
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
    'uiversion': 3
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

# utils/db.py ######################################################
import sqlite3
from flask import current_app

def get_db():
    return sqlite3.connect(current_app.config['DB_PATH'])

#test/test_auth.py ######################################################
import os
import pytest
from app import app, init_db

# Simpan token global
TOKEN = None

@pytest.fixture(scope='module')
def client():
    test_db_path = 'test_db.sqlite'
    app.config['TESTING'] = True
    app.config['DB_PATH'] = test_db_path

    # Inisialisasi database test
    init_db(test_db_path)

    with app.test_client() as client:
        yield client

    # Bersihkan database setelah testing
    if os.path.exists(test_db_path):
        os.remove(test_db_path)


def test_register_success(client):
    response = client.post('/register', json={
        "username": "testuser",
        "password": "testpass"
    })
    assert response.status_code == 201
    assert response.get_json()["message"] == "Registrasi berhasil"

def test_register_missing_fields(client):
    response = client.post('/register', json={})
    assert response.status_code == 400
    assert "wajib diisi" in response.get_json()["error"]

def test_register_duplicate_username(client):
    client.post('/register', json={"username": "dupuser", "password": "123"})
    response = client.post('/register', json={"username": "dupuser", "password": "456"})
    assert response.status_code == 409
    assert "sudah digunakan" in response.get_json()["error"]

```

## 4. LOGIN

1. DEFINISI

API SPESIFIKASI

| No  | Method | URL    | Request JSON                                     | Response JSON (Berhasil)                          | Response JSON (Gagal)                                             |
| --- | ------ | ------ | ------------------------------------------------ | ------------------------------------------------- | ----------------------------------------------------------------- |
| 2   | POST   | /login | `{ "username": "user1", "password": "pass123" }` | `{ "message": "Login berhasil", "token": "..." }` | `401 Unauthorized`: `{ "error": "Username atau password salah" }` |

SQL QUERY

user = conn.execute("SELECT \* FROM tb_user WHERE username = ? AND password = ?", (username, password)).fetchone()

2. DOKUMENTASI

```yml
#auth/login.yml
tags:
  - Auth
summary: Login pengguna
description: Endpoint untuk login dan mendapatkan token autentikasi.
consumes:
  - application/json
produces:
  - application/json
parameters:
  - in: body
    name: body
    required: true
    description: Data login pengguna
    schema:
      type: object
      required:
        - username
        - password
      properties:
        username:
          type: string
          example: johndoe
        password:
          type: string
          example: rahasia123
responses:
  200:
    description: Login berhasil
    schema:
      type: object
      properties:
        message:
          type: string
          example: Login berhasil
        token:
          type: string
          example: 4a1f70de-5d72-48ac-9187-01d3b7c177dd
  400:
    description: Input tidak lengkap
    schema:
      type: object
      properties:
        error:
          type: string
          example: Field "username" dan "password" wajib diisi
  401:
    description: Login gagal
    schema:
      type: object
      properties:
        error:
          type: string
          example: Username atau password salah
```

3. SERVICE - ROUTES - TEST

```py
#1. Folder routes/auth.py
#..................
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

#2. File: test/test_auth.py
#...............
def test_login(client):
    response = client.post('/login', json={
        "username": username,
        "password": password
    })
    assert response.status_code == 200
    json_data = response.get_json()
    assert "token" in json_data
    # Simpan token untuk test berikutnya
    global TOKEN
    TOKEN = json_data["token"]

def test_login_wrong_password(client):
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'salahpass'
    })
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Username atau password salah'

def test_login_user_not_found(client):
    response = client.post('/login', json={
        'username': 'nouser',
        'password': 'whatever'
    })
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Username atau password salah'

def test_login_missing_fields(client):
    response = client.post('/login', json={
        'username': 'testuser'
        # password tidak dikirim
    })
    assert response.status_code == 400
    assert 'wajib diisi' in response.get_json()['error']
```

## 5. LOGOUT

1. DEFINISI

API SPESIFIKASI

| No  | Method | URL     | Request JSON                              | Response JSON (Berhasil)           | Response JSON (Gagal)                                  |
| --- | ------ | ------- | ----------------------------------------- | ---------------------------------- | ------------------------------------------------------ |
| 3   | POST   | /logout | (Header: `Authorization: Bearer <token>`) | `{ "message": "Logout berhasil" }` | `401 Unauthorized`: `{ "error": "Token tidak valid" }` |

SQL QUERY

cur = conn.execute("UPDATE tb_user SET token = NULL WHERE token = ?", (token,))

2. DOKUMENTASI

```yml
#auth/logout.yml
tags:
  - Auth
summary: Logout pengguna
description: Endpoint untuk logout dengan menghapus token autentikasi.
consumes:
  - application/json
produces:
  - application/json
parameters:
  - in: header
    name: Authorization
    required: true
    type: string
    description: Token autentikasi pengguna
    example: 4a1f70de-5d72-48ac-9187-01d3b7c177dd
responses:
  200:
    description: Logout berhasil
    schema:
      type: object
      properties:
        message:
          type: string
          example: Logout berhasil
  401:
    description: Token tidak valid atau tidak ada
    schema:
      type: object
      properties:
        error:
          type: string
          example: Token tidak valid
```

3. SERVICE - ROUTES - TEST

```py
#1. Folder routes/auth.py
#..................
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

#2. File: test/test_auth.py
#............
def test_logout(client):
    headers = {"Authorization": TOKEN}
    response = client.post('/logout', headers=headers)
    assert response.status_code == 200
    assert response.get_json().get("message") == "Logout berhasil"

def test_logout_missing_token(client):
    response = client.post('/logout')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Token tidak ditemukan'

def test_logout_invalid_token(client):
    response = client.post('/logout', headers={
        'Authorization': 'invalid-token-xyz'
    })
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Token tidak valid'
```

## 6. MIDDLEWARE

```py
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
```

## 7. SISWA AUTH API READALL-CREATE

```yml
#/docs/siswa_read_all
tags:
  - Siswa
summary: Ambil semua data siswa
description: Endpoint untuk mengambil semua data siswa yang tersimpan di database. Wajib menyertakan token autentikasi.
security:
  - ApiKeyAuth: []

parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi, format: `Bearer <token>`

responses:
  200:
    description: Daftar semua siswa
    schema:
      type: object
      properties:
        message:
          type: string
          example: Daftar siswa berhasil diambil
        data:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                example: 1
              nama:
                type: string
                example: Budi
              alamat:
                type: string
                example: Jakarta

  401:
    description: Tidak diizinkan (token tidak valid atau tidak ada)
    schema:
      type: object
      properties:
        error:
          type: string
          example: Token tidak valid atau tidak ditemukan

  500:
    description: Gagal mengambil data siswa
    schema:
      type: object
      properties:
        error:
          type: string
          example: Gagal mengambil data siswa

#docs/siswa/create.yml
tags:
  - Siswa
summary: Tambah siswa baru
security:
  - ApiKeyAuth: []
parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi
  - in: body
    name: body
    required: true
    schema:
      type: object
      required:
        - nama
        - alamat
      properties:
        nama:
          type: string
        alamat:
          type: string
responses:
  201:
    description: Siswa berhasil ditambahkan
    schema:
      type: object
      properties:
        message:
          type: string
  500:
    description: Gagal menambahkan siswa
    schema:
      type: object
      properties:
        error:
          type: string
```

```py

#Definisi securityDefinitions di Swagger (app.py)
# app.py (tambahkan sebelum inisialisasi Swagger)
app.config['SWAGGER'] = {
    'title': 'BELAJAR AUTH API',
    'uiversion': 3,
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': "Masukkan token dengan format `Bearer <token>`"
        }
    }
}



# app.py
#.................
#c. create route, method
# Register blueprint >> Seperti Router() di Express
# Register Blueprint >> siswa
from routes.siswa import siswa_bp
from routes.auth import auth_bp

app.register_blueprint(auth_bp)
app.register_blueprint(siswa_bp)



# services/siswa_service.py
from utils.db import get_db

def get_db_connection():
    conn = get_db()
    conn.row_factory = sqlite3.Row
    return conn

def read_all_siswa():
    conn = get_db_connection()
    siswa = conn.execute("SELECT id, nama, alamat FROM tb_siswa").fetchall()
    conn.close()
    return [dict(row) for row in siswa]

def create_siswa(nama, alamat):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tb_siswa (nama, alamat) VALUES (?, ?)",
        (nama, alamat)
    )
    conn.commit()
    siswa_id = cursor.lastrowid
    conn.close()
    return siswa_id

def read_siswa_by_id(id):
    conn = get_db_connection()
    row = conn.execute("SELECT id, nama, alamat FROM tb_siswa WHERE id = ?", (id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_siswa(siswa_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tb_siswa WHERE id = ?", (siswa_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return deleted  # 1 jika berhasil dihapus, 0 jika tidak ditemukan

def update_siswa(siswa_id, nama, alamat):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tb_siswa SET nama = ?, alamat = ? WHERE id = ?",
        (nama, alamat, siswa_id)
    )
    conn.commit()
    updated = cursor.rowcount  # Mengecek apakah baris ter-update
    conn.close()
    return updated  # 0 jika tidak ada yang diupdate, 1 jika berhasil

#routes/siswa.py
from flask import Blueprint, request, jsonify
from flasgger import swag_from
from middleware.auth_middleware import token_required
from services import siswa_service

siswa_bp = Blueprint('siswa', __name__)

#- CREATE
@siswa_bp.route('/siswa', methods=['POST'])
@token_required
@swag_from('../docs/siswa/create.yml')
def create_siswa():
    try:
        data = request.get_json()
        # Validasi input sederhana
        if not data or 'nama' not in data or 'alamat' not in data:
            return jsonify({"error": "Field 'nama' dan 'alamat' wajib diisi"}), 400

        siswa_id = siswa_service.create_siswa(data['nama'], data['alamat'])

        return jsonify({
            "message": "Siswa berhasil ditambahkan",
            "data": {
                "id": siswa_id,
                "nama": data['nama'],
                "alamat": data['alamat']
            }
        }), 201

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Gagal menambahkan siswa"}), 500

#- READ ALL
@siswa_bp.route('/siswa', methods=['GET'])
@token_required
@swag_from('../docs/siswa/read_all.yml')
def read_all_siswa():
    try:
        data = siswa_service.read_all_siswa()
        return jsonify({
            "message": "Daftar siswa berhasil diambil",
            "data": data
        }), 200
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Gagal mengambil data siswa"}), 500

#- READ ID
@siswa_bp.route('/siswa/<int:siswa_id>', methods=['GET'])
@token_required
@swag_from('../docs/siswa_read_id.yml')
def read_siswa_by_id(siswa_id):
    try:
        data = siswa_service.read_siswa_by_id(siswa_id)
        if data:
            return jsonify({
                "message": "Data siswa ditemukan",
                "data": data
            }), 200
        return jsonify({"error": "Siswa dengan ID tersebut tidak ditemukan"}), 404
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Gagal mengambil data siswa"}), 500

#- DELETE ID
@siswa_bp.route('/siswa/<int:siswa_id>', methods=['DELETE'])
@token_required
@swag_from('../docs/siswa_delete.yml')
def delete_siswa(siswa_id):
    try:
        deleted = siswa_service.delete_siswa(siswa_id)
        if deleted:
            return jsonify({
                "message": "Siswa berhasil dihapus",
                "data": {
                    "id": siswa_id
                }
            }), 200
        return jsonify({"error": "Siswa dengan ID tersebut tidak ditemukan"}), 404
    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Gagal menghapus siswa"}), 500

#- UPDATE ID
@siswa_bp.route('/siswa/<int:siswa_id>', methods=['PUT'])
@token_required
@swag_from('../docs/siswa_update.yml')
def update_siswa(siswa_id):
    try:
        data = request.get_json()

        # Validasi input
        if not data or 'nama' not in data or 'alamat' not in data:
            return jsonify({"error": "Field 'nama' dan 'alamat' wajib diisi"}), 400

        updated = siswa_service.update_siswa(siswa_id, data['nama'], data['alamat'])

        if updated == 0:
            return jsonify({"error": "Siswa dengan ID tersebut tidak ditemukan"}), 404

        return jsonify({
            "message": "Siswa berhasil diperbarui",
            "data": {
                "id": siswa_id,
                "nama": data['nama'],
                "alamat": data['alamat']
            }
        }), 200

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "Gagal memperbarui siswa"}), 500



# test/test_siswa.py
import os
import pytest
from app import app, init_db

@pytest.fixture(scope='module')
def client():
    # Gunakan database testing
    test_db_path = 'test_db.sqlite'
    app.config['TESTING'] = True
    app.config['DB_PATH'] = test_db_path

    # Inisialisasi database test
    init_db(test_db_path)

    with app.test_client() as client:
        yield client

    # Hapus database setelah test selesai
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

@pytest.fixture(scope='module')
def auth_headers(client):
    # Register user
    client.post('/register', json={
        "username": "testuser",
        "password": "testpass"
    })

    # Login user
    response = client.post('/login', json={
        "username": "testuser",
        "password": "testpass"
    })
    token = response.get_json().get('token')

    return {
        "Authorization": token
    }

def test_get_all_siswa(client):
    # method (url)
    response = client.get('/siswa')
    # assert >> code success >> 200
    assert response.status_code == 200
    json_data = response.get_json()

    assert json_data['message'] == "Daftar siswa berhasil diambil"
    # assert >> berupa json >> list
    assert isinstance(json_data['data'], list)

def test_create_siswa(client):
    response = client.post('/siswa', json={"nama": "Silmi", "alamat": "Semarang"})
    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil ditambahkan"
    assert json_data['data']['nama'] == "Silmi"
    assert json_data['data']['alamat'] == "Semarang"
    assert isinstance(json_data['data']['id'], int)

from unittest.mock import patch

# Test gagal insert karena data kosong atau field tidak lengkap
def test_create_siswa_gagal_validasi(client):
    # data kosong
    response = client.post('/siswa', json={})
    assert response.status_code == 400
    assert response.get_json()['error'] == "Field 'nama' dan 'alamat' wajib diisi"

    # hanya ada nama
    response = client.post('/siswa', json={"nama": "Silmi"})
    assert response.status_code == 400

    # hanya ada alamat
    response = client.post('/siswa', json={"alamat": "Jakarta"})
    assert response.status_code == 400

# Test gagal insert karena terjadi exception di service
def test_create_siswa_gagal_exception(client):
    with patch('services.siswa_service.create_siswa', side_effect=Exception("DB error")):
        response = client.post('/siswa', json={"nama": "Silmi", "alamat": "Semarang"})
        assert response.status_code == 500
        assert response.get_json()['error'] == "Gagal menambahkan siswa"

def test_read_siswa_by_id(client):
    # Tambahkan siswa dulu
    create_response = client.post('/siswa', json={"nama": "Coba", "alamat": "Bandung"})
    siswa_id = create_response.get_json()['data']['id']

    # Baca siswa yang sudah dibuat
    response = client.get(f'/siswa/{siswa_id}')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Data siswa ditemukan"
    assert json_data['data']['id'] == siswa_id
    assert json_data['data']['nama'] == "Coba"
    assert json_data['data']['alamat'] == "Bandung"

    # Test siswa yang tidak ada
    response_404 = client.get('/siswa/999999')
    assert response_404.status_code == 404
    assert response_404.get_json()['error'] == "Siswa dengan ID tersebut tidak ditemukan"

def test_delete_siswa(client):
    # Tambahkan siswa terlebih dahulu
    create_response = client.post('/siswa', json={"nama": "Delete Me", "alamat": "Nowhere"})
    siswa_id = create_response.get_json()['data']['id']

    # Lakukan DELETE
    response = client.delete(f'/siswa/{siswa_id}')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil dihapus"
    assert json_data['data']['id'] == siswa_id

    # DELETE lagi → harusnya 404
    response_2 = client.delete(f'/siswa/{siswa_id}')
    assert response_2.status_code == 404
    assert response_2.get_json()['error'] == "Siswa dengan ID tersebut tidak ditemukan"

def test_update_siswa(client):
    # Tambah siswa dulu agar bisa diupdate
    create_response = client.post('/siswa', json={"nama": "Ani", "alamat": "Solo"})
    siswa_id = create_response.get_json()['data']['id']

    # Update siswa
    response = client.put(f'/siswa/{siswa_id}', json={"nama": "Ani Updated", "alamat": "Semarang"})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil diperbarui"
    assert json_data['data']['id'] == siswa_id
    assert json_data['data']['nama'] == "Ani Updated"
    assert json_data['data']['alamat'] == "Semarang"

```

## 8. SISWA AUTH API READID-DELETE-UPDATE

```yml
#docs/siswa/delete.yml
tags:
  - Siswa
summary: Hapus siswa berdasarkan ID
security:
  - ApiKeyAuth: []
parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi
  - name: id
    in: path
    required: true
    type: integer
    description: ID siswa
responses:
  200:
    description: Siswa berhasil dihapus
    schema:
      type: object
      properties:
        message:
          type: string
  404:
    description: Siswa tidak ditemukan
  500:
    description: Gagal menghapus siswa

#docs/siswa/update.yml
tags:
  - Siswa
summary: Perbarui data siswa berdasarkan ID
security:
  - ApiKeyAuth: []
parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi
  - name: id
    in: path
    required: true
    type: integer
    description: ID siswa
  - in: body
    name: body
    required: true
    schema:
      type: object
      required:
        - nama
        - alamat
      properties:
        nama:
          type: string
        alamat:
          type: string
responses:
  200:
    description: Siswa berhasil diperbarui
    schema:
      type: object
      properties:
        message:
          type: string
  404:
    description: Siswa tidak ditemukan
  500:
    description: Gagal memperbarui siswa

#docs/siswa/read_id.yml
tags:
  - Siswa
summary: Ambil data siswa berdasarkan ID
security:
  - ApiKeyAuth: []
parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi
  - name: id
    in: path
    required: true
    type: integer
    description: ID siswa
responses:
  200:
    description: Data siswa ditemukan
    schema:
      type: object
      properties:
        id:
          type: integer
        nama:
          type: string
        alamat:
          type: string
  404:
    description: Siswa tidak ditemukan
  500:
    description: Gagal mengambil data
```

```py

```

## 9. DEPLOY DOCKER SQLITE

## 10. DATABASE MYSQL

## 11. DEPLOY DOCKER MYSQL

## 12. DATABASE POSTGRE

## 13. DEPLOY DOCKER FLASK POSTGRE PGADMIN

## 14. DATABASE MONGODB

## 15. DEPLOY DOCKER FLASK MONGO
