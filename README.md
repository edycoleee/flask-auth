### BELAJAR FLASK MAHIR 2

1. MEMBUAT API AUTH >> REGISTER, LOGIN, LOGOUT >> MIDDLEWARE UTK DECORATOR API DENGAN TOKEN >> MENGGUNAKAN SQLITE 2 DB UNTUK PRODUCTION DAN TESTING
2. DEPLOY KE DOCKER
3. MENGGUNAKAN SQLITE 2 DB UNTUK PRODUCTION DAN TESTING
4. MENGGUNAKAN POSTGRE 2 DB UNTUK PRODUCTION DAN TESTING

### GITHUB

```git
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/edycoleee/flask-auth.git
git push -u origin main
```

## API AUTH SPESIFICATION

| No  | Method | URL         | Request JSON (Body)                                   | Response JSON (Success / Error)                                                                            |
| --- | ------ | ----------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1   | POST   | `/register` | `{ "username": "johndoe", "password": "rahasia123" }` | ✅ **201 Created**<br>`{ "message": "Registrasi berhasil" }`                                               |
|     |        |             |                                                       | ⚠️ **400 Bad Request** (jika field kosong)<br>`{ "error": "Field 'username' dan 'password' wajib diisi" }` |
|     |        |             |                                                       | ⛔ **409 Conflict** (username sudah terdaftar)<br>`{ "error": "Username sudah digunakan" }`                |

| No  | Method | URL      | Request JSON (Body)                                   | Response JSON (Success / Error)                                                                           |
| --- | ------ | -------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 2   | POST   | `/login` | `{ "username": "johndoe", "password": "rahasia123" }` | ✅ **200 OK**<br>`{ "message": "Login berhasil", "token": "uuid" }`                                       |
|     |        |          |                                                       | ⚠️ **400 Bad Request** (field kosong)<br>`{ "error": "Field \"username\" dan \"password\" wajib diisi" }` |
|     |        |          |                                                       | ⛔ **401 Unauthorized** (login gagal)<br>`{ "error": "Username atau password salah" }`                    |

| No  | Method | URL       | Request Header                  | Response JSON (Success / Error)                               |
| --- | ------ | --------- | ------------------------------- | ------------------------------------------------------------- |
| 3   | POST   | `/logout` | `Authorization: Bearer <token>` | ✅ **200 OK**<br>`{ "message": "Logout berhasil" }`           |
|     |        |           |                                 | ⛔ **401 Unauthorized**<br>`{ "error": "Token tidak valid" }` |

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

| No  | Method | URL         | Request JSON (Body)                                   | Response JSON (Success / Error)                                                                            |
| --- | ------ | ----------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1   | POST   | `/register` | `{ "username": "johndoe", "password": "rahasia123" }` | ✅ **201 Created**<br>`{ "message": "Registrasi berhasil" }`                                               |
|     |        |             |                                                       | ⚠️ **400 Bad Request** (jika field kosong)<br>`{ "error": "Field 'username' dan 'password' wajib diisi" }` |
|     |        |             |                                                       | ⛔ **409 Conflict** (username sudah terdaftar)<br>`{ "error": "Username sudah digunakan" }`                |

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

| No  | Method | URL      | Request JSON (Body)                                   | Response JSON (Success / Error)                                                                           |
| --- | ------ | -------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| 2   | POST   | `/login` | `{ "username": "johndoe", "password": "rahasia123" }` | ✅ **200 OK**<br>`{ "message": "Login berhasil", "token": "uuid" }`                                       |
|     |        |          |                                                       | ⚠️ **400 Bad Request** (field kosong)<br>`{ "error": "Field \"username\" dan \"password\" wajib diisi" }` |
|     |        |          |                                                       | ⛔ **401 Unauthorized** (login gagal)<br>`{ "error": "Username atau password salah" }`                    |

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
import uuid

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

| No  | Method | URL       | Request Header                  | Response JSON (Success / Error)                               |
| --- | ------ | --------- | ------------------------------- | ------------------------------------------------------------- |
| 3   | POST   | `/logout` | `Authorization: Bearer <token>` | ✅ **200 OK**<br>`{ "message": "Logout berhasil" }`           |
|     |        |           |                                 | ⛔ **401 Unauthorized**<br>`{ "error": "Token tidak valid" }` |

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
            eturn jsonify({'error': 'Token tidak ditemukan'}), 401
        with get_db() as conn:
            user = conn.execute("SELECT * FROM tb_user WHERE token = ?", (token,)).fetchone()
            if not user:
                return jsonify({'error': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated
```

## 7. SISWA AUTH API CRUD

| No  | Method | URL         | Request Body + Header                                                            | Response (Success / Error)                                                                                                                                                                                                                                                                                        |
| --- | ------ | ----------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | POST   | /siswa      | Body: `{ "nama": string, "alamat": string }`<br>Header: `Authorization: <token>` | **Success:**<br>`201`<br>{ "message": "Siswa berhasil ditambahkan", "data": { "id": int, "nama": string, "alamat": string } }<br>**Error:**<br>`400` - Field 'nama' dan 'alamat' wajib diisi<br>`401` - Token tidak valid atau tidak ditemukan<br>`500` - Gagal menambahkan siswa                                 |
| 2   | GET    | /siswa      | Header: `Authorization: <token>`                                                 | **Success:**<br>`200`<br>{ "message": "Daftar siswa berhasil diambil", "data": \[ { "id": int, "nama": string, "alamat": string }, ... ] }<br>**Error:**<br>`401` - Token tidak valid atau tidak ditemukan<br>`500` - Gagal mengambil data siswa                                                                  |
| 3   | GET    | /siswa/<id> | Header: `Authorization: <token>`                                                 | **Success:**<br>`200`<br>{ "message": "Data siswa ditemukan", "data": { "id": int, "nama": string, "alamat": string } }<br>**Error:**<br>`404` - Siswa tidak ditemukan<br>`401` - Token tidak valid atau tidak ditemukan<br>`500` - Gagal mengambil data siswa                                                    |
| 4   | DELETE | /siswa/<id> | Header: `Authorization: <token>`                                                 | **Success:**<br>`200`<br>{ "message": "Siswa berhasil dihapus", "data": { "id": int } }<br>**Error:**<br>`404` - Siswa tidak ditemukan<br>`401` - Token tidak valid atau tidak ditemukan<br>`500` - Gagal menghapus siswa                                                                                         |
| 5   | PUT    | /siswa/<id> | Body: `{ "nama": string, "alamat": string }`<br>Header: `Authorization: <token>` | **Success:**<br>`200`<br>{ "message": "Siswa berhasil diperbarui", "data": { "id": int, "nama": string, "alamat": string } }<br>**Error:**<br>`400` - Field 'nama' dan 'alamat' wajib diisi<br>`404` - Siswa tidak ditemukan<br>`401` - Token tidak valid atau tidak ditemukan<br>`500` - Gagal memperbarui siswa |
| 6   | POST   | /logout     | Header: `Authorization: <token>`                                                 | **Success:**<br>`200`<br>{ "message": "Logout berhasil" }<br>**Error:**<br>`401` - Token tidak ditemukan<br>`401` - Token tidak valid                                                                                                                                                                             |

```
git branch 02_auth_siswa         # Membuat branch baru
git checkout 02_auth_siswa       # Berpindah ke branch tersebut
# (lakukan perubahan pada file sesuai kebutuhan)
TAMBAHKAN FILE GIT .gitignore
git add .                       # Menambahkan semua perubahan ke staging area
git commit -m "finish"          # Commit dengan pesan "finish"
git push -u origin 02_auth_siswa # Push ke remote dan set tracking branch
```

```yml
#/docs/read_all.yml
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
    description: Token autentikasi.
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

#/docs/siswa/create.yml
tags:
  - Siswa
summary: Tambah siswa baru
description: Endpoint untuk menambahkan data siswa baru. Wajib menyertakan token autentikasi.
security:
  - ApiKeyAuth: []

parameters:
  - name: Authorization
    in: header
    required: true
    type: string
    description: Token autentikasi. Format: Bearer <token>

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
          example: Budi
        alamat:
          type: string
          example: Jakarta

responses:
  201:
    description: Siswa berhasil ditambahkan
    schema:
      type: object
      properties:
        message:
          type: string
          example: Siswa berhasil ditambahkan
        data:
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
    description: Gagal menambahkan siswa
    schema:
      type: object
      properties:
        error:
          type: string
          example: Gagal menambahkan siswa
```

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
  - name: siswa_id
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
  - name: siswa_id
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
  - name: siswa_id
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
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
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
    app.run(debug=True)
    # Jika menggunakan Docker: app.run(host='0.0.0.0', port=5000, debug=True)

# services/siswa_service.py
import sqlite3
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
#@swag_from('../docs/siswa/create.yml')
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
#@swag_from('../docs/siswa/read_all.yml')
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
#@swag_from('../docs/siswa_read_id.yml')
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
#@swag_from('../docs/siswa_delete.yml')
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
#@swag_from('../docs/siswa_update.yml')
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

    # TEARDOWN - pastikan koneksi tidak aktif
    import gc, time
    gc.collect()         # Paksa garbage collection
    time.sleep(0.1)      # Beri jeda agar file tidak lagi locked

    try:
        os.remove(test_db_path)
        print(f"[OK] {test_db_path} dihapus.")
    except PermissionError as e:
        print(f"[FAIL] Gagal hapus DB: {e}")

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
    print("token :",token)
    return {
        "Authorization": token
    }

def test_get_all_siswa(client, auth_headers):
    response = client.get('/siswa', headers=auth_headers)
    assert response.status_code == 200
    json_data = response.get_json()
    print("json_data :",json_data)
    assert json_data['message'] == "Daftar siswa berhasil diambil"
    # assert >> berupa json >> list
    assert isinstance(json_data['data'], list)

def test_create_siswa(client, auth_headers):
    response = client.post('/siswa', headers=auth_headers, json={"nama": "Silmi", "alamat": "Semarang"})
    assert response.status_code == 201
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil ditambahkan"
    assert json_data['data']['nama'] == "Silmi"
    assert json_data['data']['alamat'] == "Semarang"
    assert isinstance(json_data['data']['id'], int)

from unittest.mock import patch

# Test gagal insert karena data kosong atau field tidak lengkap
def test_create_siswa_gagal_validasi(client, auth_headers):
    # data kosong
    response = client.post('/siswa', headers=auth_headers, json={})
    assert response.status_code == 400
    assert response.get_json()['error'] == "Field 'nama' dan 'alamat' wajib diisi"

    # hanya ada nama
    response = client.post('/siswa', headers=auth_headers, json={"nama": "Silmi"})
    assert response.status_code == 400

    # hanya ada alamat
    response = client.post('/siswa', headers=auth_headers, json={"alamat": "Jakarta"})
    assert response.status_code == 400

# Test gagal insert karena terjadi exception di service
def test_create_siswa_gagal_exception(client, auth_headers):
    with patch('services.siswa_service.create_siswa', side_effect=Exception("DB error")):
        response = client.post('/siswa', headers=auth_headers, json={"nama": "Silmi", "alamat": "Semarang"})
        assert response.status_code == 500
        assert response.get_json()['error'] == "Gagal menambahkan siswa"

def test_read_siswa_by_id(client, auth_headers):
    # Tambahkan siswa dulu
    create_response = client.post('/siswa', headers=auth_headers, json={"nama": "Coba", "alamat": "Bandung"})
    siswa_id = create_response.get_json()['data']['id']

    # Baca siswa yang sudah dibuat
    response = client.get(f'/siswa/{siswa_id}', headers=auth_headers)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Data siswa ditemukan"
    assert json_data['data']['id'] == siswa_id
    assert json_data['data']['nama'] == "Coba"
    assert json_data['data']['alamat'] == "Bandung"

    # Test siswa yang tidak ada
    response_404 = client.get('/siswa/999999', headers=auth_headers)
    assert response_404.status_code == 404
    assert response_404.get_json()['error'] == "Siswa dengan ID tersebut tidak ditemukan"

def test_delete_siswa(client, auth_headers):
    # Tambahkan siswa terlebih dahulu
    create_response = client.post('/siswa', headers=auth_headers, json={"nama": "Delete Me", "alamat": "Nowhere"})
    siswa_id = create_response.get_json()['data']['id']

    # Lakukan DELETE
    response = client.delete(f'/siswa/{siswa_id}', headers=auth_headers)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil dihapus"
    assert json_data['data']['id'] == siswa_id

    # DELETE lagi → harusnya 404
    response_2 = client.delete(f'/siswa/{siswa_id}', headers=auth_headers)
    assert response_2.status_code == 404
    assert response_2.get_json()['error'] == "Siswa dengan ID tersebut tidak ditemukan"

def test_update_siswa(client, auth_headers):
    # Tambah siswa dulu agar bisa diupdate
    create_response = client.post('/siswa', headers=auth_headers, json={"nama": "Ani", "alamat": "Solo"})
    siswa_id = create_response.get_json()['data']['id']

    # Update siswa
    response = client.put(f'/siswa/{siswa_id}', headers=auth_headers, json={"nama": "Ani Updated", "alamat": "Semarang"})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['message'] == "Siswa berhasil diperbarui"
    assert json_data['data']['id'] == siswa_id
    assert json_data['data']['nama'] == "Ani Updated"
    assert json_data['data']['alamat'] == "Semarang"

```

## 9. DEPLOY DOCKER SQLITE

```
git branch 03_docker_sqlite         # Membuat branch baru
git checkout 03_docker_sqlite        # Berpindah ke branch tersebut
# (lakukan perubahan pada file sesuai kebutuhan)
TAMBAHKAN FILE GIT .gitignore
git add .                       # Menambahkan semua perubahan ke staging area
git commit -m "finish"          # Commit dengan pesan "finish"
git push -u origin 03_docker_sqlite  # Push ke remote dan set tracking branch
```

```
.
├── app.py
├── siswa.db
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── routes/
├── services/
├── utils/
├── middleware/
└── docs/

```

1. Buat Dockerfile, docker-compose.yml, requirements.txt

```py
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

```

```Dockerfile
# Gunakan image Python slim
FROM python:3.10-slim

# Set environment variable
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Salin semua file
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port Flask
EXPOSE 5000

# Jalankan Flask
CMD ["python", "app.py"]

```

```yml
#docker-compose.yml
version: "3.9"

services:
  flask-api:
    build: .
    container_name: flask_auth_api
    ports:
      - "5000:5000"
    volumes:
      - .:/app # mount project folder
      #- ./siswa.db:/app/siswa.db # persist file SQLite
    restart: always
```

requirements.txt

```
flask
flask-cors
flasgger
```

2. Copy semua data dengan winscp ke server ubuntu docker kecuali folder venv

3. jalankan ssh ke server ubuntu

```
ssh silmi@192.168.10.2

masuk ke folder
docker compose up --build
```

```
docker ps -a
docker images
docker rmi b750fe78269d
docker compose down
docker compose up --build -d
```

http://localhost:5000/apidocs http://192.168.10.2:5000/apidocs

Supaya bisa diakses dari luar konfigurasikan

1. subdomain cloudflare >> setting dns >> name flask.sulfat.my.id

2. setting reverse proxy

```
root@raspberrypi:/etc/nginx/sites-available# nano reverse-proxy
tambahkan

server {
    listen 80;
    server_name flask.sulfat.my.id;

    location / {
        proxy_pass http://192.168.10.2:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}


sudo systemctl status nginx
sudo systemctl stop nginx
sudo systemctl start nginx
sudo systemctl reload nginx

https://flask.sulfat.my.id/register

```

3. tambahkan ke ddns untuk update IP

```
sudo su -
root@raspberrypi:/home/silmi# nano cloudflare-ddns.sh
ctrl + x >> Y


#!/bin/bash

# Cloudflare API Token (dapatkan dari Cloudflare Dashboard)
CF_API_TOKEN="LdJXMaRcBf4HRAyCiB68cHIPf_XeF1FxrsdiC2HO"

# Domain utama
CF_ZONE_NAME="sulfat.my.id"

# Daftar subdomain yang ingin diperbarui (tambahkan domain utama sebagai "")
SUBDOMAINS=("" "satu" "dua" "home" "coba" "flask")

```

## 10. DATABASE MYSQL

```
git branch 04_mysql_docker         # Membuat branch baru
git checkout 04_mysql_docker          # Berpindah ke branch tersebut
# (lakukan perubahan pada file sesuai kebutuhan)
TAMBAHKAN FILE GIT .gitignore
git add .                       # Menambahkan semua perubahan ke staging area
git commit -m "finish"          # Commit dengan pesan "finish"
git push -u origin 04_mysql_docker  # Push ke remote dan set tracking branch
```

```yml
version: "3.8"

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: flaskdb
      MYSQL_USER: root
      MYSQL_PASSWORD: password
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql

  adminer:
    image: adminer
    container_name: adminer
    restart: always
    ports:
      - "8080:8080"

volumes:
  mysql-data:
```

## 11. DEPLOY DOCKER MYSQL

```dockerfile
# Dockerfile tetap sama
FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]

```

docker-compose.yml

```yml
version: "3.9"

services:
  flask-api:
    build: .
    container_name: flask_auth_api
    ports:
      - "5000:5000"
    volumes:
      - .:/app
    environment:
      - DB_HOST=mysql
      - DB_USER=root
      - DB_PASSWORD=password
      - DB_NAME=flaskdb
    depends_on:
      - mysql
    restart: always

  mysql:
    image: mysql:8
    container_name: flask_mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: password
      MYSQL_DATABASE: flaskdb
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql

volumes:
  mysql-data:
```

requirements.txt

```
flask
flask-cors
flasgger
mysql-connector-python

```

```py
# utils/db.py
import mysql.connector
import os

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "flaskdb")
    )

# app.py
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from utils.db import get_db

app = Flask(__name__)
CORS(app)

app.config['SWAGGER'] = {
    'title': 'BELAJAR AUTH API',
    'uiversion': 3,
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
}

swagger = Swagger(app)

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tb_user (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tb_siswa (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nama VARCHAR(255) NOT NULL,
            alamat TEXT NOT NULL
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

from routes.auth import auth_bp
from routes.siswa import siswa_bp
app.register_blueprint(auth_bp)
app.register_blueprint(siswa_bp)

if __name__ == '__main__':
    app.run(debug=True)


# services/siswa_service.py
from utils.db import get_db

def row_to_dict(cursor, row):
    return {desc[0]: value for desc, value in zip(cursor.description, row)}

def get_db_connection():
    conn = get_db()
    return conn

def read_all_siswa():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, nama, alamat FROM tb_siswa")
    rows = cursor.fetchall()
    data = [row_to_dict(cursor, row) for row in rows]
    cursor.close()
    conn.close()
    return data

def create_siswa(nama, alamat):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tb_siswa (nama, alamat) VALUES (%s, %s)",
        (nama, alamat)
    )
    conn.commit()
    siswa_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return siswa_id

def read_siswa_by_id(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, nama, alamat FROM tb_siswa WHERE id = %s", (id,))
    row = cursor.fetchone()
    result = row_to_dict(cursor, row) if row else None
    cursor.close()
    conn.close()
    return result

def delete_siswa(siswa_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tb_siswa WHERE id = %s", (siswa_id,))
    conn.commit()
    deleted = cursor.rowcount
    cursor.close()
    conn.close()
    return deleted

def update_siswa(siswa_id, nama, alamat):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tb_siswa SET nama = %s, alamat = %s WHERE id = %s",
        (nama, alamat, siswa_id)
    )
    conn.commit()
    updated = cursor.rowcount
    cursor.close()
    conn.close()
    return updated

# middleware/auth_middleware.py
from functools import wraps
from flask import request, jsonify
from utils.db import get_db

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token diperlukan'}), 401
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM tb_user WHERE token = %s", (token,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if not user:
            return jsonify({'error': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated


# routes/auth.py
from flask import Blueprint, request, jsonify
from flasgger.utils import swag_from
from utils.db import get_db
import secrets

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'Registrasi berhasil'},
        400: {'description': 'Username sudah digunakan'}
    }
})
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM tb_user WHERE username = %s", (username,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({'error': 'Username sudah digunakan'}), 400

    cursor.execute("INSERT INTO tb_user (username, password) VALUES (%s, %s)", (username, password))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Registrasi berhasil'}), 200

@auth_bp.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'Login berhasil'},
        401: {'description': 'Username atau password salah'}
    }
})
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM tb_user WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Username atau password salah'}), 401

    token = secrets.token_hex(16)
    cursor.execute("UPDATE tb_user SET token = %s WHERE id = %s", (token, user['id']))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Login berhasil', 'token': token}), 200

@auth_bp.route('/logout', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'security': [{'ApiKeyAuth': []}],
    'responses': {
        200: {'description': 'Logout berhasil'},
        401: {'description': 'Token tidak valid'}
    }
})
def logout():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Token diperlukan'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM tb_user WHERE token = %s", (token,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Token tidak valid'}), 401

    cursor.execute("UPDATE tb_user SET token = NULL WHERE token = %s", (token,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Logout berhasil'}), 200

```

## 12. DATABASE POSTGRE

```
git branch 03_docker_sqlite         # Membuat branch baru
git checkout 03_docker_sqlite        # Berpindah ke branch tersebut
# (lakukan perubahan pada file sesuai kebutuhan)
TAMBAHKAN FILE GIT .gitignore
git add .                       # Menambahkan semua perubahan ke staging area
git commit -m "finish"          # Commit dengan pesan "finish"
git push -u origin 03_docker_sqlite  # Push ke remote dan set tracking branch
```

## 13. DEPLOY DOCKER FLASK POSTGRE PGADMIN

1. Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "app.py"]

```

2. docker-compose.yml

```yml
version: "3.8"

services:
  web:
    build: .
    container_name: flask_api
    ports:
      - "5000:5000"
    environment:
      - DB_HOST=db
      - DB_PORT=5432
      - DB_NAME=siswa_db
      - DB_USER=siswa_user
      - DB_PASSWORD=siswa_pass
    depends_on:
      - db

  db:
    image: postgres:15
    container_name: postgres_db
    environment:
      POSTGRES_DB: siswa_db
      POSTGRES_USER: siswa_user
      POSTGRES_PASSWORD: siswa_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  pgadmin:
    image: dpage/pgadmin4
    container_name: pgadmin
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@example.com
      PGADMIN_DEFAULT_PASSWORD: admin123
    ports:
      - "5050:80"
    depends_on:
      - db

volumes:
  postgres_data:
```

requirements.txt

```
Flask==2.3.3
flasgger==0.9.7.1
flask-cors==4.0.0
psycopg2-binary==2.9.9

```

```py

#4. utils/db.py
import psycopg2
import os
from flask import current_app

def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", 5432),
        database=os.getenv("DB_NAME", "siswa_db"),
        user=os.getenv("DB_USER", "siswa_user"),
        password=os.getenv("DB_PASSWORD", "siswa_pass")
    )

#5. app.py
import os
from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from utils.db import get_db

app = Flask(__name__)
CORS(app)

app.config['SWAGGER'] = {
    'title': 'BELAJAR AUTH API',
    'uiversion': 3,
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
}

swagger = Swagger(app)

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tb_user (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password TEXT NOT NULL,
                token TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tb_siswa (
                id SERIAL PRIMARY KEY,
                nama TEXT NOT NULL,
                alamat TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

from routes.auth import auth_bp
from routes.siswa import siswa_bp

app.register_blueprint(auth_bp)
app.register_blueprint(siswa_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

#6. services/siswa_service.py
from utils.db import get_db

def read_all_siswa():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, nama, alamat FROM tb_siswa")
    rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "nama": r[1], "alamat": r[2]} for r in rows]

def create_siswa(nama, alamat):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tb_siswa (nama, alamat) VALUES (%s, %s) RETURNING id",
        (nama, alamat)
    )
    siswa_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    return siswa_id

def read_siswa_by_id(siswa_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, nama, alamat FROM tb_siswa WHERE id = %s", (siswa_id,))
    row = cur.fetchone()
    conn.close()
    return {"id": row[0], "nama": row[1], "alamat": row[2]} if row else None

def delete_siswa(siswa_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM tb_siswa WHERE id = %s", (siswa_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted

def update_siswa(siswa_id, nama, alamat):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE tb_siswa SET nama = %s, alamat = %s WHERE id = %s",
        (nama, alamat, siswa_id)
    )
    updated = cur.rowcount
    conn.commit()
    conn.close()
    return updated


#7. middleware/auth_middleware.py
from functools import wraps
from flask import request, jsonify
from utils.db import get_db

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token diperlukan'}), 401
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM tb_user WHERE token = %s", (token,))
        user = cur.fetchone()
        conn.close()
        if not user:
            return jsonify({'error': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated


#8. routes/auth.py
import uuid
import hashlib
from flask import Blueprint, request, jsonify
from flasgger.utils import swag_from
from utils.db import get_db
import psycopg2

auth_bp = Blueprint('auth', __name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@auth_bp.route('/register', methods=['POST'])
@swag_from('../docs/auth/register.yml')
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Field 'username' dan 'password' wajib diisi"}), 400

    password_hashed = hash_password(password)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO tb_user (username, password) VALUES (%s, %s)",
            (username, password_hashed)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Registrasi berhasil"}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": "Username sudah digunakan"}), 409
    except Exception as e:
        return jsonify({"error": f"Gagal mendaftar: {str(e)}"}), 500

@auth_bp.route('/login', methods=['POST'])
@swag_from('../docs/auth/login.yml')
def login():
    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password'))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tb_user WHERE username = %s AND password = %s", (username, password))
    user = cur.fetchone()

    if user:
        token = str(uuid.uuid4())
        cur.execute("UPDATE tb_user SET token = %s WHERE username = %s", (token, username))
        conn.commit()
        conn.close()
        return jsonify({"message": "Login berhasil", "token": token}), 200
    conn.close()
    return jsonify({"error": "Username atau password salah"}), 401

@auth_bp.route('/logout', methods=['POST'])
@swag_from('../docs/auth/logout.yml')
def logout():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token tidak ditemukan"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE tb_user SET token = NULL WHERE token = %s", (token,))
    conn.commit()
    affected = cur.rowcount
    conn.close()

    if affected:
        return jsonify({"message": "Logout berhasil"}), 200
    return jsonify({"error": "Token tidak valid"}), 401

```

## 14. DATABASE MONGODB

## 15. DEPLOY DOCKER FLASK MONGO

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "app.py"]

```

docker-compose.yml

```yml
version: "3.8"

services:
  web:
    build: .
    container_name: flask_api
    ports:
      - "5000:5000"
    environment:
      - MONGO_URI=mongodb://mongo:27017/siswa_db
    depends_on:
      - mongo

  mongo:
    image: mongo:6.0
    container_name: mongo
    restart: always
    volumes:
      - mongo_data:/data/db
    ports:
      - "27017:27017"

  mongo_express:
    image: mongo-express:1.0.0
    container_name: mongo_express
    restart: always
    environment:
      - ME_CONFIG_MONGODB_SERVER=mongo
      - ME_CONFIG_MONGODB_PORT=27017
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=admin123
    ports:
      - "8081:8081"
    depends_on:
      - mongo

volumes:
  mongo_data:
```

```py
#3. requirements.txt
Flask==2.3.3
flasgger==0.9.7.1
flask-cors==4.0.0
pymongo==4.3.3


#4. utils/db.py
from pymongo import MongoClient
import os

mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/siswa_db")
client = MongoClient(mongo_uri)
db = client.get_database()

def get_db():
    return db

#5. app.py
from flask import Flask
from flask_cors import CORS
from flasgger import Swagger

app = Flask(__name__)
CORS(app)

app.config['SWAGGER'] = {
    'title': 'BELAJAR AUTH API',
    'uiversion': 3,
    'securityDefinitions': {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    }
}

swagger = Swagger(app)

# No need init_db for MongoDB; collections auto-create on first insert

from routes.auth import auth_bp
from routes.siswa import siswa_bp

app.register_blueprint(auth_bp)
app.register_blueprint(siswa_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

#6. services/siswa_service.py
from utils.db import get_db
from bson.objectid import ObjectId

db = get_db()
siswa_col = db.tb_siswa

def read_all_siswa():
    result = []
    for doc in siswa_col.find():
        result.append({
            "id": str(doc["_id"]),
            "nama": doc.get("nama"),
            "alamat": doc.get("alamat")
        })
    return result

def create_siswa(nama, alamat):
    doc = {"nama": nama, "alamat": alamat}
    result = siswa_col.insert_one(doc)
    return str(result.inserted_id)

def read_siswa_by_id(siswa_id):
    doc = siswa_col.find_one({"_id": ObjectId(siswa_id)})
    if not doc:
        return None
    return {
        "id": str(doc["_id"]),
        "nama": doc.get("nama"),
        "alamat": doc.get("alamat")
    }

def delete_siswa(siswa_id):
    result = siswa_col.delete_one({"_id": ObjectId(siswa_id)})
    return result.deleted_count

def update_siswa(siswa_id, nama, alamat):
    result = siswa_col.update_one(
        {"_id": ObjectId(siswa_id)},
        {"$set": {"nama": nama, "alamat": alamat}}
    )
    return result.modified_count

#7. middleware/auth_middleware.py
from functools import wraps
from flask import request, jsonify
from utils.db import get_db

db = get_db()
user_col = db.tb_user

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token diperlukan'}), 401
        user = user_col.find_one({"token": token})
        if not user:
            return jsonify({'error': 'Token tidak valid'}), 401
        return f(*args, **kwargs)
    return decorated

#8. routes/auth.py
import uuid
import hashlib
from flask import Blueprint, request, jsonify
from flasgger.utils import swag_from
from utils.db import get_db

auth_bp = Blueprint('auth', __name__)
db = get_db()
user_col = db.tb_user

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@auth_bp.route('/register', methods=['POST'])
@swag_from('../docs/auth/register.yml')
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Field 'username' dan 'password' wajib diisi"}), 400

    if user_col.find_one({"username": username}):
        return jsonify({"error": "Username sudah digunakan"}), 409

    user_col.insert_one({
        "username": username,
        "password": hash_password(password),
        "token": None
    })
    return jsonify({"message": "Registrasi berhasil"}), 201

@auth_bp.route('/login', methods=['POST'])
@swag_from('../docs/auth/login.yml')
def login():
    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password'))

    user = user_col.find_one({"username": username, "password": password})
    if not user:
        return jsonify({"error": "Username atau password salah"}), 401

    token = str(uuid.uuid4())
    user_col.update_one({"_id": user["_id"]}, {"$set": {"token": token}})
    return jsonify({"message": "Login berhasil", "token": token}), 200

@auth_bp.route('/logout', methods=['POST'])
@swag_from('../docs/auth/logout.yml')
def logout():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token tidak ditemukan"}), 401

    result = user_col.update_one({"token": token}, {"$set": {"token": None}})
    if result.modified_count == 0:
        return jsonify({"error": "Token tidak valid"}), 401

    return jsonify({"message": "Logout berhasil"}), 200


```

## 8. SISWA AUTH API FRONTEND REACTJS

```
git branch 03_reactjs         # Membuat branch baru
git checkout 03_reactj       # Berpindah ke branch tersebut
# (lakukan perubahan pada file sesuai kebutuhan)
TAMBAHKAN FILE GIT .gitignore
git add .                       # Menambahkan semua perubahan ke staging area
git commit -m "finish"          # Commit dengan pesan "finish"
git push -u origin 03_reactj # Push ke remote dan set tracking branch
```

STRUKTUR FOLDER UTAMA

```
project-root/
├── backend/                  # Flask API & MongoDB/PostgreSQL config
│   └── (semua file backend kamu)
├── frontend/                 # ReactJS frontend (Vite)
│   ├── Dockerfile
│   └── (semua file Vite frontend kamu)
└── docker-compose.yml

```

```
# MEMBUAT APLIKASI FRONTEND
npm create vite@latest frontend --template react
cd frontend
npm install axios react-router-dom

#TAMBAHKAN .gitignore

src/
├── App.jsx
├── main.jsx
├── api/
│   └── axios.js
├── context/
│   └── AuthContext.jsx
├── pages/
│   ├── Landing.jsx
│   ├── Register.jsx
│   ├── Login.jsx
│   ├── Dashboard.jsx
│   ├── AddSiswa.jsx
│   └── EditSiswa.jsx
└── components/
    └── SiswaTable.jsx

```

```js
//src/api/axios.js
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000",
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = token;
  }
  return config;
});

export default api;


//src/context/AuthContext.jsx
import React, { createContext, useState, useEffect } from "react";
import api from "../api/axios";

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  // Check token presence on mount
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      setUser({ token }); // Simplified, no user detail fetch
    }
  }, []);

  const login = async (username, password) => {
    const res = await api.post("/login", { username, password });
    if (res.data.token) {
      localStorage.setItem("token", res.data.token);
      setUser({ username, token: res.data.token });
    }
    return res;
  };

  const logout = async () => {
    await api.post("/logout");
    localStorage.removeItem("token");
    setUser(null);
  };

  const register = async (username, password) => {
    return await api.post("/register", { username, password });
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, register }}>
      {children}
    </AuthContext.Provider>
  );
}


//src/main.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { AuthProvider } from "./context/AuthContext";
import { BrowserRouter } from "react-router-dom";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </AuthProvider>
  </React.StrictMode>
);


//src/App.jsx
import React, { useContext } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import Landing from "./pages/Landing";
import Register from "./pages/Register";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import AddSiswa from "./pages/AddSiswa";
import EditSiswa from "./pages/EditSiswa";

import { AuthContext } from "./context/AuthContext";

function PrivateRoute({ children }) {
  const { user } = useContext(AuthContext);
  if (!user) return <Navigate to="/" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/register" element={<Register />} />
      <Route path="/login" element={<Login />} />
      <Route
        path="/dashboard"
        element={
          <PrivateRoute>
            <Dashboard />
          </PrivateRoute>
        }
      />
      <Route
        path="/add-siswa"
        element={
          <PrivateRoute>
            <AddSiswa />
          </PrivateRoute>
        }
      />
      <Route
        path="/edit-siswa/:id"
        element={
          <PrivateRoute>
            <EditSiswa />
          </PrivateRoute>
        }
      />
    </Routes>
  );
}


//src/pages/Landing.jsx
import React from "react";
import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <div data-testid="landing-page">
      <h1>Selamat Datang</h1>
      <Link to="/register" data-testid="link-register">
        Register
      </Link>{" "}
      |{" "}
      <Link to="/login" data-testid="link-login">
        Login
      </Link>
    </div>
  );
}


//src/pages/Register.jsx
import React, { useState, useContext } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";

export default function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const { register } = useContext(AuthContext);
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    try {
      await register(username, password);
      navigate("/login");
    } catch (err) {
      setError(err.response?.data?.error || "Register gagal");
    }
  }

  return (
    <div data-testid="register-page">
      <h2>Register</h2>
      <form onSubmit={onSubmit}>
        <input
          data-testid="input-username"
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <br />
        <input
          data-testid="input-password"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <br />
        <button type="submit" data-testid="btn-register">
          Register
        </button>
      </form>
      {error && <p data-testid="error-message">{error}</p>}
      <p>
        Sudah punya akun? <Link to="/login">Login</Link>
      </p>
    </div>
  );
}


//src/pages/Login.jsx
import React, { useState, useContext } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    try {
      await login(username, password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.error || "Login gagal");
    }
  }

  return (
    <div data-testid="login-page">
      <h2>Login</h2>
      <form onSubmit={onSubmit}>
        <input
          data-testid="input-username"
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <br />
        <input
          data-testid="input-password"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <br />
        <button type="submit" data-testid="btn-login">
          Login
        </button>
      </form>
      {error && <p data-testid="error-message">{error}</p>}
      <p>
        Belum punya akun? <Link to="/register">Register</Link>
      </p>
    </div>
  );
}


//src/components/SiswaTable.jsx
import React from "react";
import { Link } from "react-router-dom";

export default function SiswaTable({ siswaList, onDelete }) {
  return (
    <table data-testid="siswa-table" border="1">
      <thead>
        <tr>
          <th>Nama</th>
          <th>Alamat</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody>
        {siswaList.map((siswa) => (
          <tr key={siswa.id} data-testid="siswa-row">
            <td>{siswa.nama}</td>
            <td>{siswa.alamat}</td>
            <td>
              <Link to={`/edit-siswa/${siswa.id}`} data-testid={`btn-edit-${siswa.id}`}>
                Edit
              </Link>{" "}
              |{" "}
              <button
                onClick={() => onDelete(siswa.id)}
                data-testid={`btn-delete-${siswa.id}`}
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}


//src/pages/Dashboard.jsx
import React, { useState, useEffect, useContext } from "react";
import { useNavigate, Link } from "react-router-dom";
import api from "../api/axios";
import SiswaTable from "../components/SiswaTable";
import { AuthContext } from "../context/AuthContext";

export default function Dashboard() {
  const [siswaList, setSiswaList] = useState([]);
  const { logout } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    fetchSiswa();
  }, []);

  async function fetchSiswa() {
    try {
      const res = await api.get("/siswa");
      setSiswaList(res.data);
    } catch (err) {
      console.error(err);
    }
  }

  async function handleDelete(id) {
    if (!window.confirm("Yakin ingin menghapus?")) return;
    try {
      await api.delete(`/siswa/${id}`);
      fetchSiswa();
    } catch (err) {
      console.error(err);
    }
  }

  async function onLogout() {
    await logout();
    navigate("/");
  }

  return (
    <div data-testid="dashboard-page">
      <h2>Dashboard</h2>
      <button onClick={() => navigate("/add-siswa")} data-testid="btn-add-siswa">
        Tambah Siswa
      </button>
      <button onClick={onLogout} data-testid="btn-logout" style={{ marginLeft: 20 }}>
        Logout
      </button>
      <SiswaTable siswaList={siswaList} onDelete={handleDelete} />
    </div>
  );
}


//src/pages/AddSiswa.jsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/axios";

export default function AddSiswa() {
  const [nama, setNama] = useState("");
  const [alamat, setAlamat] = useState("");
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  async function onSubmit(e) {
    e.preventDefault();
    try {
      await api.post("/siswa", { nama, alamat });
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.error || "Gagal menambah siswa");
    }
  }

  return (
    <div data-testid="add-siswa-page">
      <h2>Tambah Siswa</h2>
      <form onSubmit={onSubmit}>
        <input
          data-testid="input-nama"
          type="text"
          placeholder="Nama"
          value={nama}
          onChange={(e) => setNama(e.target.value)}
          required
        />
        <br />
        <input
          data-testid="input-alamat"
          type="text"
          placeholder="Alamat"
          value={alamat}
          onChange={(e) => setAlamat(e.target.value)}
          required
        />
        <br />
        <button type="submit" data-testid="btn-save">
          Simpan
        </button>{" "}
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          data-testid="btn-cancel"
        >
          Batal
        </button>
      </form>
      {error && <p data-testid="error-message">{error}</p>}
    </div>
  );
}


//src/pages/EditSiswa.jsx
import React, { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import api from "../api/axios";

export default function EditSiswa() {
  const [nama, setNama] = useState("");
  const [alamat, setAlamat] = useState("");
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const { id } = useParams();

  useEffect(() => {
    async function fetchSiswa() {
      try {
        const res = await api.get(`/siswa/${id}`);
        setNama(res.data.nama);
        setAlamat(res.data.alamat);
      } catch (err) {
        setError("Siswa tidak ditemukan");
      }
    }
    fetchSiswa();
  }, [id]);

  async function onSubmit(e) {
    e.preventDefault();
    try {
      await api.put(`/siswa/${id}`, { nama, alamat });
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.error || "Gagal update siswa");
    }
  }

  return (
    <div data-testid="edit-siswa-page">
      <h2>Edit Siswa</h2>
      <form onSubmit={onSubmit}>
        <input
          data-testid="input-nama"
          type="text"
          placeholder="Nama"
          value={nama}
          onChange={(e) => setNama(e.target.value)}
          required
        />
        <br />
        <input
          data-testid="input-alamat"
          type="text"
          placeholder="Alamat"
          value={alamat}
          onChange={(e) => setAlamat(e.target.value)}
          required
        />
        <br />
        <button type="submit" data-testid="btn-save">
          Simpan
        </button>{" "}
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          data-testid="btn-cancel"
        >
          Batal
        </button>
      </form>
      {error && <p data-testid="error-message">{error}</p>}
    </div>
  );
}

```

Pada file src/api/axios.js, kita sudah membuat interceptor:

```js
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = token; // ← Token dikirim ke semua API
  }
  return config;
});
```

Dengan ini: Setiap pemanggilan api.get(...), api.post(...), api.put(...), api.delete(...), dll otomatis akan membawa Authorization: <token>.
Kalau ingin validasi token expired, atau user tidak login (401), tambahkan interceptor response:

```js
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "/login"; // atau navigate('/login')
    }
    return Promise.reject(err);
  }
);
```

1. Struktur Folder Sederhana

```
e2e/
├── auth.spec.js
├── siswa.spec.js
├── utils/
│   └── api.js
playwright.config.js

```

2. Instalasi Playwright

```
npm install -D @playwright/test
npx playwright install
```

3. playwright.config.js

```js
// playwright.config.js
import { defineConfig } from "@playwright/test";

export default defineConfig({
  use: {
    baseURL: "http://localhost:5000", // Ganti jika URL server kamu berbeda
  },
});
```

```js
// tests/auth_siswa.spec.js
import { test, expect } from "@playwright/test";

const BASE_URL = "http://localhost:5173";
const API_BASE = "http://localhost:5000";
const dummyUser = {
  username: "testuser",
  password: "testpass123",
};
const dummySiswa = {
  nama: "Ahmad Putra",
  alamat: "Jl. Pendidikan 45",
};

let token = "";

// Test UI dan API sekaligus

test.describe("AUTH & SISWA UI + API test", () => {
  test("Register, Login, Add, Edit, Delete Siswa", async ({
    page,
    request,
  }) => {
    // Clear user jika sudah ada
    await request.post(`${API_BASE}/logout`, {
      headers: { Authorization: token },
    });

    // --- REGISTER ---
    await page.goto(`${BASE_URL}/register`);
    await page.getByTestId("register-username").fill(dummyUser.username);
    await page.getByTestId("register-password").fill(dummyUser.password);
    await page.getByTestId("register-button").click();

    await expect(page).toHaveURL(/.*login/);

    // --- LOGIN ---
    await page.goto(`${BASE_URL}/login`);
    await page.getByTestId("login-username").fill(dummyUser.username);
    await page.getByTestId("login-password").fill(dummyUser.password);
    await page.getByTestId("login-button").click();

    await expect(page).toHaveURL(`${BASE_URL}/dashboard`);

    // Ambil token dari localStorage
    token = await page.evaluate(() => localStorage.getItem("token"));
    expect(token).not.toBeNull();

    // --- ADD SISWA ---
    await page.getByTestId("add-siswa-button").click();
    await page.getByTestId("input-nama").fill(dummySiswa.nama);
    await page.getByTestId("input-alamat").fill(dummySiswa.alamat);
    await page.getByTestId("save-button").click();

    await expect(page).toHaveURL(`${BASE_URL}/dashboard`);
    await expect(page.getByTestId("siswa-nama")).toContainText(dummySiswa.nama);

    // --- EDIT SISWA ---
    await page.getByTestId("edit-siswa-button").click();
    await page.getByTestId("input-nama").fill("Ahmad Updated");
    await page.getByTestId("save-button").click();
    await expect(page.getByTestId("siswa-nama")).toContainText("Ahmad Updated");

    // --- DELETE SISWA ---
    await page.getByTestId("delete-siswa-button").click();
    await expect(page.getByTestId("siswa-nama")).not.toContainText(
      "Ahmad Updated"
    );

    // --- LOGOUT ---
    await page.getByTestId("logout-button").click();
    await expect(page).toHaveURL(`${BASE_URL}/login`);
  });
});
```

.gitignore

```
# Node modules
/node_modules

# Build files
/dist
/build

# Testing artifacts
/test-results
/playwright-report
/coverage

# Environment files
.env
.env.*
!.env.example

# Logs
*.log

# System files
.DS_Store
Thumbs.db

# IDE and editor files
.idea
*.suo
*.ntvs*
*.njsproj
*.sln

# Temporary files
*~
```

```
project-root/
├── backend/                  # Flask API & MongoDB/PostgreSQL config
│   └── (semua file backend kamu)
├── frontend/                 # ReactJS frontend (Vite)
│   ├── Dockerfile
│   └── (semua file Vite frontend kamu)
└── docker-compose.yml

```

frontend/Dockerfile

```dockerfile
# frontend/Dockerfile
FROM node:20-alpine as build

WORKDIR /app
COPY . .
RUN npm install && npm run build

# Serve with nginx
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

```

frontend/nginx.conf

```nginx
# frontend/nginx.conf
server {
  listen 80;
  server_name localhost;

  location / {
    root /usr/share/nginx/html;
    index index.html index.htm;
    try_files $uri $uri/ /index.html;
  }
}
```

```yml
version: "3.8"

services:
  backend:
    build: ./backend
    container_name: flask-backend
    ports:
      - "5000:5000"
    volumes:
      - ./backend:/app
    environment:
      - FLASK_ENV=development
    depends_on:
      - mongo
    networks:
      - fullstack

  frontend:
    build: ./frontend
    container_name: react-frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
    networks:
      - fullstack

  mongo:
    image: mongo:6
    container_name: mongo-db
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db
    networks:
      - fullstack

  mongo-express:
    image: mongo-express
    container_name: mongo-admin
    restart: always
    ports:
      - "8081:8081"
    environment:
      ME_CONFIG_MONGODB_SERVER: mongo
      ME_CONFIG_BASICAUTH_USERNAME: admin
      ME_CONFIG_BASICAUTH_PASSWORD: admin
    depends_on:
      - mongo
    networks:
      - fullstack

volumes:
  mongo_data:

networks:
  fullstack:
```

frontend/.env

```
VITE_API_URL=http://localhost:5000
```

docker compose up --build

Frontend: http://localhost:3000

Backend API: http://localhost:5000
