#test/test_auth.py ######################################################
import os
import pytest
from app import app, init_db
import time

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

    # TEARDOWN - pastikan koneksi tidak aktif
    import gc, time
    gc.collect()         # Paksa garbage collection
    time.sleep(0.1)      # Beri jeda agar file tidak lagi locked

    try:
        os.remove(test_db_path)
        print(f"[OK] {test_db_path} dihapus.")
    except PermissionError as e:
        print(f"[FAIL] Gagal hapus DB: {e}")

# VARIABEL TEST
username = "testuser"
password =  "testpass"

#- REGISTER
def test_register_success(client):
    response = client.post('/register', json={
        "username": username,
        "password": password
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

# -LOGIN
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

# - LOGOUT

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