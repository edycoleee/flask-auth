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
