
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