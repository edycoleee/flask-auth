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