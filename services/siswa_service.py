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