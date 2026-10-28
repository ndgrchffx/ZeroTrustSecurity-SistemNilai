# Sistem Nilai - Zero Trust Security

Tugas Praktikum Individu Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.
API gateway (PEP) dengan Service Nilai dan Service Transkrip, dibuat dengan Node.js, Express, dan SQLite.

## Cara menjalankan

Prasyarat: Node.js 22 atau lebih baru.

```bash
npm install
npm run seed
npm start
```

- `npm run seed` membuat database dan data awal (aman diulang, data kembali ke kondisi awal).
- `npm start` menjalankan API Gateway (port 3000), Service Nilai (port 3001), dan Service Transkrip (port 3002).
- Semua request dikirim ke gateway di `http://localhost:3000`. Login lewat `POST /auth/login` dengan body JSON `username` dan `password`, serta header `X-Device-ID` sesuai tabel di bawah.

## Daftar akun dan device ID data awal

| Username | Password | Role                                         | NIM     | Device ID    |
| -------- | -------- | -------------------------------------------- | ------- | ------------ |
| admin1   | admin123 | admin                                        | -       | DEV-ADMIN-01 |
| dosen1   | dosen123 | dosen (mengampu kelas 1: Keamanan Informasi) | -       | DEV-DOSEN-01 |
| dosen2   | dosen123 | dosen (mengampu kelas 2: Pemrograman Web)    | -       | DEV-DOSEN-02 |
| mhs1     | mhs123   | mahasiswa                                    | 2470001 | DEV-MHS-01   |
| mhs2     | mhs123   | mahasiswa                                    | 2470002 | DEV-MHS-02   |
| mhs3     | mhs123   | mahasiswa                                    | 2470003 | DEV-MHS-03   |

Akun service untuk `POST /auth/service`: `client_id` = `service-nilai`, `client_secret` = `nilai-client-secret-123`.
