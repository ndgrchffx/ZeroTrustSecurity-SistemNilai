// Mengisi data awal: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas (dosen berbeda),
// masing-masing user punya 1 device terdaftar. Jalankan: npm run seed
const fs = require("fs");
const bcrypt = require("bcryptjs");
const { config } = require("./lib/config");
const { openDb } = require("./lib/db");

// Mulai dari database bersih agar seed bisa diulang.
for (const suffix of ["", "-wal", "-shm"]) {
  try {
    fs.unlinkSync(config.dbPath + suffix);
  } catch {
    /* belum ada */
  }
}
const db = openDb();
const hash = (p) => bcrypt.hashSync(p, 8);

const USERS = [
  {
    username: "admin1",
    password: "admin123",
    nama: "Admin Prodi",
    role: "admin",
    nim: null,
    device: "DEV-ADMIN-01",
  },
  {
    username: "dosen1",
    password: "dosen123",
    nama: "Dr. Budi Santoso",
    role: "dosen",
    nim: null,
    device: "DEV-DOSEN-01",
  },
  {
    username: "dosen2",
    password: "dosen123",
    nama: "Dr. Citra Lestari",
    role: "dosen",
    nim: null,
    device: "DEV-DOSEN-02",
  },
  {
    username: "mhs1",
    password: "mhs123",
    nama: "Andi Pratama",
    role: "mahasiswa",
    nim: "2470001",
    device: "DEV-MHS-01",
  },
  {
    username: "mhs2",
    password: "mhs123",
    nama: "Bella Kusuma",
    role: "mahasiswa",
    nim: "2470002",
    device: "DEV-MHS-02",
  },
  {
    username: "mhs3",
    password: "mhs123",
    nama: "Chandra Wijaya",
    role: "mahasiswa",
    nim: "2470003",
    device: "DEV-MHS-03",
  },
];

const insertUser = db.prepare(
  "INSERT INTO users (username, password_hash, nama, role, nim) VALUES (?,?,?,?,?)",
);
const insertDevice = db.prepare(
  "INSERT INTO devices (user_id, device_id) VALUES (?,?)",
);
const insertKelas = db.prepare(
  "INSERT INTO kelas (nama, dosen_id) VALUES (?,?)",
);
const insertNilai = db.prepare(
  "INSERT INTO nilai (kelas_id, mahasiswa_id, nilai_angka) VALUES (?,?,?)",
);

db.transaction(() => {
  const id = {};
  for (const u of USERS) {
    id[u.username] = insertUser.run(
      u.username,
      hash(u.password),
      u.nama,
      u.role,
      u.nim,
    ).lastInsertRowid;
    insertDevice.run(id[u.username], u.device);
  }
  // Dua kelas, diampu dosen berbeda
  const k1 = insertKelas.run("Keamanan Informasi", id.dosen1).lastInsertRowid;
  const k2 = insertKelas.run("Pemrograman Web", id.dosen2).lastInsertRowid;
  // Nilai awal (belum final)
  insertNilai.run(k1, id.mhs1, 80);
  insertNilai.run(k1, id.mhs2, 75);
  insertNilai.run(k1, id.mhs3, 90);
  insertNilai.run(k2, id.mhs1, 85);
  insertNilai.run(k2, id.mhs2, 70);
  insertNilai.run(k2, id.mhs3, 88);
  // Client service untuk POST /auth/service
  db.prepare(
    "INSERT INTO service_clients (client_id, secret_hash, nama) VALUES (?,?,?)",
  ).run(
    config.nilaiClient.id,
    hash(config.nilaiClient.secret),
    "Service Nilai",
  );
})();

console.log("Seed selesai ->", config.dbPath);
console.table(
  USERS.map(({ username, password, role, nim, device }) => ({
    username,
    password,
    role,
    nim,
    device,
  })),
);
