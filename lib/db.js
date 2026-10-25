// Satu database SQLite bersama untuk kedua service dan gateway.
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const { config } = require("./config");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nama TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim TEXT UNIQUE            -- hanya untuk mahasiswa
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  nilai_angka REAL,
  final INTEGER NOT NULL DEFAULT 0,
  UNIQUE (kelas_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS transkrip (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  nilai_angka REAL NOT NULL,
  disinkron_pada TEXT NOT NULL,
  UNIQUE (mahasiswa_id, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,   -- hanya hash yang disimpan
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT,
  expires_at INTEGER NOT NULL,       -- epoch ms
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  nama TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  waktu TEXT NOT NULL,
  subjek TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device TEXT,
  hasil TEXT NOT NULL CHECK (hasil IN ('allow','deny')),
  alasan TEXT NOT NULL
);
`;

function openDb() {
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
  const db = new Database(config.dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA);
  return db;
}

module.exports = { openDb };
