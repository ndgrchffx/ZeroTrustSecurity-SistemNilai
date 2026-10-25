// Service Transkrip (port 3002) - resource: data transkrip mahasiswa.
// Memverifikasi X-Gateway-Secret DAN token yang diteruskan gateway.
const express = require("express");
const { config } = require("../lib/config");
const { openDb } = require("../lib/db");
const { requireGateway, requireToken } = require("../lib/guard");

const db = openDb();
const app = express();
app.disable("x-powered-by");
app.use(requireGateway); // 1) harus lewat gateway
app.use(express.json({ limit: "100kb" }));
app.use(requireToken); // 2) token wajib valid

const qUserByNim = db.prepare(
  "SELECT id, nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'",
);
const qUserById = db.prepare("SELECT id, role, nim FROM users WHERE id = ?");
const qTranskrip = db.prepare(`
  SELECT k.id AS kelas_id, k.nama AS mata_kuliah, t.nilai_angka, t.disinkron_pada
  FROM transkrip t JOIN kelas k ON k.id = t.kelas_id
  WHERE t.mahasiswa_id = ? ORDER BY k.id`);
const upsert = db.prepare(`
  INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai_angka, disinkron_pada) VALUES (?,?,?,?)
  ON CONFLICT (mahasiswa_id, kelas_id) DO UPDATE SET nilai_angka = excluded.nilai_angka, disinkron_pada = excluded.disinkron_pada`);
const qKelas = db.prepare("SELECT id FROM kelas WHERE id = ?");

// GET /transkrip/:nim  (mahasiswa: NIM sendiri, admin: semua) - dicek ulang di service
app.get("/transkrip/:nim", (req, res) => {
  if (req.auth.typ !== "user")
    return res
      .status(403)
      .json({ error: "token service tidak boleh membaca transkrip" });
  const caller = qUserById.get(Number(req.auth.sub));
  if (!caller)
    return res.status(401).json({ error: "subjek token tidak ditemukan" });
  const allowed =
    caller.role === "admin" ||
    (caller.role === "mahasiswa" && caller.nim === req.params.nim);
  if (!allowed)
    return res
      .status(403)
      .json({ error: "tidak berhak melihat transkrip ini" });

  const mhs = qUserByNim.get(req.params.nim);
  if (!mhs) return res.status(404).json({ error: "NIM tidak ditemukan" });
  const mata_kuliah = qTranskrip.all(mhs.id);
  const rata = mata_kuliah.length
    ? Math.round(
        (mata_kuliah.reduce((a, b) => a + b.nilai_angka, 0) /
          mata_kuliah.length) *
          100,
      ) / 100
    : null;
  res.json({ nim: mhs.nim, nama: mhs.nama, rata_rata: rata, mata_kuliah });
});

// POST /transkrip/sinkron  (HANYA token service) - dicek ulang di service
// body: { kelas_id, items: [{ mahasiswa_id, nilai_angka }] }
app.post("/transkrip/sinkron", (req, res) => {
  if (req.auth.typ !== "service" || req.auth.role !== "service") {
    return res
      .status(403)
      .json({ error: "hanya token service yang boleh sinkron transkrip" });
  }
  const { kelas_id, items } = req.body || {};
  if (
    !Number.isInteger(kelas_id) ||
    !qKelas.get(kelas_id) ||
    !Array.isArray(items) ||
    items.length === 0
  ) {
    return res
      .status(400)
      .json({ error: "body harus berisi kelas_id valid dan items[]" });
  }
  for (const it of items) {
    if (
      !Number.isInteger(it.mahasiswa_id) ||
      typeof it.nilai_angka !== "number" ||
      !qUserById.get(it.mahasiswa_id)
    ) {
      return res.status(400).json({ error: "item sinkron tidak valid" });
    }
  }
  const now = new Date().toISOString();
  db.transaction(() =>
    items.forEach((it) =>
      upsert.run(it.mahasiswa_id, kelas_id, it.nilai_angka, now),
    ),
  )();
  res.json({
    message: "transkrip disinkronkan",
    kelas_id,
    jumlah: items.length,
  });
});

app.use((_req, res) => res.status(404).json({ error: "tidak ditemukan" }));
app.use((err, _req, res, _next) =>
  res.status(400).json({ error: "request tidak valid" }),
);

app.listen(config.ports.transkrip, "127.0.0.1", () =>
  console.log(
    `[service-transkrip] berjalan di 127.0.0.1:${config.ports.transkrip}`,
  ),
);
