// Service Nilai (port 3001) - resource: data nilai dan kelas.
// Memverifikasi X-Gateway-Secret DAN token. Saat finalisasi, memanggil
// Service Transkrip MELALUI gateway menggunakan token service.
const express = require("express");
const { config } = require("../lib/config");
const { openDb } = require("../lib/db");
const { requireGateway, requireToken } = require("../lib/guard");

const db = openDb();
const app = express();
app.disable("x-powered-by");
app.use(requireGateway);
app.use(express.json({ limit: "10kb" }));
app.use(requireToken);

const qCaller = db.prepare("SELECT id, role FROM users WHERE id = ?");
const qKelas = db.prepare("SELECT id, nama, dosen_id FROM kelas WHERE id = ?");
const qNilaiById = db.prepare(
  "SELECT n.id, n.kelas_id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?",
);
const SELECT_NILAI = `
  SELECT n.id, n.kelas_id, k.nama AS kelas, u.nim, u.nama AS mahasiswa, n.nilai_angka, n.final
  FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.mahasiswa_id`;

// Hanya token user yang dikenal di database yang boleh lewat; kembalikan user atau null.
function caller(req, res) {
  if (req.auth.typ !== "user") {
    res
      .status(403)
      .json({ error: "token service tidak boleh mengakses endpoint ini" });
    return null;
  }
  const u = qCaller.get(Number(req.auth.sub));
  if (!u) {
    res.status(401).json({ error: "subjek token tidak ditemukan" });
    return null;
  }
  return u;
}

// GET /nilai  -> mahasiswa: milik sendiri | dosen: kelas yang diampu
app.get("/nilai", (req, res) => {
  const u = caller(req, res);
  if (!u) return;
  if (u.role === "mahasiswa") {
    return res.json(
      db
        .prepare(`${SELECT_NILAI} WHERE n.mahasiswa_id = ? ORDER BY n.kelas_id`)
        .all(u.id),
    );
  }
  if (u.role === "dosen") {
    if (req.query.kelas_id !== undefined) {
      const k = qKelas.get(Number(req.query.kelas_id));
      if (!k || k.dosen_id !== u.id)
        return res.status(403).json({ error: "kelas bukan yang Anda ampu" });
      return res.json(
        db
          .prepare(`${SELECT_NILAI} WHERE n.kelas_id = ? ORDER BY u.nim`)
          .all(k.id),
      );
    }
    return res.json(
      db
        .prepare(
          `${SELECT_NILAI} WHERE k.dosen_id = ? ORDER BY n.kelas_id, u.nim`,
        )
        .all(u.id),
    );
  }
  res.status(403).json({ error: "role tidak berhak" });
});

// PUT /nilai/:id  -> dosen pengampu, nilai belum final
app.put("/nilai/:id", (req, res) => {
  const u = caller(req, res);
  if (!u) return;
  if (u.role !== "dosen") return res.status(403).json({ error: "hanya dosen" });
  const n = qNilaiById.get(Number(req.params.id));
  if (!n || n.dosen_id !== u.id)
    return res.status(403).json({ error: "bukan kelas yang Anda ampu" });
  if (n.final) return res.status(409).json({ error: "nilai sudah final" });
  const v = (req.body || {}).nilai_angka;
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 100) {
    return res.status(400).json({ error: "nilai_angka harus angka 0-100" });
  }
  db.prepare("UPDATE nilai SET nilai_angka = ? WHERE id = ?").run(v, n.id);
  res.json({ id: n.id, nilai_angka: v });
});

// --- token service (cache sampai mendekati kedaluwarsa) -----------------------------
let cachedToken = null;
let cachedExp = 0;
async function getServiceToken() {
  if (cachedToken && Date.now() < cachedExp - 30_000) return cachedToken;
  const r = await fetch(`${config.gatewayUrl}/auth/service`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: config.nilaiClient.id,
      client_secret: config.nilaiClient.secret,
    }),
  });
  if (!r.ok) throw new Error(`gagal meminta token service (${r.status})`);
  const j = await r.json();
  cachedToken = j.access_token;
  cachedExp = Date.now() + j.expires_in * 1000;
  return cachedToken;
}

// POST /kelas/:id/finalisasi -> dosen pengampu; lalu sinkron ke Service Transkrip via gateway
app.post("/kelas/:id/finalisasi", async (req, res) => {
  const u = caller(req, res);
  if (!u) return;
  if (u.role !== "dosen") return res.status(403).json({ error: "hanya dosen" });
  const k = qKelas.get(Number(req.params.id));
  if (!k || k.dosen_id !== u.id)
    return res.status(403).json({ error: "kelas bukan yang Anda ampu" });

  const rows = db
    .prepare(
      "SELECT id, mahasiswa_id, nilai_angka, final FROM nilai WHERE kelas_id = ?",
    )
    .all(k.id);
  if (rows.length === 0)
    return res.status(409).json({ error: "kelas belum memiliki nilai" });
  if (rows.every((r) => r.final))
    return res.status(409).json({ error: "kelas sudah difinalisasi" });
  if (rows.some((r) => r.nilai_angka === null))
    return res.status(409).json({ error: "masih ada nilai yang kosong" });

  // 1) tandai final
  const ids = rows.map((r) => r.id);
  const setFinal = db.prepare(
    `UPDATE nilai SET final = ? WHERE id IN (${ids.map(() => "?").join(",")})`,
  );
  setFinal.run(1, ...ids);

  // 2) kirim ke Service Transkrip melalui gateway dengan token service
  try {
    const token = await getServiceToken();
    const r = await fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        kelas_id: k.id,
        items: rows.map((x) => ({
          mahasiswa_id: x.mahasiswa_id,
          nilai_angka: x.nilai_angka,
        })),
      }),
    });
    if (!r.ok) throw new Error(`sinkron ditolak (${r.status})`);
  } catch (e) {
    setFinal.run(0, ...ids); // batalkan finalisasi agar data tetap konsisten
    return res
      .status(502)
      .json({
        error: "finalisasi dibatalkan: sinkron transkrip gagal",
        detail: e.message,
      });
  }
  res.json({
    message: "kelas difinalisasi dan transkrip disinkronkan",
    kelas_id: k.id,
    jumlah_nilai: rows.length,
  });
});

app.use((_req, res) => res.status(404).json({ error: "tidak ditemukan" }));
app.use((err, _req, res, _next) =>
  res.status(400).json({ error: "request tidak valid" }),
);

app.listen(config.ports.nilai, "127.0.0.1", () =>
  console.log(`[service-nilai] berjalan di 127.0.0.1:${config.ports.nilai}`),
);
