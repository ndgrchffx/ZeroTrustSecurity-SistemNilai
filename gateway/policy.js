// Policy Engine (PE) - memutuskan allow/deny berdasarkan Tabel 3 + atribut dari database.
// Mengembalikan { allow: boolean, reason: string }.
// Prinsip: default deny; kepemilikan data (kelas diampu, NIM milik sendiri) dibaca dari DB,
// bukan dari isi token saja.
const { isWithinAccessHours, getAccessHours } = require("../lib/config");

const allow = (reason) => ({ allow: true, reason });
const deny = (reason) => ({ allow: false, reason });

function createPolicy(db) {
  const qKelas = db.prepare("SELECT id, dosen_id FROM kelas WHERE id = ?");
  const qNilai = db.prepare(
    "SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?",
  );
  const qUser = db.prepare("SELECT id, role, nim FROM users WHERE id = ?");

  // subject: { type: 'user'|'service', id, role }
  function decide(subject, req, now = new Date()) {
    const { method, path, query } = req;

    // ---- Subjek service: hanya boleh POST /transkrip/sinkron -------------------
    if (subject.type === "service") {
      if (method === "POST" && path === "/transkrip/sinkron")
        return allow("token service sah untuk sinkron transkrip");
      return deny(
        "token service hanya boleh mengakses POST /transkrip/sinkron",
      );
    }

    // ---- Subjek user ------------------------------------------------------------
    const user = qUser.get(Number(subject.id));
    if (!user) return deny("user tidak ditemukan");
    const role = user.role; // atribut dari database, bukan dari klaim token

    let m;

    // GET /nilai : mahasiswa (milik sendiri) / dosen (kelas yang diampu)
    if (method === "GET" && path === "/nilai") {
      if (role === "mahasiswa") {
        if (query.nim && query.nim !== user.nim)
          return deny("mahasiswa hanya boleh melihat nilai miliknya sendiri");
        return allow("mahasiswa melihat nilai miliknya");
      }
      if (role === "dosen") {
        if (query.kelas_id !== undefined) {
          const k = qKelas.get(Number(query.kelas_id));
          if (!k || k.dosen_id !== user.id)
            return deny("dosen hanya boleh melihat kelas yang diampu");
        }
        return allow("dosen melihat nilai kelas yang diampu");
      }
      return deny(`role ${role} tidak boleh mengakses GET /nilai`);
    }

    // PUT /nilai/:id : dosen, kelas diampu, belum final, dalam jam akses
    if (method === "PUT" && (m = /^\/nilai\/(\d+)$/.exec(path))) {
      if (role !== "dosen")
        return deny(`role ${role} tidak boleh mengubah nilai`);
      const n = qNilai.get(Number(m[1]));
      if (!n || n.dosen_id !== user.id)
        return deny("nilai bukan milik kelas yang diampu dosen ini");
      if (n.final) return deny("nilai sudah final, tidak dapat diubah");
      if (!isWithinAccessHours(now)) {
        const h = getAccessHours();
        return deny(`di luar jam akses (${h.start}-${h.end} ${h.timezone})`);
      }
      return allow("dosen mengubah nilai kelas yang diampu dalam jam akses");
    }

    // POST /kelas/:id/finalisasi : dosen, kelas diampu, dalam jam akses
    if (method === "POST" && (m = /^\/kelas\/(\d+)\/finalisasi$/.exec(path))) {
      if (role !== "dosen")
        return deny(`role ${role} tidak boleh memfinalisasi nilai`);
      const k = qKelas.get(Number(m[1]));
      if (!k || k.dosen_id !== user.id)
        return deny("kelas tidak diampu dosen ini");
      if (!isWithinAccessHours(now)) {
        const h = getAccessHours();
        return deny(`di luar jam akses (${h.start}-${h.end} ${h.timezone})`);
      }
      return allow("dosen memfinalisasi kelas yang diampu dalam jam akses");
    }

    // GET /transkrip/:nim : mahasiswa (NIM sendiri) / admin (semua)
    if (method === "GET" && (m = /^\/transkrip\/([^/]+)$/.exec(path))) {
      if (role === "admin") return allow("admin melihat transkrip");
      if (role === "mahasiswa") {
        return m[1] === user.nim
          ? allow("mahasiswa melihat transkrip sendiri")
          : deny("mahasiswa hanya boleh melihat transkrip dengan NIM sendiri");
      }
      return deny(`role ${role} tidak boleh melihat transkrip`);
    }

    // POST /transkrip/sinkron : khusus token service -> token user mana pun ditolak
    if (method === "POST" && path === "/transkrip/sinkron") {
      return deny("token user ditolak; endpoint ini khusus token service");
    }

    return deny("tidak ada kebijakan yang mengizinkan (default deny)");
  }

  return { decide };
}

module.exports = { createPolicy };
