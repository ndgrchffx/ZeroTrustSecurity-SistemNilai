// Menampilkan audit log terbaru. Pemakaian: npm run audit [jumlah]
const { openDb } = require("../lib/db");
const n = Number(process.argv[2]) || 20;
const rows = openDb()
  .prepare(
    "SELECT waktu, subjek, endpoint, device, hasil, alasan FROM audit_log ORDER BY id DESC LIMIT ?",
  )
  .all(n);
console.table(rows.reverse());
