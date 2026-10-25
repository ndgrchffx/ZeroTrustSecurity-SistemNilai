// Audit log (4.4): setiap keputusan akses dicatat oleh gateway ke tabel audit_log
// (dan dicetak ke console agar terlihat saat demo).
function createAudit(db) {
  const insert = db.prepare(
    "INSERT INTO audit_log (waktu, subjek, endpoint, device, hasil, alasan) VALUES (?,?,?,?,?,?)",
  );
  return function audit({ subjek, endpoint, device, hasil, alasan }) {
    const waktu = new Date().toISOString();
    insert.run(waktu, subjek, endpoint, device || null, hasil, alasan);
    console.log(
      `[AUDIT] ${waktu} | ${subjek} | ${endpoint} | device=${device || "-"} | ${hasil.toUpperCase()} | ${alasan}`,
    );
  };
}

module.exports = { createAudit };
