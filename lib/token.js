// Penerbitan & verifikasi JWT. Dipakai gateway (menerbitkan + memverifikasi)
// dan service (memverifikasi ulang, 4.1 "Verifikasi ulang di service").
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { config } = require("./config");

// Access token user: berisi sub (id user), role, typ='user'. Berlaku 10 menit.
function signAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role, typ: "user" },
    config.jwtSecret,
    {
      algorithm: "HS256",
      expiresIn: config.accessTokenTtl,
      issuer: config.jwtIssuer,
    },
  );
}

// Token service: role='service', typ='service'. Berlaku 5 menit.
function signServiceToken(clientId) {
  return jwt.sign(
    { sub: clientId, role: "service", typ: "service" },
    config.jwtSecret,
    {
      algorithm: "HS256",
      expiresIn: config.serviceTokenTtl,
      issuer: config.jwtIssuer,
    },
  );
}

// Memeriksa tanda tangan, masa berlaku, issuer, dan konsistensi role<->typ.
// Melempar error bila tidak valid.
function verifyToken(token) {
  const p = jwt.verify(token, config.jwtSecret, {
    algorithms: ["HS256"],
    issuer: config.jwtIssuer,
  });
  const consistent =
    (p.typ === "service" && p.role === "service") ||
    (p.typ === "user" && ["mahasiswa", "dosen", "admin"].includes(p.role));
  if (!consistent) throw new Error("klaim token tidak konsisten");
  return p;
}

function bearerFrom(req) {
  const h = req.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

// Refresh token = string acak opak; di database hanya disimpan hash-nya.
const newRefreshToken = () => crypto.randomBytes(48).toString("hex");
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

// Perbandingan waktu-konstan untuk secret.
function safeEqual(a, b) {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = {
  signAccessToken,
  signServiceToken,
  verifyToken,
  bearerFrom,
  newRefreshToken,
  sha256,
  safeEqual,
};
