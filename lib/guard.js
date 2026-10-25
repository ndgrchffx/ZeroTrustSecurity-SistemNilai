// Middleware pengaman untuk service (Service Nilai & Service Transkrip).
// Zero trust: service tidak percaya pada jaringan; ia menolak request yang
//  (1) tidak membawa X-Gateway-Secret yang benar  -> tidak bisa diakses langsung
//  (2) tidak membawa token valid (tanda tangan + masa berlaku) walau secret benar
const { config } = require("./config");
const { verifyToken, bearerFrom, safeEqual } = require("./tokens");

function requireGateway(req, res, next) {
  if (!safeEqual(req.get("x-gateway-secret"), config.gatewaySecret)) {
    return res
      .status(403)
      .json({ error: "akses langsung ditolak: request harus lewat gateway" });
  }
  next();
}

function requireToken(req, res, next) {
  const token = bearerFrom(req);
  if (!token) return res.status(401).json({ error: "access token tidak ada" });
  try {
    req.auth = verifyToken(token); // { sub, role, typ, ... }
  } catch {
    return res
      .status(401)
      .json({ error: "token tidak valid atau kedaluwarsa" });
  }
  next();
}

module.exports = { requireGateway, requireToken };
