// Policy Administrator (PA) - menangani /auth/*: login, refresh, logout, token service.
// Semua hasil (allow/deny) dicatat ke audit log.
const express = require("express");
const bcrypt = require("bcryptjs");
const { config } = require("../lib/config");
const {
  signAccessToken,
  signServiceToken,
  newRefreshToken,
  sha256,
} = require("../lib/tokens");

function createAuthRouter(db, audit) {
  const router = express.Router();
  const qUserByName = db.prepare("SELECT * FROM users WHERE username = ?");
  const qDevice = db.prepare(
    "SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?",
  );
  const qUserById = db.prepare("SELECT * FROM users WHERE id = ?");
  const insertRefresh = db.prepare(
    "INSERT INTO refresh_tokens (token_hash, user_id, device_id, expires_at) VALUES (?,?,?,?)",
  );
  const qRefresh = db.prepare(
    "SELECT * FROM refresh_tokens WHERE token_hash = ?",
  );
  const revoke = db.prepare(
    "UPDATE refresh_tokens SET revoked = 1 WHERE id = ?",
  );
  const qClient = db.prepare(
    "SELECT * FROM service_clients WHERE client_id = ?",
  );

  const log = (req, subjek, hasil, alasan) =>
    audit({
      subjek,
      endpoint: `${req.method} ${req.path.startsWith("/auth") ? req.path : "/auth" + req.path}`,
      device: req.get("x-device-id"),
      hasil,
      alasan,
    });
  const reject = (req, res, status, subjek, alasanInternal, pesanKlien) => {
    log(req, subjek, "deny", alasanInternal);
    return res.status(status).json({ error: pesanKlien });
  };

  // POST /auth/login -> kredensial valid + device terdaftar
  router.post("/login", (req, res) => {
    const { username, password } = req.body || {};
    const device = req.get("x-device-id");
    if (typeof username !== "string" || typeof password !== "string") {
      return reject(
        req,
        res,
        400,
        "anonymous",
        "body login tidak lengkap",
        "username dan password wajib diisi",
      );
    }
    const user = qUserByName.get(username);
    // Pesan ke klien sengaja seragam agar tidak membocorkan apakah username ada.
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return reject(
        req,
        res,
        401,
        `anonymous(${username})`,
        "kredensial tidak valid",
        "kredensial tidak valid",
      );
    }
    const subjek = `user:${user.username}(${user.role})`;
    if (!device)
      return reject(
        req,
        res,
        403,
        subjek,
        "header X-Device-ID tidak ada",
        "device tidak terdaftar",
      );
    if (!qDevice.get(user.id, device)) {
      return reject(
        req,
        res,
        403,
        subjek,
        "device tidak terdaftar untuk user ini",
        "device tidak terdaftar",
      );
    }
    const refreshToken = newRefreshToken();
    insertRefresh.run(
      sha256(refreshToken),
      user.id,
      device,
      Date.now() + config.refreshTokenTtlMs,
    );
    log(
      req,
      subjek,
      "allow",
      "login berhasil: kredensial valid dan device terdaftar",
    );
    res.json({
      access_token: signAccessToken(user),
      token_type: "Bearer",
      expires_in: 600,
      refresh_token: refreshToken,
    });
  });

  // POST /auth/refresh -> refresh token valid & belum dicabut
  router.post("/refresh", (req, res) => {
    const rt = (req.body || {}).refresh_token;
    const row = typeof rt === "string" ? qRefresh.get(sha256(rt)) : null;
    if (!row)
      return reject(
        req,
        res,
        401,
        "anonymous",
        "refresh token tidak dikenal",
        "refresh token tidak valid",
      );
    const user = qUserById.get(row.user_id);
    const subjek = `user:${user.username}(${user.role})`;
    if (row.revoked)
      return reject(
        req,
        res,
        401,
        subjek,
        "refresh token sudah dicabut",
        "refresh token tidak valid",
      );
    if (row.expires_at < Date.now())
      return reject(
        req,
        res,
        401,
        subjek,
        "refresh token kedaluwarsa",
        "refresh token tidak valid",
      );
    log(
      req,
      subjek,
      "allow",
      "access token baru diterbitkan dari refresh token",
    );
    res.json({
      access_token: signAccessToken(user),
      token_type: "Bearer",
      expires_in: 600,
    });
  });

  // POST /auth/logout -> mencabut refresh token
  router.post("/logout", (req, res) => {
    const rt = (req.body || {}).refresh_token;
    const row = typeof rt === "string" ? qRefresh.get(sha256(rt)) : null;
    if (!row)
      return reject(
        req,
        res,
        401,
        "anonymous",
        "refresh token tidak dikenal",
        "refresh token tidak valid",
      );
    const user = qUserById.get(row.user_id);
    const subjek = `user:${user.username}(${user.role})`;
    if (row.revoked)
      return reject(
        req,
        res,
        401,
        subjek,
        "refresh token sudah dicabut",
        "refresh token tidak valid",
      );
    revoke.run(row.id);
    log(req, subjek, "allow", "logout: refresh token dicabut");
    res.json({ message: "logout berhasil, refresh token dicabut" });
  });

  // POST /auth/service -> hanya Service Nilai (client ID + secret valid)
  router.post("/service", (req, res) => {
    const { client_id, client_secret } = req.body || {};
    const c = typeof client_id === "string" ? qClient.get(client_id) : null;
    if (
      !c ||
      typeof client_secret !== "string" ||
      !bcrypt.compareSync(client_secret, c.secret_hash)
    ) {
      return reject(
        req,
        res,
        401,
        `anonymous(${client_id || "-"})`,
        "client id/secret tidak valid",
        "kredensial service tidak valid",
      );
    }
    if (c.client_id !== config.nilaiClient.id) {
      return reject(
        req,
        res,
        403,
        `service:${c.client_id}`,
        "hanya Service Nilai yang boleh meminta token service",
        "tidak diizinkan",
      );
    }
    log(req, `service:${c.client_id}`, "allow", "token service diterbitkan");
    res.json({
      access_token: signServiceToken(c.client_id),
      token_type: "Bearer",
      expires_in: 300,
    });
  });

  return router;
}

module.exports = { createAuthRouter };
