// API Gateway = Policy Enforcement Point (PEP), port 3000.
// Satu-satunya pintu masuk: periksa token -> periksa device -> minta keputusan ke
// Policy Engine -> catat audit log -> teruskan ke service dengan X-Gateway-Secret.
const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { config } = require("../lib/config");
const { openDb } = require("../lib/db");
const { verifyToken, bearerFrom } = require("../lib/tokens");
const { createAudit } = require("./audit");
const { createPolicy } = require("./policy");
const { createAuthRouter } = require("./auth");

const db = openDb();
const audit = createAudit(db);
const policy = createPolicy(db);
const qUser = db.prepare("SELECT id, username, role FROM users WHERE id = ?");
const qDevice = db.prepare(
  "SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?",
);

const app = express();
app.disable("x-powered-by");

app.get("/health", (_req, res) =>
  res.json({ status: "ok", service: "gateway" }),
);

// ---- 1) Endpoint /auth/* ditangani gateway sendiri (PE/PA) -------------------
app.use(
  "/auth",
  express.json({ limit: "10kb" }),
  createAuthRouter(db, audit),
  // penangan error (body JSON rusak, dsb.) khusus /auth
  (err, _req, res, _next) =>
    res.status(400).json({ error: "body JSON tidak valid" }),
);

// ---- 2) Enforcement untuk semua endpoint lain -----------------------------------
app.use((req, res, next) => {
  const endpoint = `${req.method} ${req.path}`;
  const device = req.get("x-device-id") || null;
  const finish = (status, subjek, alasan, publicMsg) => {
    audit({ subjek, endpoint, device, hasil: "deny", alasan });
    return res
      .status(status)
      .json({ error: publicMsg || "akses ditolak", reason: alasan });
  };

  // Autentikasi: access token (user) atau token service wajib ada dan valid.
  const token = bearerFrom(req);
  if (!token)
    return finish(
      401,
      "anonymous",
      "access token tidak ada",
      "tidak terautentikasi",
    );
  let payload;
  try {
    payload = verifyToken(token);
  } catch (e) {
    return finish(
      401,
      "anonymous",
      `token tidak valid atau kedaluwarsa (${e.name})`,
      "tidak terautentikasi",
    );
  }

  let subject;
  let subjek;
  if (payload.typ === "service") {
    subject = { type: "service", id: payload.sub, role: "service" };
    subjek = `service:${payload.sub}`;
  } else {
    const u = qUser.get(Number(payload.sub));
    if (!u)
      return finish(
        401,
        "anonymous",
        "subjek token tidak ada di database",
        "tidak terautentikasi",
      );
    subject = { type: "user", id: u.id, role: u.role };
    subjek = `user:${u.username}(${u.role})`;
    // Verifikasi konteks: device harus terdaftar untuk user ini (4.3)
    if (!device) return finish(403, subjek, "header X-Device-ID tidak ada");
    if (!qDevice.get(u.id, device))
      return finish(403, subjek, "device tidak terdaftar untuk user ini");
  }

  // Keputusan dari Policy Engine
  const d = policy.decide(subject, {
    method: req.method,
    path: req.path,
    query: req.query,
  });
  if (!d.allow) return finish(403, subjek, d.reason);

  audit({ subjek, endpoint, device, hasil: "allow", alasan: d.reason });
  next();
});

// ---- 3) Teruskan ke service dengan X-Gateway-Secret ------------------------------
function proxyTo(target, pathFilter) {
  return createProxyMiddleware({
    target,
    pathFilter,
    changeOrigin: true,
    on: {
      proxyReq: (proxyReq) => {
        // Selalu timpa: nilai dari klien tidak pernah dipercaya.
        proxyReq.setHeader("X-Gateway-Secret", config.gatewaySecret);
      },
      error: (err, _req, res) => {
        audit({
          subjek: "gateway",
          endpoint: "proxy",
          device: null,
          hasil: "deny",
          alasan: `service tidak terjangkau: ${err.code || err.message}`,
        });
        if (res.writeHead && !res.headersSent) {
          res.writeHead(502, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "service tidak tersedia" }));
        }
      },
    },
  });
}
app.use(proxyTo(config.nilaiUrl, (p) => /^\/(nilai|kelas)(\/|$)/.test(p)));
app.use(proxyTo(config.transkripUrl, (p) => /^\/transkrip(\/|$)/.test(p)));

// Rute yang lolos kebijakan tapi tidak punya service -> tidak mungkin, tetap ditutup.
app.use((_req, res) => res.status(404).json({ error: "tidak ditemukan" }));

app.listen(config.ports.gateway, () =>
  console.log(
    `[gateway] PEP berjalan di http://localhost:${config.ports.gateway}`,
  ),
);
