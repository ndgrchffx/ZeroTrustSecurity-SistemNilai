// Konfigurasi terpusat. Semua nilai bisa di-override lewat environment variable.
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const gatewayPort = Number(process.env.GATEWAY_PORT || 3000);

const config = {
  root: ROOT,
  ports: {
    gateway: gatewayPort,
    nilai: Number(process.env.NILAI_PORT || 3001),
    transkrip: Number(process.env.TRANSKRIP_PORT || 3002),
  },
  dbPath: process.env.DB_PATH || path.join(ROOT, "data", "sistem-nilai.db"),

  // Secret penandatangan JWT (HS256) dan secret gateway -> service.
  jwtSecret: process.env.JWT_SECRET || "dev-jwt-secret-ganti-di-produksi",
  gatewaySecret:
    process.env.GATEWAY_SECRET || "dev-gateway-secret-ganti-di-produksi",
  jwtIssuer: "sistem-nilai-gateway",

  // Masa berlaku token (4.1)
  accessTokenTtl: "10m", // access token user: 10 menit
  serviceTokenTtl: "5m", // token service: 5 menit
  refreshTokenTtlMs: 24 * 60 * 60 * 1000, // refresh token: 1 hari

  // Kredensial Service Nilai untuk POST /auth/service
  nilaiClient: {
    id: process.env.NILAI_CLIENT_ID || "service-nilai",
    secret: process.env.NILAI_CLIENT_SECRET || "nilai-client-secret-123",
  },
  gatewayUrl: process.env.GATEWAY_URL || `http://127.0.0.1:${gatewayPort}`,
  nilaiUrl: `http://127.0.0.1:${Number(process.env.NILAI_PORT || 3001)}`,
  transkripUrl: `http://127.0.0.1:${Number(process.env.TRANSKRIP_PORT || 3002)}`,

  // File konfigurasi jam akses (dibaca ulang di setiap keputusan -> mudah didemokan)
  policyConfigFile:
    process.env.POLICY_CONFIG || path.join(ROOT, "policy-config.json"),
};

// Baca rentang jam akses (4.3). Dibaca ulang setiap dipanggil, tanpa restart.
function getAccessHours() {
  const fallback = { start: "07:00", end: "21:00", timezone: "Asia/Jakarta" };
  try {
    const raw = JSON.parse(fs.readFileSync(config.policyConfigFile, "utf8"));
    return { ...fallback, ...(raw.accessHours || {}) };
  } catch {
    return fallback;
  }
}

function toMinutes(hhmm) {
  const [h, m] = String(hhmm).split(":").map(Number);
  return h * 60 + (m || 0);
}

// true bila "sekarang" (menurut zona waktu konfigurasi) ada di dalam [start, end)
function isWithinAccessHours(now = new Date()) {
  const { start, end, timezone } = getAccessHours();
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: timezone,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).formatToParts(now);
  const h = Number(parts.find((p) => p.type === "hour").value) % 24;
  const m = Number(parts.find((p) => p.type === "minute").value);
  const cur = h * 60 + m;
  const s = toMinutes(start);
  const e = toMinutes(end);
  return s <= e ? cur >= s && cur < e : cur >= s || cur < e;
}

module.exports = { config, getAccessHours, isWithinAccessHours };
