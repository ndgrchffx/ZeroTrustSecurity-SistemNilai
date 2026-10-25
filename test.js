// Uji otomatis: menjalankan sistem di port & database terpisah (tidak mengganggu data demo),
// lalu memeriksa setiap kebutuhan pada soal (4.1 - 4.4 dan Tabel 3).  Jalankan: npm test
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const net = require("net");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const DATA = path.join(__dirname, "data");
fs.mkdirSync(DATA, { recursive: true });
const env = {
  ...process.env,
  DB_PATH: path.join(DATA, "test.db"),
  POLICY_CONFIG: path.join(DATA, "test-policy.json"),
  GATEWAY_PORT: "4000",
  NILAI_PORT: "4001",
  TRANSKRIP_PORT: "4002",
};
const GW = "http://127.0.0.1:4000";
const NILAI = "http://127.0.0.1:4001";
const TRANSKRIP = "http://127.0.0.1:4002";
const JWT_SECRET = env.JWT_SECRET || "dev-jwt-secret-ganti-di-produksi";
const GW_SECRET = env.GATEWAY_SECRET || "dev-gateway-secret-ganti-di-produksi";

const setHours = (start, end) =>
  fs.writeFileSync(
    env.POLICY_CONFIG,
    JSON.stringify({ accessHours: { start, end, timezone: "Asia/Jakarta" } }),
  );

let pass = 0;
let fail = 0;
function check(name, cond, extra = "") {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}
const section = (t) => console.log(`\n== ${t}`);

async function call(
  base,
  method,
  p,
  { token, device, body, headers = {} } = {},
) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h["X-Device-ID"] = device;
  if (body !== undefined) h["Content-Type"] = "application/json";
  const r = await fetch(base + p, {
    method,
    headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await r.json();
  } catch {
    /* kosong */
  }
  return { status: r.status, json };
}
const gw = (m, p, o) => call(GW, m, p, o);

async function login(username, password, device) {
  const r = await gw("POST", "/auth/login", {
    body: { username, password },
    device,
  });
  return {
    ...r,
    token: r.json && r.json.access_token,
    refresh: r.json && r.json.refresh_token,
  };
}

function waitPort(port, ms = 15000) {
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = net.connect(port, "127.0.0.1");
      s.on("connect", () => {
        s.destroy();
        resolve();
      });
      s.on("error", () => {
        s.destroy();
        if (Date.now() - t0 > ms) reject(new Error(`port ${port} tidak siap`));
        else setTimeout(tryOnce, 200);
      });
    };
    tryOnce();
  });
}

(async () => {
  setHours("00:00", "24:00"); // jam akses terbuka selama pengujian awal
  const seed = spawnSync(process.execPath, ["seed.js"], {
    cwd: __dirname,
    env,
    encoding: "utf8",
  });
  if (seed.status !== 0) {
    console.error(seed.stderr);
    process.exit(1);
  }
  const server = spawn(process.execPath, ["start.js"], {
    cwd: __dirname,
    env,
    stdio: ["ignore", "pipe", "inherit"],
  });
  server.stdout.on("data", () => {}); // log audit tidak ditampilkan saat uji
  const shutdown = (code) => {
    server.kill();
    process.exit(code);
  };

  try {
    await Promise.all([4000, 4001, 4002].map((p) => waitPort(p)));

    // ------------------------------------------------------------------------------
    section("4.1 Autentikasi & token");
    const mhs1 = await login("mhs1", "mhs123", "DEV-MHS-01");
    check(
      "login valid -> 200 + access & refresh token",
      mhs1.status === 200 && mhs1.token && mhs1.refresh,
    );
    const dec = jwt.decode(mhs1.token);
    check(
      "JWT berisi sub dan role",
      dec && dec.sub && dec.role === "mahasiswa",
    );
    check("access token berlaku 10 menit", dec.exp - dec.iat === 600);
    check(
      "login password salah -> 401",
      (await login("mhs1", "salah", "DEV-MHS-01")).status === 401,
    );
    check(
      "login device tidak terdaftar -> 403",
      (await login("mhs1", "mhs123", "DEV-MHS-02")).status === 403,
    );
    check(
      "login tanpa X-Device-ID -> 403",
      (await login("mhs1", "mhs123", undefined)).status === 403,
    );

    const rf = await gw("POST", "/auth/refresh", {
      body: { refresh_token: mhs1.refresh },
    });
    check(
      "refresh dengan refresh token valid -> 200",
      rf.status === 200 && rf.json.access_token,
    );
    const rfBad = await gw("POST", "/auth/refresh", {
      body: { refresh_token: "ngawur" },
    });
    check("refresh dengan token ngawur -> 401", rfBad.status === 401);
    const db0 = new Database(env.DB_PATH, { readonly: true });
    const rtRow = db0
      .prepare(
        "SELECT * FROM refresh_tokens WHERE user_id = (SELECT id FROM users WHERE username = ?) ORDER BY id LIMIT 1",
      )
      .get("mhs1");
    check(
      "refresh token disimpan di DB sebagai hash (bukan plaintext)",
      rtRow &&
        rtRow.token_hash !== mhs1.refresh &&
        rtRow.token_hash.length === 64,
    );
    check(
      "refresh token berlaku ~1 hari",
      Math.abs(rtRow.expires_at - Date.now() - 86400000) < 60000,
    );
    db0.close();
    const lo = await gw("POST", "/auth/logout", {
      body: { refresh_token: mhs1.refresh },
    });
    check("logout -> 200", lo.status === 200);
    check(
      "refresh setelah logout (dicabut) -> 401",
      (
        await gw("POST", "/auth/refresh", {
          body: { refresh_token: mhs1.refresh },
        })
      ).status === 401,
    );

    const svc = await gw("POST", "/auth/service", {
      body: {
        client_id: "service-nilai",
        client_secret: "nilai-client-secret-123",
      },
    });
    const sdec = svc.json && jwt.decode(svc.json.access_token);
    check(
      "POST /auth/service valid -> token role=service",
      svc.status === 200 && sdec.role === "service",
    );
    check("token service berlaku 5 menit", sdec && sdec.exp - sdec.iat === 300);
    check(
      "POST /auth/service secret salah -> 401",
      (
        await gw("POST", "/auth/service", {
          body: { client_id: "service-nilai", client_secret: "x" },
        })
      ).status === 401,
    );
    const svcToken = svc.json.access_token;

    // Gateway secret & verifikasi ulang di service
    const user1 = (await login("mhs1", "mhs123", "DEV-MHS-01")).token;
    check(
      "akses langsung ke Service Nilai tanpa gateway secret -> 403",
      (await call(NILAI, "GET", "/nilai", { token: user1 })).status === 403,
    );
    check(
      "akses langsung ke Service Transkrip tanpa gateway secret -> 403",
      (await call(TRANSKRIP, "GET", "/transkrip/2470001", { token: user1 }))
        .status === 403,
    );
    check(
      "gateway secret salah -> 403",
      (
        await call(NILAI, "GET", "/nilai", {
          token: user1,
          headers: { "X-Gateway-Secret": "salah" },
        })
      ).status === 403,
    );
    check(
      "secret benar tanpa token -> 401",
      (
        await call(NILAI, "GET", "/nilai", {
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 401,
    );
    const forged = jwt.sign(
      { sub: "4", role: "mahasiswa", typ: "user" },
      "secret-palsu",
      { expiresIn: "10m", issuer: "sistem-nilai-gateway" },
    );
    check(
      "secret benar + token tanda tangan palsu -> 401",
      (
        await call(NILAI, "GET", "/nilai", {
          token: forged,
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 401,
    );
    const expired = jwt.sign(
      { sub: "4", role: "mahasiswa", typ: "user" },
      JWT_SECRET,
      { expiresIn: -10, issuer: "sistem-nilai-gateway" },
    );
    check(
      "secret benar + token kedaluwarsa -> 401 (Service Nilai)",
      (
        await call(NILAI, "GET", "/nilai", {
          token: expired,
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 401,
    );
    check(
      "secret benar + token kedaluwarsa -> 401 (Service Transkrip)",
      (
        await call(TRANSKRIP, "GET", "/transkrip/2470001", {
          token: expired,
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 401,
    );

    // ------------------------------------------------------------------------------
    section("4.2 Kebijakan akses (Tabel 3) & 4.3 device");
    const T = {};
    T.admin = await login("admin1", "admin123", "DEV-ADMIN-01");
    T.d1 = await login("dosen1", "dosen123", "DEV-DOSEN-01");
    T.d2 = await login("dosen2", "dosen123", "DEV-DOSEN-02");
    T.m1 = await login("mhs1", "mhs123", "DEV-MHS-01");
    T.m2 = await login("mhs2", "mhs123", "DEV-MHS-02");

    check(
      "tanpa token -> 401",
      (await gw("GET", "/nilai", { device: "DEV-MHS-01" })).status === 401,
    );
    check(
      "token kedaluwarsa lewat gateway -> 401",
      (await gw("GET", "/nilai", { token: expired, device: "DEV-MHS-01" }))
        .status === 401,
    );
    check(
      "token valid tanpa X-Device-ID -> 403",
      (await gw("GET", "/nilai", { token: T.m1.token })).status === 403,
    );
    check(
      "device milik user lain -> 403",
      (await gw("GET", "/nilai", { token: T.m1.token, device: "DEV-MHS-02" }))
        .status === 403,
    );
    check(
      "device tidak terdaftar -> 403",
      (await gw("GET", "/nilai", { token: T.m1.token, device: "DEV-ASING" }))
        .status === 403,
    );

    let r = await gw("GET", "/nilai", {
      token: T.m1.token,
      device: "DEV-MHS-01",
    });
    check(
      "GET /nilai mahasiswa -> hanya nilai sendiri",
      r.status === 200 &&
        r.json.length === 2 &&
        r.json.every((x) => x.nim === "2470001"),
    );
    check(
      "GET /nilai?nim=milik-orang-lain (mahasiswa) -> 403",
      (
        await gw("GET", "/nilai?nim=2470002", {
          token: T.m1.token,
          device: "DEV-MHS-01",
        })
      ).status === 403,
    );
    r = await gw("GET", "/nilai?kelas_id=1", {
      token: T.d1.token,
      device: "DEV-DOSEN-01",
    });
    check(
      "GET /nilai dosen kelas yang diampu -> 200 (3 mahasiswa)",
      r.status === 200 && r.json.length === 3,
    );
    check(
      "GET /nilai dosen kelas orang lain -> 403",
      (
        await gw("GET", "/nilai?kelas_id=2", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
        })
      ).status === 403,
    );
    check(
      "GET /nilai admin -> 403",
      (
        await gw("GET", "/nilai", {
          token: T.admin.token,
          device: "DEV-ADMIN-01",
        })
      ).status === 403,
    );

    check(
      "PUT /nilai/:id dosen pengampu -> 200",
      (
        await gw("PUT", "/nilai/1", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body: { nilai_angka: 95 },
        })
      ).status === 200,
    );
    check(
      "PUT /nilai/:id dosen kelas lain -> 403",
      (
        await gw("PUT", "/nilai/4", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body: { nilai_angka: 95 },
        })
      ).status === 403,
    );
    check(
      "PUT /nilai/:id mahasiswa -> 403",
      (
        await gw("PUT", "/nilai/1", {
          token: T.m1.token,
          device: "DEV-MHS-01",
          body: { nilai_angka: 100 },
        })
      ).status === 403,
    );
    check(
      "PUT /nilai/:id nilai di luar 0-100 -> 400",
      (
        await gw("PUT", "/nilai/1", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body: { nilai_angka: 500 },
        })
      ).status === 400,
    );

    // ------------------------------------------------------------------------------
    section("4.3 Jam akses (dapat dikonfigurasi)");
    setHours("00:00", "00:00"); // selalu di luar jam akses
    r = await gw("PUT", "/nilai/2", {
      token: T.d1.token,
      device: "DEV-DOSEN-01",
      body: { nilai_angka: 77 },
    });
    check(
      "ubah nilai di luar jam akses -> 403 (alasan: jam akses)",
      r.status === 403 && /jam akses/.test(r.json.reason),
    );
    r = await gw("POST", "/kelas/1/finalisasi", {
      token: T.d1.token,
      device: "DEV-DOSEN-01",
    });
    check(
      "finalisasi di luar jam akses -> 403",
      r.status === 403 && /jam akses/.test(r.json.reason),
    );
    check(
      "GET (baca) tetap boleh di luar jam akses",
      (
        await gw("GET", "/nilai?kelas_id=1", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
        })
      ).status === 200,
    );
    setHours("00:00", "24:00"); // kembali dibuka tanpa restart server
    check(
      "jam akses dibuka lagi via konfigurasi (tanpa restart) -> 200",
      (
        await gw("PUT", "/nilai/2", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body: { nilai_angka: 77 },
        })
      ).status === 200,
    );

    // ------------------------------------------------------------------------------
    section("Finalisasi + sinkron transkrip lewat gateway");
    check(
      "finalisasi kelas orang lain -> 403",
      (
        await gw("POST", "/kelas/2/finalisasi", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
        })
      ).status === 403,
    );
    check(
      "finalisasi oleh mahasiswa -> 403",
      (
        await gw("POST", "/kelas/1/finalisasi", {
          token: T.m1.token,
          device: "DEV-MHS-01",
        })
      ).status === 403,
    );
    r = await gw("POST", "/kelas/1/finalisasi", {
      token: T.d1.token,
      device: "DEV-DOSEN-01",
    });
    check(
      "finalisasi kelas yang diampu -> 200",
      r.status === 200 && r.json.jumlah_nilai === 3,
      JSON.stringify(r),
    );
    check(
      "finalisasi ulang -> 409",
      (
        await gw("POST", "/kelas/1/finalisasi", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
        })
      ).status === 409,
    );
    check(
      "ubah nilai yang sudah final -> 403",
      (
        await gw("PUT", "/nilai/1", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body: { nilai_angka: 10 },
        })
      ).status === 403,
    );

    r = await gw("GET", "/transkrip/2470001", {
      token: T.m1.token,
      device: "DEV-MHS-01",
    });
    check(
      "transkrip mahasiswa memuat nilai final hasil sinkron (95)",
      r.status === 200 &&
        r.json.mata_kuliah.length === 1 &&
        r.json.mata_kuliah[0].nilai_angka === 95,
      JSON.stringify(r),
    );
    check(
      "transkrip NIM orang lain (mahasiswa) -> 403",
      (
        await gw("GET", "/transkrip/2470002", {
          token: T.m1.token,
          device: "DEV-MHS-01",
        })
      ).status === 403,
    );
    check(
      "transkrip admin semua NIM -> 200",
      (
        await gw("GET", "/transkrip/2470002", {
          token: T.admin.token,
          device: "DEV-ADMIN-01",
        })
      ).status === 200,
    );
    check(
      "transkrip oleh dosen -> 403",
      (
        await gw("GET", "/transkrip/2470001", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
        })
      ).status === 403,
    );
    check(
      "transkrip NIM tidak ada (admin) -> 404",
      (
        await gw("GET", "/transkrip/9999999", {
          token: T.admin.token,
          device: "DEV-ADMIN-01",
        })
      ).status === 404,
    );

    const body = { kelas_id: 1, items: [{ mahasiswa_id: 4, nilai_angka: 95 }] };
    check(
      "POST /transkrip/sinkron token user (dosen) -> 403",
      (
        await gw("POST", "/transkrip/sinkron", {
          token: T.d1.token,
          device: "DEV-DOSEN-01",
          body,
        })
      ).status === 403,
    );
    check(
      "POST /transkrip/sinkron token user (admin) -> 403",
      (
        await gw("POST", "/transkrip/sinkron", {
          token: T.admin.token,
          device: "DEV-ADMIN-01",
          body,
        })
      ).status === 403,
    );
    check(
      "POST /transkrip/sinkron tanpa token -> 401",
      (await gw("POST", "/transkrip/sinkron", { body })).status === 401,
    );
    check(
      "POST /transkrip/sinkron token service -> 200",
      (await gw("POST", "/transkrip/sinkron", { token: svcToken, body }))
        .status === 200,
    );
    check(
      "token service tidak boleh membaca transkrip -> 403",
      (await gw("GET", "/transkrip/2470001", { token: svcToken })).status ===
        403,
    );
    check(
      "token service tidak boleh akses /nilai -> 403",
      (await gw("GET", "/nilai", { token: svcToken })).status === 403,
    );
    check(
      "service transkrip menolak token user pada /sinkron (verifikasi ulang)",
      (
        await call(TRANSKRIP, "POST", "/transkrip/sinkron", {
          token: T.d1.token,
          body,
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 403,
    );
    check(
      "service transkrip menolak mahasiswa baca NIM lain walau lewat secret",
      (
        await call(TRANSKRIP, "GET", "/transkrip/2470002", {
          token: T.m1.token,
          headers: { "X-Gateway-Secret": GW_SECRET },
        })
      ).status === 403,
    );
    check(
      "endpoint tak dikenal -> 403 (default deny)",
      (
        await gw("GET", "/rahasia", {
          token: T.admin.token,
          device: "DEV-ADMIN-01",
        })
      ).status === 403,
    );

    // ------------------------------------------------------------------------------
    section("4.4 Audit log");
    const db = new Database(env.DB_PATH, { readonly: true });
    const rows = db.prepare("SELECT * FROM audit_log").all();
    check("audit log terisi", rows.length > 50, `jumlah=${rows.length}`);
    check(
      "kolom wajib terisi: waktu, subjek, endpoint, hasil, alasan",
      rows.every(
        (x) => x.waktu && x.subjek && x.endpoint && x.hasil && x.alasan,
      ),
    );
    check(
      "ada keputusan allow dan deny",
      rows.some((x) => x.hasil === "allow") &&
        rows.some((x) => x.hasil === "deny"),
    );
    check(
      "device tercatat",
      rows.some((x) => x.device === "DEV-DOSEN-01"),
    );
    check(
      "subjek user tercatat (user:dosen1(dosen))",
      rows.some((x) => x.subjek === "user:dosen1(dosen)"),
    );
    check(
      "subjek service tercatat (service:service-nilai)",
      rows.some((x) => x.subjek === "service:service-nilai"),
    );
    check(
      "panggilan antar-service (sinkron saat finalisasi) tercatat",
      rows.some(
        (x) =>
          x.subjek === "service:service-nilai" &&
          x.endpoint === "POST /transkrip/sinkron" &&
          x.hasil === "allow",
      ),
    );
    check(
      "alasan penolakan jam akses tercatat",
      rows.some((x) => x.hasil === "deny" && /jam akses/.test(x.alasan)),
    );
    db.close();
  } catch (e) {
    fail++;
    console.error("ERROR:", e);
  }

  console.log(`\nHasil: ${pass} lulus, ${fail} gagal`);
  shutdown(fail ? 1 : 0);
})();
