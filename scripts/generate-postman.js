// Membuat koleksi Postman (42 request) ke postman/sistem-nilai.postman_collection.json
// Jalankan: npm run postman   lalu import file hasilnya ke Postman.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const DEC =
  "const dec = t => JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));";
const GWS = "{{gateway_secret}}";

function item(
  name,
  method,
  url,
  { dev, tok, body, headers = [], expect, tests = [], save = [], note } = {},
) {
  const h = [];
  if (tok) h.push({ key: "Authorization", value: `Bearer {{${tok}}}` });
  if (dev) h.push({ key: "X-Device-ID", value: dev });
  h.push(...headers);
  if (body !== undefined)
    h.push({ key: "Content-Type", value: "application/json" });
  const exec = [DEC];
  if (expect) {
    const list = Array.isArray(expect) ? expect : [expect];
    exec.push(
      `pm.test('Status ${list.join(" atau ")}', () => pm.expect(${JSON.stringify(list)}).to.include(pm.response.code));`,
    );
  }
  exec.push("let j = null; try { j = pm.response.json(); } catch (e) {}");
  save.forEach(([v, expr]) =>
    exec.push(`if (j) pm.collectionVariables.set('${v}', ${expr});`),
  );
  exec.push(...tests);
  return {
    name,
    event: [{ listen: "test", script: { type: "text/javascript", exec } }],
    request: {
      method,
      header: h,
      description: note,
      body:
        body !== undefined
          ? {
              mode: "raw",
              raw: JSON.stringify(body, null, 2),
              options: { raw: { language: "json" } },
            }
          : undefined,
      url,
    },
  };
}
const B = "{{base_url}}";
const D = {
  d1: "DEV-DOSEN-01",
  d2: "DEV-DOSEN-02",
  a: "DEV-ADMIN-01",
  m1: "DEV-MHS-01",
  m2: "DEV-MHS-02",
};
const login = (name, u, p, dev, tokVar, refVar, expect = 200) =>
  item(name, "POST", `${B}/auth/login`, {
    dev,
    body: { username: u, password: p },
    expect,
    save:
      expect === 200
        ? [
            [tokVar, "j.access_token"],
            ...(refVar ? [[refVar, "j.refresh_token"]] : []),
          ]
        : [],
    tests:
      expect === 200
        ? [
            "pm.test('JWT berisi sub & role, berlaku 10 menit', () => { const p = dec(j.access_token); pm.expect(p).to.have.property('sub'); pm.expect(p).to.have.property('role'); pm.expect(p.exp - p.iat).to.eql(600); });",
          ]
        : [],
  });

const folders = [
  [
    "0. Cek gateway",
    [item("Health gateway", "GET", `${B}/health`, { expect: 200 })],
  ],
  [
    "1. Autentikasi & token (4.1)",
    [
      login(
        "1.1 Login dosen1",
        "dosen1",
        "dosen123",
        D.d1,
        "token_dosen1",
        "refresh_dosen1",
      ),
      login("1.2 Login mhs1", "mhs1", "mhs123", D.m1, "token_mhs1"),
      login("1.3 Login admin1", "admin1", "admin123", D.a, "token_admin"),
      login(
        "1.4 Login password salah (401)",
        "mhs1",
        "salah",
        D.m1,
        null,
        null,
        401,
      ),
      login(
        "1.5 Login dari device tidak terdaftar (403)",
        "mhs1",
        "mhs123",
        D.d1,
        null,
        null,
        403,
      ),
      item("1.6 Refresh access token", "POST", `${B}/auth/refresh`, {
        body: { refresh_token: "{{refresh_dosen1}}" },
        expect: 200,
        save: [["token_dosen1", "j.access_token"]],
      }),
      item(
        "1.7 Refresh dengan token ngawur (401)",
        "POST",
        `${B}/auth/refresh`,
        { body: { refresh_token: "ngawur" }, expect: 401 },
      ),
      item(
        "1.8 Token service (client ID + secret)",
        "POST",
        `${B}/auth/service`,
        {
          body: {
            client_id: "service-nilai",
            client_secret: "nilai-client-secret-123",
          },
          expect: 200,
          save: [["token_service", "j.access_token"]],
          tests: [
            "pm.test('role=service, berlaku 5 menit', () => { const p = dec(j.access_token); pm.expect(p.role).to.eql('service'); pm.expect(p.exp - p.iat).to.eql(300); });",
          ],
        },
      ),
      item(
        "1.9 Token service dengan secret salah (401)",
        "POST",
        `${B}/auth/service`,
        {
          body: { client_id: "service-nilai", client_secret: "salah" },
          expect: 401,
        },
      ),
      login(
        "1.10 Login mhs2 (untuk uji logout)",
        "mhs2",
        "mhs123",
        D.m2,
        "token_mhs2",
        "refresh_mhs2",
      ),
      item("1.11 Logout (refresh token dicabut)", "POST", `${B}/auth/logout`, {
        body: { refresh_token: "{{refresh_mhs2}}" },
        expect: 200,
      }),
      item("1.12 Refresh setelah logout (401)", "POST", `${B}/auth/refresh`, {
        body: { refresh_token: "{{refresh_mhs2}}" },
        expect: 401,
      }),
    ],
  ],
  [
    "2. Gateway secret & verifikasi ulang di service (4.1)",
    [
      item(
        "2.1 Akses LANGSUNG ke Service Nilai :3001 tanpa secret (403)",
        "GET",
        "{{nilai_url}}/nilai",
        { tok: "token_mhs1", expect: 403 },
      ),
      item(
        "2.2 Akses LANGSUNG ke Service Transkrip :3002 tanpa secret (403)",
        "GET",
        "{{transkrip_url}}/transkrip/2470001",
        { tok: "token_mhs1", expect: 403 },
      ),
      item(
        "2.3 Secret benar, TANPA token (401)",
        "GET",
        "{{nilai_url}}/nilai",
        { headers: [{ key: "X-Gateway-Secret", value: GWS }], expect: 401 },
      ),
      item(
        "2.4 Secret benar, token palsu (401)",
        "GET",
        "{{nilai_url}}/nilai",
        {
          headers: [
            { key: "X-Gateway-Secret", value: GWS },
            {
              key: "Authorization",
              value:
                "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0Iiwicm9sZSI6Im1haGFzaXN3YSJ9.palsu",
            },
          ],
          expect: 401,
        },
      ),
    ],
  ],
  [
    "3. Kebijakan akses & device (4.2, 4.3)",
    [
      item("3.1 Tanpa token (401)", "GET", `${B}/nilai`, {
        dev: D.m1,
        expect: 401,
      }),
      item("3.2 Token valid, tanpa X-Device-ID (403)", "GET", `${B}/nilai`, {
        tok: "token_mhs1",
        expect: 403,
      }),
      item("3.3 Device milik user lain (403)", "GET", `${B}/nilai`, {
        tok: "token_mhs1",
        dev: D.d1,
        expect: 403,
      }),
      item("3.4 Mahasiswa lihat nilai sendiri", "GET", `${B}/nilai`, {
        tok: "token_mhs1",
        dev: D.m1,
        expect: 200,
        tests: [
          "pm.test('hanya nilai milik NIM 2470001', () => pm.expect(j.every(x => x.nim === '2470001')).to.be.true);",
        ],
      }),
      item(
        "3.5 Mahasiswa minta nilai NIM lain (403)",
        "GET",
        `${B}/nilai?nim=2470002`,
        { tok: "token_mhs1", dev: D.m1, expect: 403 },
      ),
      item(
        "3.6 Dosen lihat nilai kelas yang diampu",
        "GET",
        `${B}/nilai?kelas_id=1`,
        {
          tok: "token_dosen1",
          dev: D.d1,
          expect: 200,
          tests: [
            "pm.test('3 mahasiswa', () => pm.expect(j.length).to.eql(3));",
          ],
        },
      ),
      item(
        "3.7 Dosen lihat kelas dosen lain (403)",
        "GET",
        `${B}/nilai?kelas_id=2`,
        { tok: "token_dosen1", dev: D.d1, expect: 403 },
      ),
      item("3.8 Admin akses /nilai (403)", "GET", `${B}/nilai`, {
        tok: "token_admin",
        dev: D.a,
        expect: 403,
      }),
      item("3.9 Dosen ubah nilai kelasnya", "PUT", `${B}/nilai/1`, {
        tok: "token_dosen1",
        dev: D.d1,
        body: { nilai_angka: 90 },
        expect: 200,
      }),
      item(
        "3.10 Dosen ubah nilai kelas dosen lain (403)",
        "PUT",
        `${B}/nilai/4`,
        {
          tok: "token_dosen1",
          dev: D.d1,
          body: { nilai_angka: 90 },
          expect: 403,
        },
      ),
      item("3.11 Mahasiswa ubah nilai (403)", "PUT", `${B}/nilai/1`, {
        tok: "token_mhs1",
        dev: D.m1,
        body: { nilai_angka: 100 },
        expect: 403,
      }),
    ],
  ],
  [
    "4. Jam akses (4.3) - DEMO MANUAL",
    [
      item(
        "4.1 Ubah nilai (200 jika dalam jam akses, 403 jika di luar)",
        "PUT",
        `${B}/nilai/2`,
        {
          tok: "token_dosen1",
          dev: D.d1,
          body: { nilai_angka: 77 },
          expect: [200, 403],
          tests: [
            "if (pm.response.code === 403) pm.test('alasan penolakan = jam akses', () => pm.expect(j.reason).to.include('jam akses'));",
          ],
          note: "Demo: jalankan saat jam akses terbuka (200), edit policy-config.json jadi start/end 00:00 (simpan, tanpa restart), kirim lagi -> 403 alasan jam akses.",
        },
      ),
    ],
  ],
  [
    "5. Finalisasi & transkrip (4.2)",
    [
      item(
        "5.1 Finalisasi kelas dosen lain (403)",
        "POST",
        `${B}/kelas/2/finalisasi`,
        { tok: "token_dosen1", dev: D.d1, expect: 403 },
      ),
      item(
        "5.2 Mahasiswa memfinalisasi (403)",
        "POST",
        `${B}/kelas/1/finalisasi`,
        { tok: "token_mhs1", dev: D.m1, expect: 403 },
      ),
      item(
        "5.3 Dosen finalisasi kelasnya (sinkron ke transkrip)",
        "POST",
        `${B}/kelas/1/finalisasi`,
        {
          tok: "token_dosen1",
          dev: D.d1,
          expect: 200,
          tests: [
            "pm.test('3 nilai disinkron', () => pm.expect(j.jumlah_nilai).to.eql(3));",
          ],
          note: "Butuh jam akses terbuka.",
        },
      ),
      item("5.4 Finalisasi ulang (409)", "POST", `${B}/kelas/1/finalisasi`, {
        tok: "token_dosen1",
        dev: D.d1,
        expect: 409,
      }),
      item("5.5 Ubah nilai yang sudah final (403)", "PUT", `${B}/nilai/1`, {
        tok: "token_dosen1",
        dev: D.d1,
        body: { nilai_angka: 10 },
        expect: 403,
      }),
      item(
        "5.6 Mahasiswa lihat transkrip sendiri",
        "GET",
        `${B}/transkrip/2470001`,
        {
          tok: "token_mhs1",
          dev: D.m1,
          expect: 200,
          tests: [
            "pm.test('nilai final hasil sinkron = 90', () => { pm.expect(j.mata_kuliah.length).to.eql(1); pm.expect(j.mata_kuliah[0].nilai_angka).to.eql(90); });",
          ],
        },
      ),
      item(
        "5.7 Mahasiswa lihat transkrip NIM lain (403)",
        "GET",
        `${B}/transkrip/2470002`,
        { tok: "token_mhs1", dev: D.m1, expect: 403 },
      ),
      item(
        "5.8 Admin lihat transkrip mahasiswa mana pun",
        "GET",
        `${B}/transkrip/2470001`,
        { tok: "token_admin", dev: D.a, expect: 200 },
      ),
      item("5.9 Dosen lihat transkrip (403)", "GET", `${B}/transkrip/2470001`, {
        tok: "token_dosen1",
        dev: D.d1,
        expect: 403,
      }),
    ],
  ],
  [
    "6. Token service & sinkron (4.1, 4.2)",
    [
      item(
        "6.1 /transkrip/sinkron dengan token USER dosen (403)",
        "POST",
        `${B}/transkrip/sinkron`,
        {
          tok: "token_dosen1",
          dev: D.d1,
          body: { kelas_id: 1, items: [{ mahasiswa_id: 4, nilai_angka: 90 }] },
          expect: 403,
        },
      ),
      item(
        "6.2 /transkrip/sinkron dengan token SERVICE",
        "POST",
        `${B}/transkrip/sinkron`,
        {
          tok: "token_service",
          body: { kelas_id: 1, items: [{ mahasiswa_id: 4, nilai_angka: 90 }] },
          expect: 200,
          note: "Token service berlaku 5 menit; bila 401, jalankan ulang 1.8.",
        },
      ),
      item("6.3 Token service akses /nilai (403)", "GET", `${B}/nilai`, {
        tok: "token_service",
        expect: 403,
      }),
      item(
        "6.4 /transkrip/sinkron tanpa token (401)",
        "POST",
        `${B}/transkrip/sinkron`,
        { body: { kelas_id: 1, items: [] }, expect: 401 },
      ),
    ],
  ],
];

const col = {
  info: {
    name: "Sistem Nilai - Zero Trust",
    schema:
      "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    description:
      "Jalankan `npm run seed` lalu `npm start`. Kirim request berurutan dari atas (token tersimpan otomatis). Ulangi demo: `npm run seed` lagi.",
  },
  variable: [
    { key: "base_url", value: "http://localhost:3000" },
    { key: "nilai_url", value: "http://localhost:3001" },
    { key: "transkrip_url", value: "http://localhost:3002" },
    { key: "gateway_secret", value: "dev-gateway-secret-ganti-di-produksi" },
  ],
  item: folders.map(([name, items]) => ({ name, item: items })),
};
// Bentuk ekspor standar Postman (URL terurai, _postman_id, response[]) agar mudah diimpor.
function fixUrl(raw) {
  const [p, q] = raw.split("?");
  const i = p.indexOf("/");
  const host = i === -1 ? p : p.slice(0, i);
  const segs =
    i === -1
      ? []
      : p
          .slice(i + 1)
          .split("/")
          .filter(Boolean);
  const u = { raw, host: [host], path: segs };
  if (q)
    u.query = q.split("&").map((kv) => {
      const [key, value] = kv.split("=");
      return { key, value };
    });
  return u;
}
function walk(items) {
  for (const it of items) {
    if (it.item) {
      walk(it.item);
      continue;
    }
    it.request.url = fixUrl(it.request.url);
    it.response = [];
  }
}
walk(col.item);
col.info._postman_id = crypto.randomUUID();
const out = path.join(
  __dirname,
  "..",
  "postman",
  "sistem-nilai.postman_collection.json",
);
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(col, null, 2));
console.log(
  "Koleksi dibuat:",
  out,
  "-",
  folders.reduce((a, f) => a + f[1].length, 0),
  "request",
);
