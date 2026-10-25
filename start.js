// Menjalankan gateway + kedua service sekaligus dalam satu terminal.
const { spawn } = require("child_process");
const path = require("path");

const procs = [
  ["service-transkrip", "service-transkrip/index.js"],
  ["service-nilai", "service-nilai/index.js"],
  ["gateway", "gateway/index.js"],
].map(([name, file]) => {
  const p = spawn(process.execPath, [path.join(__dirname, file)], {
    stdio: "inherit",
    env: process.env,
  });
  p.on("exit", (code) => {
    if (code) console.error(`[${name}] berhenti dengan kode ${code}`);
  });
  return p;
});

const stop = () => procs.forEach((p) => p.kill());
process.on("SIGINT", () => {
  stop();
  process.exit(0);
});
process.on("SIGTERM", () => {
  stop();
  process.exit(0);
});
