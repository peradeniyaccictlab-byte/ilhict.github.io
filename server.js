/*
 * Interactive Learning Hub (ILH) - LAN server
 * Run on the teacher / Smart Board computer:   node server.js
 * Students open  http://<this-computer-IP>:3000  in any browser on the same network.
 * No npm packages needed (Node.js 14 or newer).
 *
 * Optional settings (environment variables): PORT (default 3000), MAX_UPLOAD_MB (default 4096)
 */
"use strict";
const http = require("http"), fs = require("fs"), path = require("path"), os = require("os"), crypto = require("crypto");

const PORT = +process.env.PORT || 3000;
const MAX = (+process.env.MAX_UPLOAD_MB || 4096) * 1024 * 1024;
const ROOT = __dirname, DATA_DIR = path.join(ROOT, "data"), UP_DIR = path.join(ROOT, "uploads");
const DB_FILE = path.join(DATA_DIR, "data.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UP_DIR, { recursive: true });

/* ---------- Data (saved to data/data.json, files saved to uploads/) ---------- */
let db = { subject: "Science", pin: "1234", classes: [], lessons: [] };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, "utf8"))); } catch (e) {}
function persist() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
persist();
let lastId = 0;
const newId = () => (lastId = Math.max(Date.now(), lastId + 1));

const MIME = { html: "text/html; charset=utf-8", htm: "text/html; charset=utf-8", pdf: "application/pdf",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp",
  mp4: "video/mp4", webm: "video/webm" };
const extOf = (n) => path.extname(String(n)).slice(1).toLowerCase();

/* ---------- Helpers ---------- */
const tokens = new Map();   // teacher session tokens -> expiry time
const fails = new Map();    // ip -> { n, until }  (PIN brute-force protection)

function send(res, code, obj, extra) {
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, extra));
  res.end(JSON.stringify(obj));
}
function readJson(req, limit) {
  return new Promise((ok, no) => {
    let n = 0; const chunks = [];
    req.on("data", (d) => { n += d.length; if (n > (limit || 1e6)) { no(new Error("Request too large")); req.destroy(); } else chunks.push(d); });
    req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { no(new Error("Bad request")); } });
    req.on("error", no);
  });
}
function authed(req) {
  const t = req.headers["x-token"], exp = t && tokens.get(t);
  if (exp && exp > Date.now()) return true;
  if (t) tokens.delete(t);
  return false;
}
function same(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function lanUrls() {
  const out = [];
  const ifs = os.networkInterfaces();
  Object.keys(ifs).forEach((k) => ifs[k].forEach((i) => {
    if (i.family === "IPv4" && !i.internal) out.push("http://" + i.address + ":" + PORT);
  }));
  return out;
}
function removeFile(l) { if (l && l.file) fs.unlink(path.join(UP_DIR, path.basename(l.file)), () => {}); }

function serveFile(req, res, fp) {
  fs.stat(fp, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end("Not found"); }
    const type = MIME[extOf(fp)] || "application/octet-stream";
    const h = { "Content-Type": type, "Accept-Ranges": "bytes", "X-Content-Type-Options": "nosniff" };
    if (fp.startsWith(UP_DIR) && type.startsWith("text/html"))   // uploaded pages run isolated from the app
      h["Content-Security-Policy"] = "sandbox allow-scripts allow-forms allow-popups allow-modals";
    const m = /bytes=(\d*)-(\d*)/.exec(req.headers.range || "");
    let stream;
    if (m && (m[1] || m[2])) {
      let s = m[1] ? +m[1] : Math.max(0, st.size - +m[2]), e = m[1] && m[2] ? +m[2] : st.size - 1;
      e = Math.min(e, st.size - 1);
      if (s > e) { res.writeHead(416, { "Content-Range": "bytes */" + st.size }); return res.end(); }
      res.writeHead(206, Object.assign(h, { "Content-Range": "bytes " + s + "-" + e + "/" + st.size, "Content-Length": e - s + 1 }));
      stream = fs.createReadStream(fp, { start: s, end: e });
    } else {
      res.writeHead(200, Object.assign(h, { "Content-Length": st.size }));
      stream = fs.createReadStream(fp);
    }
    stream.on("error", () => res.destroy());
    stream.pipe(res);
  });
}

/* ---------- Upload (streamed straight to disk, so big videos are fine) ---------- */
function handleUpload(req, res, u) {
  const cls = +u.searchParams.get("cls");
  const title = (u.searchParams.get("title") || "").trim().slice(0, 120);
  const name = (u.searchParams.get("name") || "").slice(0, 200);
  if (!db.classes.some((c) => c.id === cls) || !title) return send(res, 400, { error: "Choose a class and enter a title." });
  if (!MIME[extOf(name)]) return send(res, 400, { error: "Unsupported file type. Use PDF, HTML, PNG, JPG, GIF, WEBP or MP4." });
  const id = newId();
  const stored = id + "_" + name.replace(/[^\w.\-]+/g, "_");
  const fp = path.join(UP_DIR, stored);
  const ws = fs.createWriteStream(fp);
  let n = 0, dead = false;
  const fail = (code, msg) => {
    if (dead) return; dead = true;
    req.unpipe(ws); ws.destroy(); fs.unlink(fp, () => {});
    send(res, code, { error: msg }, { Connection: "close" });
    res.on("finish", () => req.destroy());
  };
  req.on("data", (d) => { n += d.length; if (n > MAX) fail(413, "File is too large (limit " + Math.round(MAX / 1048576) + " MB)."); });
  req.on("aborted", () => { dead = true; ws.destroy(); fs.unlink(fp, () => {}); });
  ws.on("error", () => fail(500, "Could not save the file on the server."));
  ws.on("finish", () => {
    if (dead) return;
    const lesson = { id, cls, title, type: "file", fileName: name, file: stored };
    db.lessons.push(lesson); persist();
    send(res, 200, lesson);
  });
  req.pipe(ws);
}

/* ---------- Routes ---------- */
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, "http://localhost"), p = u.pathname, M = req.method;

    if (M === "GET" && (p === "/" || p === "/index.html")) return serveFile(req, res, path.join(ROOT, "index.html"));
    if (M === "GET" && p.startsWith("/files/")) return serveFile(req, res, path.join(UP_DIR, path.basename(decodeURIComponent(p.slice(7)))));

    if (M === "GET" && p === "/api/data")
      return send(res, 200, { subject: db.subject, classes: db.classes, lessons: db.lessons, maxMb: Math.round(MAX / 1048576), urls: lanUrls() });

    if (M === "POST" && p === "/api/login") {
      const ip = req.socket.remoteAddress, f = fails.get(ip) || { n: 0, until: 0 };
      if (f.until > Date.now()) return send(res, 429, { error: "Too many wrong attempts. Please wait a minute." });
      const b = await readJson(req);
      if (same(b.pin || "", db.pin)) {
        fails.delete(ip);
        const t = crypto.randomBytes(24).toString("hex");
        tokens.set(t, Date.now() + 8 * 3600 * 1000);
        return send(res, 200, { token: t });
      }
      f.n++; if (f.n >= 5) { f.n = 0; f.until = Date.now() + 60000; }
      fails.set(ip, f);
      return send(res, 401, { error: "Incorrect PIN. Please try again." });
    }

    if (p.startsWith("/api/")) {
      if (!authed(req)) return send(res, 401, { error: "Please enter the teacher PIN again." });

      if (M === "POST" && p === "/api/upload") return handleUpload(req, res, u);

      if (M === "POST" && p === "/api/classes") {
        const name = String((await readJson(req)).name || "").trim().slice(0, 40);
        if (!name) return send(res, 400, { error: "Enter a class name." });
        if (db.classes.some((c) => c.name.toLowerCase() === name.toLowerCase())) return send(res, 400, { error: "This class already exists." });
        db.classes.push({ id: newId(), name }); persist();
        return send(res, 200, { ok: true });
      }
      let m = /^\/api\/classes\/(\d+)$/.exec(p);
      if (M === "DELETE" && m) {
        const id = +m[1];
        db.lessons.filter((l) => l.cls === id).forEach(removeFile);
        db.lessons = db.lessons.filter((l) => l.cls !== id);
        db.classes = db.classes.filter((c) => c.id !== id); persist();
        return send(res, 200, { ok: true });
      }
      if (M === "POST" && p === "/api/links") {
        const b = await readJson(req);
        const title = String(b.title || "").trim().slice(0, 120);
        let url = String(b.url || "").trim();
        if (!db.classes.some((c) => c.id === +b.cls) || !title || !url) return send(res, 400, { error: "Please fill in all fields." });
        if (b.type !== "web" && b.type !== "youtube") return send(res, 400, { error: "Bad link type." });
        if (/^\s*(javascript|data|vbscript):/i.test(url)) return send(res, 400, { error: "This link is not allowed." });
        if (!/^https?:\/\//i.test(url)) url = "https://" + url;
        db.lessons.push({ id: newId(), cls: +b.cls, title, type: b.type, path: url }); persist();
        return send(res, 200, { ok: true });
      }
      m = /^\/api\/lessons\/(\d+)$/.exec(p);
      if (M === "DELETE" && m) {
        const l = db.lessons.find((x) => x.id === +m[1]);
        removeFile(l);
        db.lessons = db.lessons.filter((x) => x !== l); persist();
        return send(res, 200, { ok: true });
      }
      if (M === "POST" && p === "/api/settings") {
        const b = await readJson(req);
        if (typeof b.subject === "string" && b.subject.trim()) db.subject = b.subject.trim().slice(0, 60);
        if (typeof b.pin === "string") {
          if (b.pin.trim().length < 4) return send(res, 400, { error: "PIN must be at least 4 characters." });
          db.pin = b.pin.trim().slice(0, 12);
        }
        persist();
        return send(res, 200, { ok: true });
      }
    }
    send(res, 404, { error: "Not found" });
  } catch (e) {
    if (!res.headersSent) send(res, 400, { error: e.message || "Bad request" });
  }
});

server.on("error", (e) => {
  console.error(e.code === "EADDRINUSE" ? "Port " + PORT + " is already in use. Close the other ILH window or set PORT=3001." : e.message);
  process.exit(1);
});
server.listen(PORT, "0.0.0.0", () => {
  console.log("\n  Interactive Learning Hub (ILH) is running\n");
  console.log("  Teacher / Smart Board : http://localhost:" + PORT);
  const l = lanUrls();
  console.log(l.length ? "  Students (same network):" : "  No network connection found.");
  l.forEach((x) => console.log("     " + x));
  console.log("\n  Keep this window open while lessons are being used. Press Ctrl+C to stop.\n");
});
