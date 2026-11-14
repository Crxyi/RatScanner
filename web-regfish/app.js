"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_EN = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };
const VERDICT = {
  MALICIOUS: ["Malicious", "Clear malware traits found. Do not run it and delete it from your mods/plugins folder. If you already ran it: change your passwords, log out of Minecraft/Discord sessions everywhere and check your PC."],
  SUSPICIOUS: ["Suspicious", "Strong signs of dangerous behaviour. Only run it if you trust the source and understand the flagged code."],
  CAUTION: ["Caution", "Some capabilities that could be abused, but no typical malware pattern. Usually harmless – have a quick look."],
  CLEAN: ["Clean", "No known malware patterns found. A static scan is no guarantee – only download files from sources you trust."]
};
const SOURCE_EN = { asm: "Bytecode", resource: "Resource", binary: "Binary", site: "Website" };
const DISCORD_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M20.3 4.4A19.8 19.8 0 0 0 15.4 3l-.6 1.3a18.3 18.3 0 0 0-5.6 0L8.6 3a19.7 19.7 0 0 0-4.9 1.5C.6 9.1-.3 13.6.1 18a19.9 19.9 0 0 0 6 3l1.3-2.1a12.9 12.9 0 0 1-2-.97l.5-.38a14.2 14.2 0 0 0 12.2 0l.5.38c-.64.38-1.3.7-2 .97l1.3 2.1a19.8 19.8 0 0 0 6-3c.5-5.1-.84-9.6-3.6-13.6ZM8 15.3c-1.2 0-2.2-1.1-2.2-2.4s1-2.4 2.2-2.4 2.2 1.1 2.2 2.4-1 2.4-2.2 2.4Zm8 0c-1.2 0-2.2-1.1-2.2-2.4s1-2.4 2.2-2.4 2.2 1.1 2.2 2.4-1 2.4-2.2 2.4Z"/></svg>';

let state = { me: null, report: null, live: false, sevOff: new Set(), busy: false, viewer: { cls: null, container: "", hits: [], hitIdx: -1 } };
let turnstileId = null;

/* ---------- basics ---------- */
function theme(t) {
  try { if (t) localStorage.setItem("rs-theme", t); t = t || localStorage.getItem("rs-theme"); } catch (e) {}
  if (t) document.documentElement.dataset.theme = t;
}
theme();
$("#themeBtn").onclick = () => theme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
function show(id) {
  $$("main.view").forEach(m => {
    const on = m.id === id, was = !m.classList.contains("hidden");
    m.classList.toggle("hidden", !on);
    if (on && !was) { m.classList.remove("enter"); void m.offsetWidth; m.classList.add("enter"); }
  });
  const route = { home: "#/", plans: "#/plans", leaderboard: "#/leaderboard", supporters: "#/supporters", how: "#/how" }[id];
  $$("nav a").forEach(a => a.classList.toggle("active", !!route && a.getAttribute("href") === route));
  window.scrollTo(0, 0);
}
function stagger(nodes, step = 35, max = 14) { nodes.forEach((n, i) => { n.classList.add("stagger"); n.style.animationDelay = Math.min(i, max) * step + "ms"; }); }
function countUp(el, to, ms = 1000) {
  const t0 = performance.now();
  const tick = t => { const k = Math.min(1, (t - t0) / ms); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 4))); if (k < 1) requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
}
window.addEventListener("scroll", () => $(".top").classList.toggle("scrolled", window.scrollY > 4), { passive: true });
function msg(text, err = true) { const m = $("#homeMsg"); m.textContent = text; m.className = "msg" + (err ? " err" : ""); }
async function api(path, opts) {
  const r = await fetch("/api/" + path, Object.assign({ credentials: "same-origin" }, opts || {}));
  let j = null;
  try { j = await r.json(); } catch (e) {}
  if (!r.ok) { const e = new Error((j && j.error) || ("HTTP " + r.status)); e.needLogin = j && j.needLogin; throw e; }
  return j;
}
const post = (path, body) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
function fmtSize(n) { return n >= 1073741824 ? (n / 1073741824).toFixed(2) + " GB" : n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(0) + " KB" : n + " B"; }
function shortCls(c) { return c ? c.replace(/\//g, ".") : ""; }
function extOf(name) { const m = /\.([a-z0-9]{1,5})$/i.exec(name || ""); return m ? m[1].toUpperCase() : "FILE"; }

/* ---------- account / turnstile ---------- */
async function loadMe() {
  try { state.me = await api("me.php"); } catch (e) { state.me = { loggedIn: false, discordEnabled: false, guestJarsPerDay: 5 }; }
  const me = state.me, a = $("#account");
  loginWall(me);
  if (me.loggedIn) {
    a.innerHTML = `<img src="${esc(me.user.avatar)}" alt=""><span class="who">${esc(me.user.name)}</span><button class="ghost small" id="logoutBtn">Log out</button>`;
    $("#logoutBtn").onclick = async () => { try { await post("logout.php"); } catch (e) {} loadMe(); };
  } else if (me.discordEnabled) {
    a.innerHTML = `<a class="btn-discord" href="/api/login.php" title="${me.joinsServer ? "Log in with Discord – you will also join our Discord server" : "Log in with Discord"}">${DISCORD_SVG}Log in</a>`;
  } else a.innerHTML = "";
  const q = $("#quota");
  if (me.loggedIn) q.innerHTML = `Logged in${me.user.plan ? ` · <b>${esc(me.user.plan)}</b>` : ""} – <b>${Math.max(0, me.user.limit - me.user.usedToday).toLocaleString("en-US")}</b> scans left today (.jar, .exe, .dll, scripts …).`;
  else q.innerHTML = `Without login: <b>${me.guestLeft ?? me.guestJarsPerDay} of ${me.guestJarsPerDay}</b> .jar scans left today.${me.discordEnabled ? ` <a href="/api/login.php">Log in with Discord</a> to scan .exe files and other programs and to get more scans.` : ""}`;
  const nav = $("#navDiscord");
  if (me.invite) { nav.href = me.invite; nav.classList.remove("hidden"); } else nav.classList.add("hidden");
  const foot = $("#discordInvite");
  if (foot) foot.innerHTML = me.invite ? `<a href="${esc(me.invite)}" target="_blank" rel="noopener noreferrer">Join our Discord</a>` : "";
  if (me.turnstileSiteKey && !window.turnstile) {
    const s = document.createElement("script");
    s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad";
    s.async = true;
    document.head.appendChild(s);
  }
}
window.onTurnstileLoad = () => {
  if (!state.me || !state.me.turnstileSiteKey) return;
  turnstileId = window.turnstile.render("#cfCheck", { sitekey: state.me.turnstileSiteKey, theme: document.documentElement.dataset.theme === "light" ? "light" : "dark", appearance: "interaction-only" });
};
async function turnstileToken() {
  if (!state.me || !state.me.turnstileSiteKey) return null;
  if (!window.turnstile || turnstileId === null) throw new Error("Security check is still loading – try again in a second.");
  for (let i = 0; i < 60; i++) { const t = window.turnstile.getResponse(turnstileId); if (t) return t; await new Promise(r => setTimeout(r, 250)); }
  throw new Error("Please complete the Cloudflare security check.");
}
function resetTurnstile() { try { if (window.turnstile && turnstileId !== null) window.turnstile.reset(turnstileId); } catch (e) {} }

/* ---------- scanning in a worker ---------- */
let worker = null, seq = 0;
const pending = new Map();
function makeEngine() {
  const queue = [];
  let port = null;
  const frame = document.createElement("iframe");
  frame.src = "/decompiler.html?v=15";
  frame.hidden = true; frame.tabIndex = -1; frame.setAttribute("aria-hidden", "true"); frame.style.display = "none";
  const eng = {
    onmessage: null, onerror: null,
    postMessage(m, t = []) { if (port) port.postMessage(m, t); else queue.push([m, t]); },
    terminate() { window.removeEventListener("message", onWin); try { if (port) port.close(); } catch (e) {} frame.remove(); }
  };
  function onWin(e) {
    if (e.source !== frame.contentWindow || e.origin !== location.origin || !e.data) return;
    if (e.data.type === "rs-engine" && e.ports[0]) {
      port = e.ports[0];
      port.onmessage = ev => eng.onmessage && eng.onmessage(ev);
      for (const [m, t] of queue) port.postMessage(m, t);
      queue.length = 0;
    } else if (e.data.type === "rs-engine-crash" && eng.onerror) eng.onerror({ message: e.data.error });
  }
  window.addEventListener("message", onWin);
  document.body.appendChild(frame);
  return eng;
}
function getWorker() {
  if (worker) return worker;
  worker = makeEngine();
  worker.onmessage = e => {
    const m = e.data;
    if (m.type === "progress") setProgress(m.stage, m.p);
    else if (m.type === "done") { const p = pending.get("scan"); pending.delete("scan"); if (p) p.resolve(m.report); }
    else if (m.type === "deepprogress") { state.deep = Object.assign({ status: "running" }, m); updateDeep(); }
    else if (m.type === "deepdone") onDeepDone(m.report);
    else if (m.type === "zip") { const p = pending.get(m.id); pending.delete(m.id); if (p) p.resolve(m.blob); }
    else if (m.type === "source") { const p = pending.get(m.id); pending.delete(m.id); if (p) p.resolve(m.source); }
    else if (m.type === "error" && m.id === "deep") { state.deep = { status: "error", error: m.error }; updateDeep(); }
    else if (m.type === "error") { const k = m.id ?? "scan"; const p = pending.get(k); pending.delete(k); if (p) p.reject(new Error(m.error)); }
  };
  worker.onerror = e => { const p = pending.get("scan"); pending.delete("scan"); if (p) p.reject(new Error(e.message || "Scanner crashed")); worker = null; };
  return worker;
}
function workerScan(buffer, name, sha256) {
  return new Promise((resolve, reject) => { pending.set("scan", { resolve, reject }); getWorker().postMessage({ cmd: "scan", buffer, name, sha256 }, [buffer]); });
}
function workerDisasm(container, cls, cmd = "disasm") {
  const id = ++seq;
  return new Promise((resolve, reject) => { pending.set(id, { resolve, reject }); getWorker().postMessage({ cmd, id, container, cls }); });
}
function softHash(alg, data) {
  const u = data instanceof Uint8Array ? data : new Uint8Array(data), n = u.length, sha1 = alg === "SHA-1";
  const words = ((n + 8) >> 6) + 1 << 4, W = new Uint32Array(words);
  for (let i = 0; i < n; i++) W[i >> 2] |= u[i] << (24 - (i & 3) * 8);
  W[n >> 2] |= 0x80 << (24 - (n & 3) * 8);
  W[words - 1] = (n * 8) >>> 0; W[words - 2] = Math.floor(n / 0x20000000);
  const rotl = (x, c) => (x << c) | (x >>> (32 - c)), rotr = (x, c) => (x >>> c) | (x << (32 - c)), w = new Uint32Array(sha1 ? 80 : 64);
  let H;
  if (sha1) {
    H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for (let o = 0; o < words; o += 16) {
      for (let t = 0; t < 80; t++) w[t] = t < 16 ? W[o + t] : rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
      let [a, b, c, d, e] = H;
      for (let t = 0; t < 80; t++) {
        const f = t < 20 ? (b & c) | (~b & d) : t < 40 ? b ^ c ^ d : t < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
        const k = t < 20 ? 0x5a827999 : t < 40 ? 0x6ed9eba1 : t < 60 ? 0x8f1bbcdc : 0xca62c1d6;
        const tmp = (rotl(a, 5) + f + e + k + w[t]) | 0; e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
      }
      H = [H[0] + a | 0, H[1] + b | 0, H[2] + c | 0, H[3] + d | 0, H[4] + e | 0];
    }
  } else {
    const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for (let o = 0; o < words; o += 16) {
      for (let t = 0; t < 64; t++) {
        if (t < 16) w[t] = W[o + t];
        else { const x = w[t - 15], y = w[t - 2]; w[t] = (w[t - 16] + (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) + w[t - 7] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10))) | 0; }
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let t = 0; t < 64; t++) {
        const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) | 0;
        const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H = H.map((v, i) => (v + [a, b, c, d, e, f, g, h][i]) | 0);
    }
  }
  return H.map(v => (v >>> 0).toString(16).padStart(8, "0")).join("");
}
async function sha256Hex(buf) { if (!(window.crypto && crypto.subtle)) return softHash("SHA-256", buf); const h = await crypto.subtle.digest("SHA-256", buf); return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, "0")).join(""); }
const MAX_FILE = 1024 * 1024 * 1024;
const isZip = u => u.length > 4 && u[0] === 0x50 && u[1] === 0x4b && (u[2] === 3 || u[2] === 5 || u[2] === 7);

async function scanBuffer(buffer, name) {
  if (state.busy) return;
  if (buffer.byteLength > MAX_FILE) { show("home"); return msg("File is larger than 1 GB."); }
  const u8 = new Uint8Array(buffer);
  const kind = isZip(u8) ? "jar" : "other";
  if (isGuest() && kind !== "jar") { show("home"); return gate(sniff(u8.subarray(0, 8), name).label); }
  if (state.deep && state.deep.status === "running" && worker) {
    worker.terminate(); worker = null;
    for (const p of pending.values()) p.reject(new Error("Cancelled"));
    pending.clear();
  }
  state.deep = null;
  state.busy = true;
  show("progress");
  $("#pFile").textContent = name + " · " + fmtSize(buffer.byteLength);
  $("#pExt").textContent = extOf(name);
  setProgress("Checking limits…", 1);
  try {
    const sha = await sha256Hex(buffer);
    const token = await turnstileToken();
    const q = await post("quota.php", { sha256: sha, kind, turnstile: token });
    resetTurnstile();
    const report = await workerScan(buffer, name, sha);
    state.report = report; state.live = true; state.quick = report; state.ticket = { ticket: q.ticket, sha256: sha, fileName: name };
    if (report.classCount > 0) { state.deep = { status: "running", phase: "deobfuscate", done: 0, total: 1 }; getWorker().postMessage({ cmd: "deep" }); }
    renderReport(report, true);
    post("record.php", { ticket: q.ticket, sha256: sha, fileName: name, verdict: report.verdict, score: report.score, type: report.type,
      findings: report.findings.slice(0, 40).map(f => ({ severity: f.severity, title: f.title, category: f.category })) }).catch(() => {}).then(loadMe);
  } catch (e) {
    resetTurnstile();
    show("home"); if (e.needLogin && kind !== "jar") gate(sniff(u8.subarray(0, 8), name).label); else msg(e.message);
    loadMe();
  } finally { state.busy = false; }
}
async function scanFile(f) { if (f) scanBuffer(await f.arrayBuffer(), f.name); }
$("#file").onchange = e => { const f = e.target.files[0]; e.target.value = ""; if (f && !state.busy) dfxIngest(f); };

/* ---------- drag & drop ---------- */
const dfx = $("#dragfx");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
const D = { on: false, depth: 0, raf: 0, parts: [], mx: innerWidth / 2, my: innerHeight / 2, cx: innerWidth / 2, cy: innerHeight / 2, lock: false, warnDrag: false, mode: "idle", hideT: 0, ctx: null, w: 0, h: 0, dpr: 1, color: "#fff", ok: "#3ddc97", warn: "#ff8a3d", seq: 0 };
const MIME_EXT = [[/java-archive|x-java/, "JAR"], [/msdownload|ms-dos|msdos|portable-executable|x-dosexec|x-executable/, "EXE"], [/x-msi|ms-installer/, "MSI"], [/zip/, "ZIP"], [/python/, "PY"], [/powershell/, "PS1"], [/x-sh|shellscript/, "SH"], [/bat|x-msdos-batch/, "BAT"], [/javascript/, "JS"], [/vbscript/, "VBS"]];
const isGuest = () => !!state.me && !state.me.loggedIn && !state.me.local;
let wallPoll = null;
function loginWall(me) {
  const need = !!(me && me.local && me.requireLogin && !me.loggedIn);
  let wall = $("#loginWall");
  document.body.classList.toggle("needs-login", need);
  if (!need) { if (wall) wall.remove(); clearInterval(wallPoll); wallPoll = null; return; }
  if (!wall) {
    wall = document.createElement("div");
    wall.id = "loginWall";
    wall.className = "login-wall";
    wall.innerHTML = `<div class="login-card"><div class="login-logo"><span class="brand-mark"></span></div>
      <h2>Log in to use RatScanner</h2><p>Sign in with your Discord account to start scanning. The login opens in your browser – come back here afterwards.</p>
      <a class="btn-discord big" id="wallLogin" href="/api/login.php">${DISCORD_SVG}Log in with Discord</a><p class="login-wait muted small hidden" id="wallWait">Waiting for Discord… finish the login in your browser.</p>
      ${me.invite ? `<p class="muted small">No account on our server yet? <a href="${esc(me.invite)}" target="_blank" rel="noopener noreferrer">Join our Discord</a></p>` : ""}</div>`;
    document.body.appendChild(wall);
    $("#wallLogin").addEventListener("click", () => { $("#wallWait").classList.remove("hidden"); });
  }
  if (!wallPoll) wallPoll = setInterval(() => { if (!document.hidden) loadMe(); }, 2500);
}
window.addEventListener("focus", () => { if (state.me && state.me.local) loadMe(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden && state.me && state.me.local) loadMe(); });

function dfxText(t) { $(".dfx-text").textContent = t; }
function dfxChip(t) { $(".dfx-chip-t").textContent = t || ""; }
function dfxMode(m) {
  D.mode = m;
  dfx.classList.toggle("warn", m === "warn" || (D.warnDrag && m !== "dropped"));
  dfx.classList.toggle("dropped", m === "dropped");
}
function dfxMeasure() {}
function dfxStart() {
  if (D.on) return;
  D.on = true; clearTimeout(D.hideT);
  dfx.classList.remove("hidden");
  requestAnimationFrame(() => dfx.classList.add("on"));
}
function dfxStop(delay = 0) {
  D.seq++;
  const go = () => {
    D.on = false; dfx.classList.remove("on");
    D.hideT = setTimeout(() => { dfx.classList.add("hidden"); D.warnDrag = false; dfxMode("idle"); dfxText("Drop to scan"); dfxChip(""); $(".dfx-ext").textContent = "FILE"; $(".dfx-sub").textContent = "Read as bytes only – never executed, never uploaded"; $("#drop").classList.remove("over"); }, 150);
  };
  delay ? setTimeout(go, delay) : go();
}
function dfxPointer() {}
function guessExt(e) {
  const it = e.dataTransfer && e.dataTransfer.items && e.dataTransfer.items[0];
  const t = (it && it.type || "").toLowerCase();
  for (const [re, x] of MIME_EXT) if (re.test(t)) return x;
  return "";
}
function sniff(u8, name) {
  const ext = (extOf(name) || "").toLowerCase(), b = i => u8[i], m = (...xs) => xs.every((x, i) => b(i) === x);
  if (m(0x50, 0x4b)) return { n: 2, label: ext === "jar" ? "Java archive" : ext === "mrpack" ? "Modpack" : "ZIP archive", zip: true };
  if (m(0x4d, 0x5a)) return { n: 2, label: ext === "dll" ? "Windows library (PE)" : "Windows program (PE)" };
  if (m(0x7f, 0x45, 0x4c, 0x46)) return { n: 4, label: "Linux program (ELF)" };
  if (m(0xca, 0xfe, 0xba, 0xbe)) return { n: 4, label: ext === "class" ? "Java class file" : "Mach-O universal binary" };
  if (m(0xcf, 0xfa, 0xed, 0xfe) || m(0xce, 0xfa, 0xed, 0xfe)) return { n: 4, label: "macOS program (Mach-O)" };
  if (m(0xd0, 0xcf, 0x11, 0xe0)) return { n: 4, label: "Installer / OLE file" };
  if (m(0x23, 0x21)) return { n: 2, label: "Script" };
  return { n: 0, label: ["bat", "cmd", "ps1", "vbs", "js", "py", "sh"].includes(ext) ? "Script" : "File" };
}
async function dfxIngest(f) {
  const my = ++D.seq;
  dfxStart();
  dfxMode("dropped");
  dfxText(f.name.length > 48 ? f.name.slice(0, 45) + "…" : f.name);
  $(".dfx-sub").textContent = fmtSize(f.size);
  $(".dfx-ext").textContent = (extOf(f.name) || "FILE").slice(0, 4);
  let head = new Uint8Array(0);
  try { head = new Uint8Array(await f.slice(0, 16).arrayBuffer()); } catch (e) {}
  if (my !== D.seq) return;
  const sn = sniff(head, f.name);
  const magic = sn.n ? [...head.slice(0, sn.n)].map(c => c.toString(16).padStart(2, "0").toUpperCase()).join(" ") : "";
  dfxChip(magic ? magic + "  ·  " + sn.label : sn.label);
  const blocked = isGuest() && !sn.zip && f.size <= MAX_FILE;
  await new Promise(r => setTimeout(r, reduceMotion ? 120 : blocked ? 500 : 420));
  if (my !== D.seq) return;
  if (blocked) {
    dfxMode("warn"); dfxText("Login required");
    $(".dfx-sub").textContent = "Programs and scripts need a free Discord login";
    await new Promise(r => setTimeout(r, reduceMotion ? 300 : 1100));
    if (my !== D.seq) return;
    dfxStop(); show("home"); gate(sn.label);
    return;
  }
  dfxStop();
  scanFile(f);
}
function gate(label) {
  const m = $("#homeMsg"), can = state.me && state.me.discordEnabled;
  m.className = "gate";
  m.innerHTML = `<div class="gate-ico">EXE</div><div class="gate-t"><b>${esc(label)} – log in to scan it</b><span>${can ? "Programs, DLLs and scripts are scanned for free with a Discord login. Without login you can scan 5 .jar files per day." : "Discord login is not available right now. Without login only .jar files can be scanned."}</span></div>${can ? `<a class="btn-discord" href="/api/login.php">${DISCORD_SVG}Log in with Discord</a>` : ""}`;
  m.scrollIntoView({ block: "nearest", behavior: reduceMotion ? "auto" : "smooth" });
}

const hasFiles = e => e.dataTransfer && [...(e.dataTransfer.types || [])].includes("Files");
const dropOk = () => $("#viewer").classList.contains("hidden") && !state.busy;
window.addEventListener("dragenter", e => {
  if (!hasFiles(e) || !dropOk()) return;
  e.preventDefault(); D.depth++;
  if (D.depth === 1 || !D.on) {
    dfxStart(); $("#drop").classList.add("over");
    const x = guessExt(e);
    $(".dfx-ext").textContent = x || "FILE";
    D.warnDrag = !!x && x !== "JAR" && x !== "ZIP" && isGuest();
    dfxMode("idle");
    dfxChip(D.warnDrag ? x + " needs a Discord login" : "");
    dfxText("Drop to scan");
  }
});
window.addEventListener("dragover", e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); e.dataTransfer.dropEffect = dropOk() ? "copy" : "none";
  if (D.on) dfxPointer(e.clientX, e.clientY);
});
window.addEventListener("dragleave", e => { if (!hasFiles(e)) return; D.depth = Math.max(0, D.depth - 1); if (D.depth === 0 && D.mode !== "dropped") dfxStop(); });
window.addEventListener("drop", e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); D.depth = 0;
  const f = e.dataTransfer.files[0];
  if (!f || !dropOk()) return dfxStop();
  D.warnDrag = false;
  dfxIngest(f, e.clientX, e.clientY);
});
window.addEventListener("resize", () => { if (D.on) dfxMeasure(); });

$("#urlForm").onsubmit = async e => {
  e.preventDefault();
  if (state.busy) return;
  show("progress");
  $("#pFile").textContent = $("#url").value;
  $("#pExt").textContent = extOf($("#url").value.split("?")[0]);
  setProgress("Downloading…", 1);
  try {
    const token = await turnstileToken();
    const r = await fetch("/api/fetch.php", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: $("#url").value, turnstile: token }) });
    resetTurnstile();
    if (!r.ok) { let j = null; try { j = await r.json(); } catch (x) {} throw new Error((j && j.error) || "Download failed (HTTP " + r.status + ")"); }
    if (/json/i.test(r.headers.get("Content-Type") || "")) return await scanSitePage(await r.json());
    const name = decodeURIComponent(r.headers.get("X-File-Name") || "download.jar");
    await scanBuffer(await r.arrayBuffer(), name);
  } catch (err) { resetTurnstile(); show("home"); msg(err.message); }
};
async function scanSitePage(data) {
  if (!data || data.kind !== "page") throw new Error((data && data.error) || "The server sent an unexpected answer.");
  setProgress("Checking the page…", 60);
  const report = await new Promise((resolve, reject) => { pending.set("scan", { resolve, reject }); getWorker().postMessage({ cmd: "site", data }); });
  state.deep = null; state.report = report; state.live = false; state.quick = null; state.ticket = null;
  renderSite(report);
}
function siteAge(created) {
  const t = Date.parse(created || ""); if (!Number.isFinite(t)) return null;
  const days = Math.floor((Date.now() - t) / 86400000);
  return days < 60 ? days + " days" : days < 730 ? Math.round(days / 30.4) + " months" : Math.round(days / 365.25) + " years";
}
function renderSite(r) {
  state.sevOff = new Set(["INFO"]);
  if (location.hash !== "#/report") history.pushState(null, "", "#/report");
  const v = VERDICT[r.verdict] || VERDICT.CLEAN, s = r.site || {};
  const sub = { CLEAN: "Nothing on this page looks like phishing, a scam or injected code.", CAUTION: "A few things worth a second look, but no typical attack pattern.", SUSPICIOUS: "Signs of phishing, fake downloads or tampering. Do not log in or download anything here.", MALICIOUS: "This page is built to steal accounts, money or install malware. Close it." }[r.verdict] || v[1];
  const fmtDate = d => { const t = Date.parse(d || ""); return Number.isFinite(t) ? new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : null; };
  const rows = [["Address", r.final], ["Opened", r.url !== r.final ? r.url : null], ["Status", s.status ? "HTTP " + s.status : null], ["Domain", s.domain],
    ["Registered", s.created ? fmtDate(s.created) + " · " + siteAge(s.created) + " ago" : "unknown"], ["Registrar", s.registrar], ["Certificate", s.cert ? (s.cert.issuer || "?") + (s.cert.to ? " · valid until " + (fmtDate(s.cert.to) || s.cert.to) : "") : (/^https:/.test(r.final || "") ? null : "none (no HTTPS)")],
    ["Server", [s.server, s.poweredBy].filter(Boolean).join(" · ") || null], ["Scripts", (s.scripts || []).length + " external · " + (s.inlineScripts || 0) + " inline"], ["Forms", s.forms ? s.forms + (s.passwordFields ? " · " + s.passwordFields + " password field" + (s.passwordFields > 1 ? "s" : "") : "") : null]]
    .filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const el = $("#report");
  el.innerHTML = `
  <section class="verdict v-${r.verdict}">
    <div class="vring" id="vring"><div><b>${r.score}</b><span>RISK</span></div></div>
    <div><div class="fname">${esc(s.host || r.fileName)}${r.title ? " · " + esc(r.title) : ""}</div><div class="vlabel">${v[0]}</div><div class="vsub">${esc(sub)}</div>
      <div class="note">Website check – the page was downloaded as text on our server and read here. Nothing from it was run or shown.</div></div>
    <div class="vactions"><button class="ghost" id="dlJson" type="button">JSON report</button><button class="ghost" id="newScan">New scan</button></div>
  </section>
  ${behaviorPanel(r, "What this site does", "Checked: domain age and look-alike names, redirects, login forms and where they send data, fake captchas (ClickFix), wallet drainers, fake updates and downloads, hidden or injected code and every string in its JavaScript.")}
  <div class="sevbar" id="sevbar">${SEV.map(x => `<span class="sevchip s-${x}${state.sevOff.has(x) ? " off" : ""}" data-s="${x}"><i></i>${SEV_EN[x]} <b>${r.severityCounts[x] || 0}</b></span>`).join("")}</div>
  <div class="rgrid">
    <div class="panel"><h2>Findings <small id="fcount"></small></h2><div class="findings" id="findings"></div></div>
    <div class="side-stack">
      <div class="panel"><h2>Site</h2><dl class="kv">${rows.map(([k, x]) => `<dt>${k}</dt><dd${k === "Address" || k === "Opened" ? ' class="mono"' : ""}>${esc(x)}</dd>`).join("")}</dl></div>
      ${(s.chain || []).length > 1 ? `<div class="panel"><h2>Redirects <small>${s.chain.length - 1}</small></h2><ol class="chain">${s.chain.map(c => `<li><code>${esc(c.url)}</code><span>${c.code || ""}</span></li>`).join("")}</ol></div>` : ""}
      ${(r.downloads || []).length ? `<div class="panel"><h2>Downloads on this page <small>${r.downloads.length}</small></h2><table class="tbl dl-tbl">${r.downloads.slice(0, 25).map((d, i) => `<tr><td><b>${esc(d.name || d.host)}</b><br><span class="muted small">${esc(d.host)}${d.filehost ? " · file host" : ""}</span></td><td><button class="small ghost" data-dl="${i}" type="button">Scan</button></td></tr>`).join("")}</table></div>` : ""}
      ${(s.scripts || []).length ? `<div class="panel"><h2>Scripts <small>${s.scripts.length}</small></h2><table class="tbl">${s.scripts.slice(0, 30).map(x => `<tr><td class="mono">${esc(x.url.replace(/^https?:\/\//, "").slice(0, 70))}</td><td>${x.status === "checked" ? fmtSize(x.size) : esc(x.status)}</td></tr>`).join("")}</table></div>` : ""}
    </div>
  </div>`;
  const ring = $("#vring");
  requestAnimationFrame(() => requestAnimationFrame(() => ring.style.setProperty("--p", r.score)));
  countUp($("#vring b"), r.score);
  stagger($$("#report .side-stack > .panel"), 60, 8);
  $("#newScan").onclick = () => { location.hash = "#/"; };
  $("#dlJson").onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }));
    a.download = "ratscan-site-" + (s.host || "page").replace(/[^a-z0-9.-]/gi, "_") + ".json";
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  $$("[data-dl]").forEach(b => b.onclick = () => { const d = r.downloads[+b.dataset.dl]; location.hash = "#/"; $("#url").value = d.url; setTimeout(() => $("#urlForm").requestSubmit(), 50); });
  $$("#sevbar .sevchip").forEach(c => c.onclick = () => { const k = c.dataset.s; state.sevOff.has(k) ? state.sevOff.delete(k) : state.sevOff.add(k); c.classList.toggle("off"); renderFindings(false); });
  renderFindings(false);
  show("report");
}
$("#hashForm").onsubmit = async e => {
  e.preventDefault();
  try {
    const j = await api("lookup.php?sha256=" + encodeURIComponent($("#hash").value.trim().toLowerCase()));
    if (!j.found) return msg("This hash has not been scanned here yet. Drop the file to check it.", false);
    renderSaved(j.report);
  } catch (err) { msg(err.message); }
};

function setProgress(stage, p) {
  $("#pStage").textContent = stage;
  $("#pBar").style.width = Math.max(2, p) + "%";
  const keys = $$("#pSteps li").map(li => li.dataset.k.split("|"));
  let cur = keys.findIndex(ks => ks.some(k => stage.startsWith(k)));
  if (stage === "Done") cur = keys.length;
  $$("#pSteps li").forEach((li, i) => { li.classList.toggle("done", cur >= 0 && i < cur); li.classList.toggle("on", i === cur); });
}

/* ---------- leaderboard / plans / supporters ---------- */
async function renderLeaderboard() {
  show("leaderboard");
  const list = $("#lbList"), me = $("#lbMe");
  list.innerHTML = `<li class="skeleton"></li>`.repeat(4);
  try {
    const j = await api("leaderboard.php");
    const myName = state.me && state.me.loggedIn ? state.me.user.username : null;
    if (state.me && state.me.loggedIn) { const u = state.me.user; me.innerHTML = u.rank ? `You are <b>#${u.rank}</b> with <b>${u.files}</b> different files (${u.scans} scans).` : `You have not scanned anything yet – drop a file to get on the board.`; }
    else if (state.me && state.me.discordEnabled) me.innerHTML = `<a class="btn-discord" href="/api/login.php">${DISCORD_SVG}Log in with Discord</a> to appear on the leaderboard.${state.me.joinsServer ? " Logging in also adds you to our Discord server." : ""}`;
    else me.innerHTML = "";
    list.innerHTML = j.entries.length ? j.entries.map(e => `<li class="${e.username === myName ? "me" : ""}"><span class="rk">#${e.rank}</span><img src="${esc(e.avatar)}" alt="" loading="lazy">
      <span class="nm">${esc(e.name)}<small>@${esc(e.username)}</small></span><span class="ct"><b>${e.files}</b><small>files · ${e.scans} scans</small></span></li>`).join("")
      : `<li><span class="muted">Nobody on the board yet. Be the first!</span></li>`;
    stagger($$("li", list), 40);
  } catch (e) { list.innerHTML = `<li><span class="muted">${esc(e.message)}</span></li>`; }
}
async function renderPlans() {
  show("plans");
  stagger($$("#plans .plan"), 80);
  try {
    const info = await api("plans.php");
    for (const p of info.plans) { const el = $("#lim-" + p.id); if (el) el.textContent = p.perDay >= 100000 ? "Unlimited" : p.perDay.toLocaleString("en-US"); }
    $("#limGuest").textContent = info.guest; $("#limFree").textContent = info.freeUser;
    const inv = info.invite || (state.me && state.me.invite) || "";
    $$("#plans .discord-link, #plans .plan-btn").forEach(a => { if (inv) { a.href = inv; a.target = "_blank"; a.rel = "noopener noreferrer"; } });
    $("#plansContact").textContent = info.contact || "Open a ticket or message the team there and tell them which plan you want.";
  } catch (e) {}
}
async function renderSupporters() {
  show("supporters");
  const list = $("#supList");
  list.innerHTML = `<li class="skeleton"></li>`.repeat(3);
  try {
    const j = await api("supporters.php");
    list.innerHTML = j.entries.length ? j.entries.map((e, i) => `<li class="plan-${esc(String(e.plan).toLowerCase())}"><span class="rk">${i + 1}</span><img src="${esc(e.avatar)}" alt="" loading="lazy">
      <span class="nm">${esc(e.name)}<small>@${esc(e.username)}</small></span><span class="ct"><span class="tier">${esc(e.plan)}</span></span></li>`).join("")
      : `<li><span class="muted">No supporters yet – <a href="#/plans">get a plan</a> and be the first.</span></li>`;
    stagger($$("li", list), 40);
  } catch (e) { list.innerHTML = `<li><span class="muted">${esc(e.message)}</span></li>`; }
}

function route() {
  closeViewer();
  const h = location.hash;
  if (h === "#/how") return show("how");
  if (h === "#/leaderboard") return renderLeaderboard();
  if (h === "#/plans") return renderPlans();
  if (h === "#/supporters") return renderSupporters();
  if (h === "#/report" && state.report) return renderReport(state.report, state.live);
  show("home");
  if (h === "#/login-failed") msg("Discord login failed. Please try again.");
}
window.addEventListener("hashchange", route);

/* ---------- report ---------- */
function renderSaved(r) {
  const v = VERDICT[r.verdict] || VERDICT.CLEAN;
  const el = $("#report");
  el.innerHTML = `<section class="verdict v-${esc(r.verdict)}">
    <div class="vring" id="vring"><div><b>${+r.score || 0}</b><span>RISK</span></div></div>
    <div><div class="fname">${esc(r.file_name)} · ${esc(r.type)}</div><div class="vlabel">${v[0]}</div><div class="vsub">${v[1]}</div>
      <div class="note">Saved result from ${new Date(r.first_seen * 1000).toLocaleDateString("en-GB")} · scanned ${r.submissions}× · Drop the file to see every detail and the code.</div></div>
    <div class="vactions"><button class="ghost" id="newScan">New scan</button></div></section>
  <div class="rgrid"><div class="panel"><h2>Top findings</h2><div class="findings">${(r.summary || []).length ? r.summary.map(f => `<div class="finding s-${esc(f.severity)}"><div class="sum-row"><span class="sev">${SEV_EN[f.severity] || ""}</span><div><div class="ftitle">${esc(f.title)}</div><div class="fmeta">${esc(f.category)}</div></div></div></div>`).join("") : `<div class="empty">No findings.</div>`}</div></div>
  <div class="side-stack"><div class="panel"><h2>File</h2><dl class="kv"><dt>SHA-256</dt><dd class="mono">${esc(r.sha256)}</dd></dl></div></div></div>`;
  const ring = $("#vring");
  requestAnimationFrame(() => requestAnimationFrame(() => ring.style.setProperty("--p", +r.score || 0)));
  $("#newScan").onclick = () => { location.hash = "#/"; };
  show("report");
}
function renderReport(r, live) {
  state.sevOff = new Set(["INFO"]);
  if (location.hash !== "#/report") history.pushState(null, "", "#/report");
  const v = VERDICT[r.verdict] || VERDICT.CLEAN, meta = r.meta || {}, title = meta.name || r.fileName;
  const hasCode = live && r.classes && r.classes.length > 0;
  const rows = [["Type", r.type], ["Name", meta.name], ["ID", meta.id], ["Version", meta.version], ["Authors", meta.authors], ["Size", fmtSize(r.size)],
    ["Classes", r.classCount || null], ["Archives", r.containers.length > 1 ? r.containers.length : null], ["Files", r.resourceCount || null], ["Duration", (r.durationMs / 1000).toFixed(1) + " s"]]
    .filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const el = $("#report");
  el.innerHTML = `
  <section class="verdict v-${r.verdict}">
    <div class="vring" id="vring"><div><b>${r.score}</b><span>RISK</span></div></div>
    <div><div class="fname">${esc(r.fileName)}${title !== r.fileName ? " · " + esc(title) : ""}</div><div class="vlabel">${v[0]}</div><div class="vsub">${v[1]}</div>
      ${r.obfuscated ? `<div class="note">The file is obfuscated – hidden features are possible even if little was found.</div>` : ""}</div>
    <div class="vactions">${hasCode ? `<button id="openCode">View code</button>` : ""}${hasCode ? `<button class="ghost" id="dlSrc" type="button">Download deobfuscated source (.zip)</button>` : ""}<button class="ghost" id="dlJson" type="button">JSON report</button><button class="ghost" id="newScan">New scan</button></div>
  </section>
  ${hasCode ? `<section class="deep" id="deepBox"></section>` : ""}
  ${behaviorPanel(r)}
  <div class="sevbar" id="sevbar">${SEV.map(s => `<span class="sevchip s-${s}${state.sevOff.has(s) ? " off" : ""}" data-s="${s}"><i></i>${SEV_EN[s]} <b>${r.severityCounts[s] || 0}</b></span>`).join("")}</div>
  <div class="rgrid">
    <div class="panel"><h2>Findings <small id="fcount"></small></h2><div class="findings" id="findings"></div></div>
    <div class="side-stack">
      <div class="panel"><h2>File</h2><dl class="kv">${rows.map(([k, x]) => `<dt>${k}</dt><dd>${esc(x)}</dd>`).join("")}<dt>SHA-256</dt><dd class="mono">${esc(r.hashes.sha256)}</dd><dt>SHA-1</dt><dd class="mono">${esc(r.hashes.sha1)}</dd></dl></div>
      ${r.binary ? binaryPanel(r.binary) : ""}
      ${r.capabilities.length || !r.binary ? `<div class="panel"><h2>Capabilities <small>own classes</small></h2><div class="caps">${r.capabilities.length ? r.capabilities.map(c => `<span class="cap" title="${esc(c.category)}"><b>${esc(c.label)}</b> · ${c.classes}</span>`).join("") : `<span class="muted small">No special capabilities.</span>`}</div></div>` : ""}
      ${r.entrypoints.length ? `<div class="panel"><h2>Entrypoints</h2><table class="tbl">${r.entrypoints.slice(0, 30).map(e => { const i = e.indexOf(":"); return `<tr><td>${esc(e.slice(i + 1).trim())}</td><td>${esc(e.slice(0, i))}</td></tr>`; }).join("")}</table></div>` : ""}
      ${r.containers.length > 1 ? `<div class="panel"><h2>Nested archives <small>${r.containers.length - 1}</small></h2><table class="tbl">${r.containers.slice(1, 60).map(c => `<tr><td>${esc(c.path)}</td><td>${c.classes} cl.</td></tr>`).join("")}</table></div>` : ""}
    </div>
  </div>`;
  const ring = $("#vring");
  requestAnimationFrame(() => requestAnimationFrame(() => ring.style.setProperty("--p", r.score)));
  countUp($("#vring b"), r.score);
  stagger($$("#report .side-stack > .panel"), 60, 8);
  $("#newScan").onclick = () => { location.hash = "#/"; };
  if (hasCode) $$("#report .bh[data-cls]").forEach(li => { const c = (r.classes || []).find(x => x.n === li.dataset.cls || li.dataset.cls.startsWith(x.n + "$")); if (c) { li.classList.add("bh-link"); li.title = "Show in code"; li.onclick = () => openViewer([c.n, c.c]); } });
  if ($("#dlSrc")) $("#dlSrc").onclick = async () => {
    const b = $("#dlSrc"), label = b.textContent;
    b.disabled = true; b.textContent = state.deep && state.deep.status === "done" ? "Packing ZIP…" : "Waiting for the deep scan…";
    try {
      const id = ++seq;
      const blob = await new Promise((resolve, reject) => { pending.set(id, { resolve, reject }); getWorker().postMessage({ cmd: "srczip", id, name: r.fileName, report: r }); });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = (r.fileName || "file").replace(/\.[a-z0-9]{1,5}$/i, "") + "-deobfuscated-source.zip";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    } catch (e) { alert(e.message); }
    finally { b.disabled = false; b.textContent = label; }
  };
  $("#dlJson").onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }));
    a.download = "ratscan-" + r.hashes.sha256.slice(0, 12) + ".json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  if (hasCode) $("#openCode").onclick = () => openViewer(firstFlagged(), "");
  $$("#sevbar .sevchip").forEach(c => c.onclick = () => { const s = c.dataset.s; state.sevOff.has(s) ? state.sevOff.delete(s) : state.sevOff.add(s); c.classList.toggle("off"); renderFindings(hasCode); });
  renderFindings(hasCode);
  show("report");
  updateDeep();
}
const fmtN = n => (n || 0).toLocaleString("en-US");
function behaviorPanel(r, heading = "What happens when you run it", note = null) {
  const list = r.behavior || [];
  if (!list.length) return "";
  const bad = list.filter(b => b.hit && b.bad).length, hits = list.filter(b => b.hit);
  const site = r.kind === "site";
  const head = bad ? `${bad} thing${bad > 1 ? "s" : ""} you would not want ${site ? "from a website" : "on your PC"}` : site ? "Nothing dangerous found on this page" : hits.length ? "Nothing that installs itself or opens your PC was found" : "Nothing found that it would do outside the game";
  const row = b => `<li class="bh ${b.hit ? (b.bad ? "bh-bad" : "bh-info") : "bh-no"}"${b.hit && b.cls ? ` data-cls="${esc(b.cls)}"` : ""}><i></i><div><b>${esc(b.hit ? b.label : b.none)}</b>${b.hit ? `<span>${esc(b.why || "")}${b.cls ? ` · <code>${esc(b.cls.split("/").pop())}</code>` : ""}</span>` : ""}</div></li>`;
  const order = [...list.filter(b => b.hit && b.bad), ...list.filter(b => b.hit && !b.bad), ...list.filter(b => !b.hit)];
  return `<section class="behave${bad ? " behave-bad" : ""}"><div class="behave-h"><h2>${esc(heading)}</h2><span>${esc(head)}</span></div>
    <ul class="behave-list">${order.map(row).join("")}</ul>
    <p class="behave-note">${esc(note || "Worked out from the code without running it – install steps, autostart, backdoors, tunnels and system changes are looked for in every class" + (r.deep ? " and every decompiled line" : "") + ".")}</p></section>`;
}
function updateDeep() {
  const box = $("#deepBox");
  if (!box) return;
  const d = state.deep;
  if (!d) { box.classList.add("hidden"); return; }
  box.className = "deep deep-" + d.status;
  if (d.status === "error") { box.innerHTML = `<div class="deep-h"><b>Deep scan stopped</b><span>${esc(d.error)}</span></div>`; return; }
  if (d.status === "running") {
    const pct = d.total ? Math.round(100 * d.done / d.total) : 0;
    const text = d.phase === "deobfuscate"
      ? `Deobfuscating – emulating string decryption · ${fmtN(d.done)} / ${fmtN(d.total)} classes`
      : `Decompiling with Vineflower and reading every line · ${fmtN(d.done)} / ${fmtN(d.total)} classes · ${fmtN(d.lines)} lines read${d.decrypted ? ` · ${fmtN(d.decrypted)} hidden strings decrypted` : ""}`;
    let bar = $(".deep-bar > div", box);
    if (!bar) { box.innerHTML = `<div class="deep-h"><b>Deep scan running</b><span class="deep-t"></span></div><div class="deep-bar"><div></div></div>`; bar = $(".deep-bar > div", box); }
    $(".deep-t", box).textContent = text;
    bar.style.width = (d.phase === "deobfuscate" ? pct * 0.1 : 10 + pct * 0.9) + "%";
    return;
  }
  const st = (state.report && state.report.deep) || {};
  const pct = st.classes ? Math.round(100 * st.decompiled / st.classes) : 100;
  const changed = d.from && state.report && d.from !== state.report.verdict ? `<span class="deep-change">Verdict changed: ${esc(VERDICT[d.from][0])} → ${esc(VERDICT[state.report.verdict][0])}</span>` : "";
  box.innerHTML = `<div class="deep-h"><b>Deep scan complete</b><span>Deobfuscated, decompiled and every line read.</span>${changed}</div>
    <dl class="deep-stats">
      <div><dt>Classes decompiled</dt><dd>${fmtN(st.decompiled)} / ${fmtN(st.classes)} <small>${pct}%</small></dd></div>
      <div><dt>Lines read</dt><dd>${fmtN(st.lines)}</dd></div>
      <div><dt>Hidden strings decrypted</dt><dd>${fmtN(st.decrypted)}</dd></div>
      <div><dt>Decryptor methods</dt><dd>${fmtN((st.decryptors || []).length)}</dd></div>
    </dl>${st.failed ? `<p class="deep-note">${fmtN(st.failed)} classes could not be decompiled – their bytecode was read instead.</p>` : ""}`;
}
function onDeepDone(report) {
  const before = state.report, y = window.scrollY, quick = state.quick || before;
  state.deep = { status: "done", from: quick && quick.verdict };
  if (!before || !state.live || before.hashes.sha256 !== report.hashes.sha256) return;
  state.report = report;
  const off = new Set(state.sevOff);
  const onReport = !$("#report").classList.contains("hidden");
  renderReport(report, true);
  state.sevOff = off;
  $$("#sevbar .sevchip").forEach(c => c.classList.toggle("off", off.has(c.dataset.s)));
  renderFindings(true);
  if (onReport) window.scrollTo(0, y);
  if (!viewer.classList.contains("hidden")) renderTabs();
  const rank = { CLEAN: 0, CAUTION: 1, SUSPICIOUS: 2, MALICIOUS: 3 };
  if (state.ticket && quick && (rank[report.verdict] > rank[quick.verdict] || report.score > quick.score)) {
    post("record.php", Object.assign({}, state.ticket, { upgrade: true, verdict: report.verdict, score: report.score, type: report.type,
      findings: report.findings.slice(0, 40).map(f => ({ severity: f.severity, title: f.title, category: f.category })) })).catch(() => {});
  }
}
function binaryPanel(b) {
  const rows = [["Format", b.format], ["Architecture", b.arch], ["Subsystem", b.subsystem], ["Compiled", b.compiled], ["Imports", b.importCount], ["Overlay", b.overlay ? fmtSize(b.overlay) : null], ["Strings", b.strings]].filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const secs = (b.sections || []).map(s => `<tr><td>${esc(s.name)}</td><td>${fmtSize(s.size)}</td><td class="${s.entropy > 7.2 ? "hot" : ""}">${s.entropy}</td></tr>`).join("");
  const imps = Object.entries(b.imports || {}).map(([dll, fns]) => `<details><summary>${esc(dll)} <span class="muted">(${fns.length})</span></summary><div>${esc(fns.join(", "))}</div></details>`).join("");
  return `<div class="panel"><h2>Program</h2><dl class="kv">${rows.map(([k, x]) => `<dt>${k}</dt><dd>${esc(x)}</dd>`).join("")}</dl>
    ${(b.notes || []).length ? `<div class="caps mt">${b.notes.map(n => `<span class="cap"><b>${esc(n)}</b></span>`).join("")}</div>` : ""}
    ${(b.capabilities || []).length ? `<div class="note">Uses: ${esc(b.capabilities.join(" · "))}</div>` : ""}</div>
    ${secs ? `<div class="panel"><h2>Sections</h2><table class="bin-sec"><tr><th>Name</th><th>Size</th><th>Entropy</th></tr>${secs}</table></div>` : ""}
    ${imps ? `<div class="panel imports"><h2>Imports</h2>${imps}</div>` : ""}`;
}
function firstFlagged() {
  const f = state.report.findings.find(f => f.cls && !f.cls.startsWith("res:") && !f.cls.startsWith("file:") && state.report.classes.some(c => c.n === f.cls || f.cls.startsWith(c.n + "$")));
  return f ? [f.cls, f.container || ""] : state.report.classes.length ? [state.report.classes[0].n, state.report.classes[0].c] : [null, ""];
}
function renderFindings(canView) {
  const r = state.report, list = r.findings.filter(f => !state.sevOff.has(f.severity));
  $("#fcount").textContent = list.length + " of " + r.findings.length;
  const box = $("#findings");
  if (!list.length) { box.innerHTML = `<div class="empty">${r.findings.length ? "All findings are filtered out." : "No findings. 🎉"}</div>`; return; }
  box.innerHTML = list.slice(0, 400).map((f, i) => {
    const where = f.cls ? shortCls(f.cls) + (f.method ? " · " + f.method.replace(/\(.*$/, "()") : "") : (f.evidence || "");
    const tags = [];
    if (f.entrypoint) tags.push("Entrypoint"); if (f.library) tags.push("Library"); if (f.occurrences > 1) tags.push(f.occurrences + "×");
    if (f.source && f.source !== "asm") tags.push(SOURCE_EN[f.source] || f.source);
    const rel = f.related && f.related.length ? `<div class="related">${f.related.map(x => `<div>• <b>${esc(x.label)}</b>${x.cls ? ` in <code>${esc(shortCls(x.cls))}</code>` : ""}${x.evidence ? `: <code>${esc(x.evidence)}</code>` : ""}</div>`).join("")}</div>` : "";
    const canOpen = canView && f.cls && !f.cls.startsWith("res:") && !f.cls.startsWith("file:") && r.classes.some(c => c.n === f.cls || f.cls.startsWith(c.n + "$"));
    return `<details class="finding s-${f.severity}" ${i < 3 && f.severity !== "INFO" ? "open" : ""}>
      <summary><span class="sev">${SEV_EN[f.severity]}</span><div><div class="ftitle">${esc(f.title)}</div><div class="fmeta">${esc(f.category)} · ${esc(where)}</div></div><div class="ftags">${tags.map(t => `<span class="tagp">${esc(t)}</span>`).join("")}</div></summary>
      <div class="fbody"><p>${esc(f.description)}</p>${f.evidence && !rel ? `<div class="ev">${esc(f.evidence)}</div>` : ""}${rel}
      <div class="loc">${f.container ? `<span>${esc(f.container)}</span>` : ""}${f.line ? `<span>line ${f.line}</span>` : ""}${canOpen ? `<button class="small ghost" data-open="${i}">Show in code →</button>` : ""}</div></div>
    </details>`;
  }).join("") + (list.length > 400 ? `<div class="empty">… ${list.length - 400} more (see JSON report)</div>` : "");
  stagger($$(".finding", box));
  $$("[data-open]", box).forEach(b => b.onclick = () => { const f = list[+b.dataset.open]; openViewer([f.cls, f.container || ""], f); });
}

/* ---------- bytecode viewer ---------- */
const viewer = $("#viewer");
function renderTabs() {
  const java = state.deep && state.deep.status === "done";
  if (!java) state.viewer.engine = "asm";
  else if (!state.viewer.engine) state.viewer.engine = "java";
  $("#tabs").innerHTML = (java ? `<button data-e="java" class="${state.viewer.engine === "java" ? "on" : ""}">Java · deobfuscated</button>` : "") + `<button data-e="asm" class="${state.viewer.engine === "asm" ? "on" : ""}">Bytecode</button>`;
  $$("#tabs button").forEach(b => b.onclick = () => { state.viewer.engine = b.dataset.e; renderTabs(); loadClass(state.viewer.cls, state.viewer.container); });
}
function openViewer([cls, container], focus) { if (!cls) return; state.viewer.engine = null; renderTabs(); viewer.classList.remove("hidden"); document.body.style.overflow = "hidden"; renderTree(); loadClass(cls, container, focus); }
function closeViewer() { viewer.classList.add("hidden"); document.body.style.overflow = ""; }
$("#closeViewer").onclick = closeViewer;
document.addEventListener("keydown", e => {
  if (viewer.classList.contains("hidden")) return;
  if (e.key === "Escape") closeViewer();
  if (e.key === "n" && document.activeElement.tagName !== "INPUT") stepHit(1);
  if (e.key === "N" && document.activeElement.tagName !== "INPUT") stepHit(-1);
});
$("#treeFilter").oninput = renderTree;
$("#onlyFlagged").onchange = renderTree;
$("#prevHit").onclick = () => stepHit(-1);
$("#nextHit").onclick = () => stepHit(1);
function renderTree() {
  const r = state.report, q = $("#treeFilter").value.trim().toLowerCase(), only = $("#onlyFlagged").checked;
  let items = r.classes.filter(c => (!only || c.s) && (!q || c.n.toLowerCase().includes(q)));
  items.sort((a, b) => (a.c + a.n).localeCompare(b.c + b.n));
  const total = items.length;
  items = items.slice(0, 3000);
  let html = "", lastPkg = null;
  for (const c of items) {
    const i = c.n.lastIndexOf("/"), pkg = (c.c ? c.c + " › " : "") + (i > 0 ? c.n.slice(0, i).replace(/\//g, ".") : "(default)");
    if (pkg !== lastPkg) { html += `<div class="tree-pkg">${esc(pkg)}</div>`; lastPkg = pkg; }
    const active = c.n === state.viewer.cls && c.c === state.viewer.container ? " active" : "";
    const badges = [c.entry ? "entry" : "", c.hidden ? "disguised" : "", c.lib ? "lib" : ""].filter(Boolean).join(" ");
    html += `<div class="tree-item${c.s ? " s-" + c.s : ""}${active}" data-n="${esc(c.n)}" data-c="${esc(c.c)}" title="${esc(c.n)}"><i></i>${esc(c.n.slice(i + 1))}${badges ? ` <em>${badges}</em>` : ""}</div>`;
  }
  if (!total) html = `<div class="tree-pkg">No classes${only ? " – turn off “flagged only”" : ""}.</div>`;
  if (total > 3000) html += `<div class="tree-pkg">… ${total - 3000} more – use the filter</div>`;
  const list = $("#treeList");
  list.innerHTML = html;
  $$(".tree-item", list).forEach(t => t.onclick = () => loadClass(t.dataset.n, t.dataset.c));
}
function topOf(cls, container) {
  let i = cls.indexOf("$");
  while (i > 0) { const cand = cls.slice(0, i); if (state.report.classes.some(c => c.n === cand && c.c === container)) return cand; i = cls.indexOf("$", i + 1); }
  return cls;
}
function classFindings(cls, container) {
  const top = topOf(cls, container);
  return state.report.findings.filter(f => f.cls && (f.container || "") === container && (f.cls === top || f.cls.startsWith(top + "$") || (f.related || []).some(x => x.cls === top)));
}
let loadSeq = 0;
async function loadClass(cls, container, focus) {
  const v = state.viewer;
  v.cls = topOf(cls, container); v.container = container;
  $("#crumb").textContent = (container ? container + " › " : "") + shortCls(v.cls);
  $$(".tree-item").forEach(t => t.classList.toggle("active", t.dataset.n === v.cls && t.dataset.c === container));
  const fs = classFindings(v.cls, container);
  $("#classFindings").innerHTML = fs.map((f, i) => `<span class="cf s-${f.severity}" data-i="${i}">${esc(SEV_EN[f.severity])} · ${esc(f.title)}</span>`).join("");
  $$("#classFindings .cf").forEach(c => c.onclick = () => jumpTo(needlesOf([fs[+c.dataset.i]])));
  const java = v.engine === "java";
  $("#code").innerHTML = `<span class="loading">${java ? "Loading Java source…" : "Reading bytecode…"}</span>`;
  const id = ++loadSeq;
  try { const src = await workerDisasm(container, v.cls, java ? "java" : "disasm"); if (id === loadSeq) renderCode(src, fs, focus); }
  catch (e) { if (id === loadSeq) $("#code").innerHTML = `<span class="loading">Error: ${esc(e.message)}</span>`; }
}
function needlesOf(fs) {
  const out = [];
  const add = (s, sev) => { if (!s) return; s = String(s).replace(/^\[[^\]]+\]\s*/, "").replace(/…$/, ""); if (s.length > 40) s = s.slice(0, 40); if (s.length >= 5) out.push({ s, sev }); };
  for (const f of fs) { add(f.needle, f.severity); add(f.evidence, f.severity); for (const x of f.related || []) { add(x.needle, f.severity); add(x.evidence, f.severity); } }
  return out;
}
function tokenize(src) {
  const re = /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*")|\b([A-Z][A-Z0-9_]{2,})\b|(\b-?\d+\b)|(L[\w\/$]+;)|\b(public|private|protected|static|final|class|interface|enum|extends|implements|import|package|return|new|if|else|for|while|do|switch|case|default|break|continue|try|catch|finally|throw|throws|void|int|long|boolean|char|byte|short|float|double|this|super|null|true|false|instanceof|synchronized|abstract|native|var|record|yield)\b/g;
  const toks = []; let last = 0, m;
  while ((m = re.exec(src))) { if (m.index > last) toks.push([null, src.slice(last, m.index)]); toks.push([m[1] ? "c" : m[2] ? "s" : m[3] ? "o" : m[4] ? "n" : m[6] ? "k" : "t", m[0]]); last = re.lastIndex; }
  if (last < src.length) toks.push([null, src.slice(last)]);
  return toks;
}
function renderCode(src, fs, focus) {
  const lines = [[]];
  for (const [c, text] of tokenize(src)) text.split("\n").forEach((p, i) => { if (i > 0) lines.push([]); if (p) lines[lines.length - 1].push(c ? `<span class="t-${c}">${esc(p)}</span>` : esc(p)); });
  const raw = src.split("\n"), needles = needlesOf(fs), rank = s => SEV.indexOf(s), hits = [];
  const html = lines.map((parts, i) => {
    let best = null;
    for (const n of needles) if ((raw[i] || "").includes(n.s) && (best === null || rank(n.sev) < rank(best))) best = n.sev;
    if (best) hits.push(i);
    return `<span class="l${best ? " hit s-" + best : ""}">${parts.join("")}</span>`;
  }).join("");
  const code = $("#code");
  code.innerHTML = html; code.scrollTop = 0;
  state.viewer.hits = hits; state.viewer.hitIdx = -1;
  if (focus) jumpTo(needlesOf([focus])); else if (hits.length) stepHit(1); else $("#hitInfo").textContent = "0 hits";
}
function jumpTo(needles) {
  const v = state.viewer, lines = $$("#code .l");
  for (let k = 0; k < v.hits.length; k++) if (needles.some(n => lines[v.hits[k]].textContent.includes(n.s))) { v.hitIdx = k - 1; stepHit(1); return; }
  if (v.hits.length) stepHit(1);
}
function stepHit(d) {
  const v = state.viewer;
  if (!v.hits.length) return;
  v.hitIdx = (v.hitIdx + d + v.hits.length) % v.hits.length;
  const lines = $$("#code .l");
  $$("#code .l.cur").forEach(l => l.classList.remove("cur"));
  const el = lines[v.hits[v.hitIdx]];
  el.classList.add("cur"); el.scrollIntoView({ block: "center" });
  $("#hitInfo").textContent = `${v.hitIdx + 1}/${v.hits.length}`;
}

api("stats.php").then(s => { $("#stats").textContent = `${s.scanned.toLocaleString("en-US")} files scanned`; }).catch(() => {});
loadMe().then(route);
