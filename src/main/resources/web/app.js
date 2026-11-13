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
const SOURCE_EN = { asm: "ASM", vineflower: "Vineflower", cfr: "CFR", decompiler: "Decompiler", resource: "Resource", binary: "Binary" };
const DISCORD_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M20.3 4.4A19.8 19.8 0 0 0 15.4 3l-.6 1.3a18.3 18.3 0 0 0-5.6 0L8.6 3a19.7 19.7 0 0 0-4.9 1.5C.6 9.1-.3 13.6.1 18a19.9 19.9 0 0 0 6 3l1.3-2.1a12.9 12.9 0 0 1-2-.97l.5-.38a14.2 14.2 0 0 0 12.2 0l.5.38c-.64.38-1.3.7-2 .97l1.3 2.1a19.8 19.8 0 0 0 6-3c.5-5.1-.84-9.6-3.6-13.6ZM8 15.3c-1.2 0-2.2-1.1-2.2-2.4s1-2.4 2.2-2.4 2.2 1.1 2.2 2.4-1 2.4-2.2 2.4Zm8 0c-1.2 0-2.2-1.1-2.2-2.4s1-2.4 2.2-2.4 2.2 1.1 2.2 2.4-1 2.4-2.2 2.4Z"/></svg>';

let state = { me: null, report: null, sevOff: new Set(), viewer: { cls: null, container: "", engine: "vineflower", hits: [], hitIdx: -1 } };
let pollTimer = null;
let turnstileId = null;

function theme(t) {
  try { if (t) localStorage.setItem("rs-theme", t); t = t || localStorage.getItem("rs-theme"); } catch (e) {}
  if (t) document.documentElement.dataset.theme = t;
}
theme();
$("#themeBtn").onclick = () => theme(document.documentElement.dataset.theme === "light" ? "dark" : "light");

function show(id) {
  $$("main.view").forEach(m => {
    const on = m.id === id;
    const was = !m.classList.contains("hidden");
    m.classList.toggle("hidden", !on);
    if (on && !was) { m.classList.remove("enter"); void m.offsetWidth; m.classList.add("enter"); }
  });
  const route = { home: "#/", plans: "#/plans", leaderboard: "#/leaderboard", supporters: "#/supporters", how: "#/how" }[id];
  $$("nav a").forEach(a => a.classList.toggle("active", !!route && a.getAttribute("href") === route));
  window.scrollTo(0, 0);
}
function stagger(nodes, step = 35, max = 14) {
  nodes.forEach((n, i) => { n.classList.add("stagger"); n.style.animationDelay = Math.min(i, max) * step + "ms"; });
}
function countUp(el, to, ms = 1000) {
  const t0 = performance.now();
  const tick = t => { const k = Math.min(1, (t - t0) / ms); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 4))); if (k < 1) requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
}
window.addEventListener("scroll", () => $(".top").classList.toggle("scrolled", window.scrollY > 4), { passive: true });
function msg(text, err = true) {
  const m = $("#homeMsg");
  m.textContent = text;
  m.className = "msg" + (err ? " err" : "");
}
async function api(url, opts) {
  const r = await fetch(url, opts);
  let j = null;
  try { j = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((j && j.error) || ("HTTP " + r.status));
  return j;
}
function fmtSize(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(0) + " KB" : n + " B"; }
function shortCls(c) { return c ? c.replace(/\//g, ".") : ""; }
function ownerOf(id) { try { return JSON.parse(localStorage.getItem("rs-owner") || "{}")[id] || null; } catch (e) { return null; } }
function rememberOwner(id, token) {
  if (!token) return;
  try {
    const m = JSON.parse(localStorage.getItem("rs-owner") || "{}");
    m[id] = token;
    const keys = Object.keys(m);
    if (keys.length > 50) delete m[keys[0]];
    localStorage.setItem("rs-owner", JSON.stringify(m));
  } catch (e) {}
}
function extOf(name) { const m = /\.([a-z0-9]{1,5})$/i.exec(name || ""); return m ? m[1].toUpperCase() : "FILE"; }

/* ---------- account / turnstile ---------- */
async function loadMe() {
  try { state.me = await api("/api/me"); } catch (e) { state.me = { loggedIn: false, discordEnabled: false }; }
  const a = $("#account");
  const me = state.me;
  if (me.loggedIn) {
    a.innerHTML = `<img src="${esc(me.user.avatar)}" alt=""><span class="who">${esc(me.user.name)}</span><button class="ghost small" id="logoutBtn">Log out</button>`;
    $("#logoutBtn").onclick = async () => { await fetch("/auth/logout", { method: "POST" }); loadMe(); };
  } else if (me.discordEnabled) {
    a.innerHTML = `<a class="btn-discord" href="/auth/login" title="${me.joinsServer ? "Log in with Discord – you will also join our Discord server" : "Log in with Discord"}">${DISCORD_SVG}Log in</a>`;
  } else a.innerHTML = "";
  const q = $("#quota");
  if (me.loggedIn) q.innerHTML = `Logged in – you can scan <b>.jar</b>, <b>.exe</b>, <b>.dll</b>, scripts and more.`;
  else q.innerHTML = `Without login: <b>${me.anonJarsLeft ?? me.anonJarsPerDay} of ${me.anonJarsPerDay}</b> .jar scans left today.${me.discordEnabled ? ` <a href="/auth/login">Log in with Discord</a> to scan .exe files and other programs and to get more scans.` : ""}`;
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
  turnstileId = window.turnstile.render("#cfCheck", {
    sitekey: state.me.turnstileSiteKey,
    theme: document.documentElement.dataset.theme === "light" ? "light" : "dark",
    appearance: "interaction-only"
  });
};
async function turnstileToken() {
  if (!state.me || !state.me.turnstileSiteKey) return null;
  if (!window.turnstile || turnstileId === null) throw new Error("Security check is still loading – try again in a second.");
  for (let i = 0; i < 60; i++) {
    const t = window.turnstile.getResponse(turnstileId);
    if (t) return t;
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error("Please complete the Cloudflare security check.");
}
function resetTurnstile() { try { if (window.turnstile && turnstileId !== null) window.turnstile.reset(turnstileId); } catch (e) {} }
function needLogin() {
  if (state.me && state.me.requireLogin && !state.me.loggedIn) { msg("Please log in with Discord to scan files."); return true; }
  return false;
}

/* ---------- upload ---------- */
async function uploadFile(f) {
  if (!f) return;
  if (needLogin()) { show("home"); return; }
  if (f.size > 100 * 1024 * 1024) { show("home"); return msg("File is larger than 100 MB."); }
  if (state.me && !state.me.loggedIn && !/\.(jar|zip|litemod)$/i.test(f.name)) {
    show("home");
    return msg(state.me.discordEnabled ? "Log in with Discord (top right) to scan .exe, .dll, scripts and other programs. Without login you can scan .jar files." : "Only .jar files can be scanned on this server.");
  }
  let token = null;
  try { token = await turnstileToken(); } catch (e) { show("home"); return msg(e.message); }
  show("progress");
  $("#pFile").textContent = f.name + " · " + fmtSize(f.size);
  $("#pExt").textContent = extOf(f.name);
  setProgress("Uploading…", 1);
  try {
    const full = $("#full").checked ? "1" : "0";
    const headers = { "Content-Type": "application/octet-stream" };
    if (token) headers["X-Turnstile-Token"] = token;
    const j = await api(`/api/scan?name=${encodeURIComponent(f.name)}&full=${full}`, { method: "POST", body: f, headers });
    rememberOwner(j.id, j.owner);
    location.hash = "#/scan/" + j.id;
  } catch (e) { show("home"); msg(e.message); }
  finally { resetTurnstile(); loadMe(); }
}
$("#file").onchange = e => { uploadFile(e.target.files[0]); e.target.value = ""; };

/* drag & drop animation */
const dragfx = $("#dragfx");
let dragDepth = 0;
function dragShow(on) { dragfx.classList.toggle("hidden", !on); if (on) dragfx.classList.remove("dropped"); $("#drop").classList.toggle("over", on); }
const hasFiles = e => e.dataTransfer && [...(e.dataTransfer.types || [])].includes("Files");
window.addEventListener("dragenter", e => {
  if (!hasFiles(e) || !$("#viewer").classList.contains("hidden")) return;
  e.preventDefault(); dragDepth++; dragShow(true);
});
window.addEventListener("dragover", e => { if (hasFiles(e)) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } });
window.addEventListener("dragleave", e => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (dragDepth === 0) dragShow(false); });
window.addEventListener("drop", e => {
  if (!hasFiles(e)) return;
  e.preventDefault(); dragDepth = 0;
  const f = e.dataTransfer.files[0];
  if (!f) return dragShow(false);
  dragfx.classList.add("dropped");
  $(".dragfx-text").textContent = "Scanning " + f.name;
  setTimeout(() => { dragShow(false); $(".dragfx-text").textContent = "Drop to scan"; uploadFile(f); }, 520);
});

$("#urlForm").onsubmit = async e => {
  e.preventDefault();
  if (needLogin()) return;
  let token = null;
  try { token = await turnstileToken(); } catch (err) { return msg(err.message); }
  show("progress");
  $("#pFile").textContent = $("#url").value;
  $("#pExt").textContent = extOf($("#url").value.split("?")[0]);
  setProgress("Downloading…", 1);
  try {
    const j = await api("/api/scan-url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: $("#url").value, full: $("#full").checked, turnstile: token }) });
    rememberOwner(j.id, j.owner);
    location.hash = "#/scan/" + j.id;
  } catch (err) { show("home"); msg(err.message); }
  finally { resetTurnstile(); }
};
$("#hashForm").onsubmit = async e => {
  e.preventDefault();
  try {
    const j = await api("/api/hash/" + $("#hash").value.trim().toLowerCase());
    if (!j.found) {
      msg(j.knownBad ? "⚠ This hash is on the list of known malware – but it was not scanned here yet." : "This hash has not been scanned here yet. Upload the file to check it.", !!j.knownBad);
      return;
    }
    if (j.live) { location.hash = "#/scan/" + j.report.id; return; }
    renderReport(j.report, false);
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
async function poll(id) {
  clearTimeout(pollTimer);
  try {
    const j = await api("/api/job/" + id);
    if (location.hash !== "#/scan/" + id) return;
    if (j.status === "done") { renderReport(j.report, true); loadMe(); return; }
    if (j.status === "error") { show("home"); msg("Scan failed: " + j.error); return; }
    show("progress");
    $("#pFile").textContent = j.fileName;
    $("#pExt").textContent = extOf(j.fileName);
    setProgress(j.stage, j.progress);
    pollTimer = setTimeout(() => poll(id), 600);
  } catch (e) { show("home"); msg(e.message); }
}

/* ---------- leaderboard ---------- */
async function renderLeaderboard() {
  show("leaderboard");
  const list = $("#lbList"), me = $("#lbMe");
  list.innerHTML = `<li class="skeleton"></li>`.repeat(4);
  try {
    const j = await api("/api/leaderboard");
    const myName = state.me && state.me.loggedIn ? state.me.user.username : null;
    if (state.me && state.me.loggedIn) {
      const u = state.me.user;
      me.innerHTML = u.rank ? `You are <b>#${u.rank}</b> with <b>${u.files}</b> different files (${u.scans} scans).` : `You have not scanned anything yet – drop a file to get on the board.`;
    } else if (state.me && state.me.discordEnabled) {
      me.innerHTML = `<a class="btn-discord" href="/auth/login">${DISCORD_SVG}Log in with Discord</a> to appear on the leaderboard.${state.me.joinsServer ? " Logging in also adds you to our Discord server." : ""}`;
    } else {
      me.innerHTML = `Discord login is not set up on this server yet (DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET).`;
    }
    list.innerHTML = j.entries.length ? j.entries.map(e => `<li class="${e.username === myName ? "me" : ""}">
      <span class="rk">#${e.rank}</span><img src="${esc(e.avatar)}" alt="" loading="lazy">
      <span class="nm">${esc(e.name)}<small>@${esc(e.username)}</small></span>
      <span class="ct"><b>${e.files}</b><small>files · ${e.scans} scans</small></span></li>`).join("")
      : `<li><span class="muted">Nobody on the board yet. Be the first!</span></li>`;
    stagger($$("li", list), 40);
  } catch (e) { list.innerHTML = `<li><span class="muted">${esc(e.message)}</span></li>`; }
}

function route() {
  closeViewer();
  const h = location.hash;
  if (h.startsWith("#/scan/")) { poll(h.slice(7)); return; }
  if (h === "#/how") { show("how"); return; }
  if (h === "#/leaderboard") { renderLeaderboard(); return; }
  if (h === "#/plans") { renderPlans(); return; }
  if (h === "#/supporters") { renderSupporters(); return; }
  show("home");
  if (h === "#/login-failed") msg("Discord login failed. Please try again.");
}
window.addEventListener("hashchange", route);

/* ---------- plans ---------- */
async function renderPlans() {
  show("plans");
  stagger($$("#plans .plan"), 80);
  try {
    const info = await api("/api/plans");
    for (const p of info.plans) { const el = $("#lim-" + p.id); if (el) el.textContent = p.apiPerDay.toLocaleString("en-US"); }
    const inv = info.invite || (state.me && state.me.invite) || "";
    $$("#plans .discord-link, #plans .plan-btn").forEach(a => { if (inv) { a.href = inv; a.target = "_blank"; a.rel = "noopener noreferrer"; } });
    $("#plansContact").textContent = info.contact ? info.contact : "Open a ticket or message the team there and tell them which plan you want.";
  } catch (e) {}
  $$("#plans .origin").forEach(s => s.textContent = location.origin);
  renderApiAccount();
}
function renderApiAccount() {
  const box = $("#apiAccount");
  const me = state.me;
  if (!me || !me.loggedIn) {
    box.innerHTML = me && me.discordEnabled ? `<p><a class="btn-discord" href="/auth/login">${DISCORD_SVG}Log in with Discord</a> to see your plan and create an API key.</p>` : `<p class="muted">Discord login is not set up on this server.</p>`;
    return;
  }
  const u = me.user;
  box.innerHTML = `<dl class="kv"><dt>Plan</dt><dd>${u.plan ? `<b>${esc(u.plan)}</b>` : "No plan"}</dd>
    <dt>API today</dt><dd>${u.apiUsedToday} / ${u.apiBudget} scans</dd>
    <dt>Key</dt><dd class="mono">${u.apiKeyPrefix ? esc(u.apiKeyPrefix) + "…" : "none"}</dd></dl>
    <div class="row mt"><button id="newKey">${u.apiKeyPrefix ? "Create new key" : "Create API key"}</button>${u.apiKeyPrefix ? `<button class="ghost" id="delKey">Revoke key</button>` : ""}</div>
    <div id="keyOut"></div>`;
  $("#newKey").onclick = async () => {
    if (u.apiKeyPrefix && !confirm("Create a new key? The old one stops working immediately.")) return;
    try {
      const j = await api("/api/key", { method: "POST" });
      await loadMe();
      renderApiAccount();
      $("#keyOut").innerHTML = `<p class="note">Copy your key now – it is only shown once:</p><div class="ev" id="keyVal"></div>`;
      $("#keyVal").textContent = j.key;
    } catch (e) { $("#keyOut").textContent = e.message; }
  };
  const del = $("#delKey");
  if (del) del.onclick = async () => { if (!confirm("Revoke your API key?")) return; await api("/api/key", { method: "DELETE" }); await loadMe(); renderApiAccount(); };
}
async function renderSupporters() {
  show("supporters");
  const list = $("#supList");
  list.innerHTML = `<li class="skeleton"></li>`.repeat(3);
  try {
    const j = await api("/api/supporters");
    list.innerHTML = j.entries.length ? j.entries.map((e, i) => `<li class="plan-${esc(e.plan.toLowerCase())}">
      <span class="rk">${i + 1}</span><img src="${esc(e.avatar)}" alt="" loading="lazy">
      <span class="nm">${esc(e.name)}<small>@${esc(e.username)}</small></span>
      <span class="ct"><span class="tier">${esc(e.plan)}</span></span></li>`).join("")
      : `<li><span class="muted">No supporters yet – <a href="#/plans">get a plan</a> and be the first.</span></li>`;
    stagger($$("li", list), 40);
  } catch (e) { list.innerHTML = `<li><span class="muted">${esc(e.message)}</span></li>`; }
}

/* ---------- report ---------- */
function renderReport(r, live) {
  state.report = r;
  state.sevOff = new Set(["INFO"]);
  const v = VERDICT[r.verdict] || VERDICT.CLEAN;
  const meta = r.meta || {};
  const title = meta.name || r.fileName;
  const owned = !!ownerOf(r.id) || (state.me && state.me.loggedIn);
  const hasCode = live && owned && r.classes && r.classes.length > 0;
  const metaRows = [
    ["Type", r.type], ["Name", meta.name], ["ID", meta.id], ["Version", meta.version], ["Authors", meta.authors],
    ["Size", fmtSize(r.size)], ["Classes", r.classCount || null], ["Archives", r.containers.length > 1 ? r.containers.length : null], ["Files", r.resourceCount || null],
    ["Duration", (r.durationMs / 1000).toFixed(1) + " s"]
  ].filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const engines = r.engines || {};
  const engLine = (k, label) => {
    const e = engines[k] || {};
    const st = { ok: "done", budget: "time limit – rest on demand", timeout: "time limit", error: "partial errors", "on-demand": "on demand" }[e.status] || e.status || "–";
    const n = e.classes !== undefined ? e.classes + " classes · " : "";
    return `<div class="engine-row"><span>${label}</span><span>${n}${esc(st)}</span></div>`;
  };
  const el = $("#report");
  el.innerHTML = `
  <section class="verdict v-${r.verdict}">
    <div class="vring" id="vring"><div><b>${r.score}</b><span>RISK</span></div></div>
    <div>
      <div class="fname">${esc(r.fileName)}${title !== r.fileName ? " · " + esc(title) : ""}</div>
      <div class="vlabel">${v[0]}</div>
      <div class="vsub">${v[1]}</div>
      ${r.obfuscated ? `<div class="note">The file is obfuscated – hidden features are possible even if little was found.</div>` : ""}
    </div>
    <div class="vactions">
      ${hasCode ? `<button id="openCode">View code</button>` : ""}
      ${!live ? `<span class="note">Saved report – upload the file again to view its code.</span>` : ""}
      ${live && !owned && r.classes && r.classes.length ? `<span class="note">Only the uploader can view the code.</span>` : ""}
      ${live ? `<a href="/api/job/${encodeURIComponent(r.id)}/report.json"><button class="ghost" type="button">JSON report</button></a>` : ""}
      <button class="ghost" id="newScan">New scan</button>
    </div>
  </section>
  <div class="sevbar" id="sevbar">${SEV.map(s => `<span class="sevchip s-${s}${state.sevOff.has(s) ? " off" : ""}" data-s="${s}"><i></i>${SEV_EN[s]} <b>${r.severityCounts[s] || 0}</b></span>`).join("")}</div>
  <div class="rgrid">
    <div class="panel"><h2>Findings <small id="fcount"></small></h2><div class="findings" id="findings"></div></div>
    <div class="side-stack">
      <div class="panel"><h2>File</h2><dl class="kv">${metaRows.map(([k, x]) => `<dt>${k}</dt><dd>${esc(x)}</dd>`).join("")}
        <dt>SHA-256</dt><dd class="mono">${esc(r.hashes.sha256)}</dd><dt>SHA-1</dt><dd class="mono">${esc(r.hashes.sha1)}</dd><dt>MD5</dt><dd class="mono">${esc(r.hashes.md5)}</dd></dl></div>
      ${r.binary ? binaryPanel(r.binary) : ""}
      ${r.capabilities.length || !r.binary ? `<div class="panel"><h2>Capabilities <small>own classes</small></h2><div class="caps">${r.capabilities.length ? r.capabilities.map(c => `<span class="cap" title="${esc(c.category)}"><b>${esc(c.label)}</b> · ${c.classes}</span>`).join("") : `<span class="muted small">No special capabilities.</span>`}</div></div>` : ""}
      ${r.entrypoints.length ? `<div class="panel"><h2>Entrypoints</h2><table class="tbl">${r.entrypoints.slice(0, 30).map(e => { const i = e.indexOf(":"); return `<tr><td>${esc(e.slice(i + 1).trim())}</td><td>${esc(e.slice(0, i))}</td></tr>`; }).join("")}</table></div>` : ""}
      ${r.classCount ? `<div class="panel"><h2>Engines</h2>${engLine("asm", "ASM bytecode")}${engLine("vineflower", "Vineflower")}${engLine("cfr", "CFR")}</div>` : ""}
      ${r.containers.length > 1 ? `<div class="panel"><h2>Nested archives <small>${r.containers.length - 1}</small></h2><table class="tbl">${r.containers.slice(1, 60).map(c => `<tr><td>${esc(c.path)}</td><td>${c.classes} cl.</td></tr>`).join("")}</table></div>` : ""}
    </div>
  </div>`;
  const ring = $("#vring");
  requestAnimationFrame(() => requestAnimationFrame(() => ring.style.setProperty("--p", r.score)));
  countUp($("#vring b"), r.score);
  stagger($$("#report .side-stack > .panel"), 60, 8);
  $("#newScan").onclick = () => { location.hash = "#/"; };
  if (hasCode) $("#openCode").onclick = () => openViewer(firstFlagged(), "");
  $$("#sevbar .sevchip").forEach(c => c.onclick = () => {
    const s = c.dataset.s;
    state.sevOff.has(s) ? state.sevOff.delete(s) : state.sevOff.add(s);
    c.classList.toggle("off");
    renderFindings(hasCode);
  });
  renderFindings(hasCode);
  show("report");
}

function binaryPanel(b) {
  const rows = [["Format", b.format], ["Architecture", b.arch], ["Subsystem", b.subsystem], ["Compiled", b.compiled], ["Imports", b.importCount], ["Overlay", b.overlay ? fmtSize(b.overlay) : null], ["Strings", b.strings]]
    .filter(x => x[1] !== undefined && x[1] !== null && x[1] !== "");
  const secs = (b.sections || []).map(s => `<tr><td>${esc(s.name)}</td><td>${fmtSize(s.size)}</td><td class="${s.entropy > 7.2 ? "hot" : ""}">${s.entropy}</td></tr>`).join("");
  const imps = Object.entries(b.imports || {}).map(([dll, fns]) => `<details><summary>${esc(dll)} <span class="muted">(${fns.length})</span></summary><div>${esc(fns.join(", "))}</div></details>`).join("");
  return `<div class="panel"><h2>Program</h2><dl class="kv">${rows.map(([k, x]) => `<dt>${k}</dt><dd>${esc(x)}</dd>`).join("")}</dl>
    ${(b.notes || []).length ? `<div class="caps mt">${b.notes.map(n => `<span class="cap"><b>${esc(n)}</b></span>`).join("")}</div>` : ""}
    ${(b.capabilities || []).length ? `<div class="note">Uses: ${esc(b.capabilities.join(" · "))}</div>` : ""}</div>
    ${secs ? `<div class="panel"><h2>Sections</h2><table class="bin-sec"><tr><th>Name</th><th>Size</th><th>Entropy</th></tr>${secs}</table></div>` : ""}
    ${imps ? `<div class="panel imports"><h2>Imports</h2>${imps}</div>` : ""}`;
}

function firstFlagged() {
  const f = state.report.findings.find(f => f.cls && !f.cls.startsWith("res:") && !f.cls.startsWith("file:"));
  return f ? [f.cls, f.container || ""] : state.report.classes.length ? [state.report.classes[0].n, state.report.classes[0].c] : [null, ""];
}

function renderFindings(canView) {
  const r = state.report;
  const list = r.findings.filter(f => !state.sevOff.has(f.severity));
  $("#fcount").textContent = list.length + " of " + r.findings.length;
  const box = $("#findings");
  if (!list.length) {
    box.innerHTML = `<div class="empty">${r.findings.length ? "All findings are filtered out." : "No findings. 🎉"}</div>`;
    return;
  }
  box.innerHTML = list.slice(0, 400).map((f, i) => {
    const where = f.cls ? shortCls(f.cls) + (f.method ? " · " + f.method.replace(/\(.*$/, "()") : "") : (f.evidence || "");
    const tags = [];
    if (f.entrypoint) tags.push("Entrypoint");
    if (f.library) tags.push("Library");
    if (f.occurrences > 1) tags.push(f.occurrences + "×");
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

/* ---------- code viewer ---------- */
const viewer = $("#viewer");
function openViewer([cls, container], focus) {
  if (!cls) return;
  viewer.classList.remove("hidden");
  document.body.style.overflow = "hidden";
  renderTree();
  loadClass(cls, container, state.viewer.engine, focus);
}
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
$$("#tabs button").forEach(b => b.onclick = () => { state.viewer.engine = b.dataset.e; loadClass(state.viewer.cls, state.viewer.container, b.dataset.e); });
$("#prevHit").onclick = () => stepHit(-1);
$("#nextHit").onclick = () => stepHit(1);

function renderTree() {
  const r = state.report;
  const q = $("#treeFilter").value.trim().toLowerCase();
  const only = $("#onlyFlagged").checked;
  let items = r.classes.filter(c => (!only || c.s) && (!q || c.n.toLowerCase().includes(q)));
  items.sort((a, b) => (a.c + a.n).localeCompare(b.c + b.n));
  const total = items.length;
  items = items.slice(0, 3000);
  let html = "", lastPkg = null;
  for (const c of items) {
    const i = c.n.lastIndexOf("/");
    const pkg = (c.c ? c.c + " › " : "") + (i > 0 ? c.n.slice(0, i).replace(/\//g, ".") : "(default)");
    if (pkg !== lastPkg) { html += `<div class="tree-pkg">${esc(pkg)}</div>`; lastPkg = pkg; }
    const active = c.n === state.viewer.cls && c.c === state.viewer.container ? " active" : "";
    const badges = [c.entry ? "entry" : "", c.hidden ? "disguised" : "", c.lib ? "lib" : ""].filter(Boolean).join(" ");
    html += `<div class="tree-item${c.s ? " s-" + c.s : ""}${active}" data-n="${esc(c.n)}" data-c="${esc(c.c)}" title="${esc(c.n)}"><i></i>${esc(c.n.slice(i + 1))}${badges ? ` <em>${badges}</em>` : ""}</div>`;
  }
  if (!total) html = `<div class="tree-pkg">No classes${only ? " – turn off “flagged only”" : ""}.</div>`;
  if (total > 3000) html += `<div class="tree-pkg">… ${total - 3000} more – use the filter</div>`;
  const list = $("#treeList");
  list.innerHTML = html;
  $$(".tree-item", list).forEach(t => t.onclick = () => loadClass(t.dataset.n, t.dataset.c, state.viewer.engine));
}
function topOf(cls, container) {
  let i = cls.indexOf("$");
  while (i > 0) {
    const cand = cls.slice(0, i);
    if (state.report.classes.some(c => c.n === cand && c.c === container)) return cand;
    i = cls.indexOf("$", i + 1);
  }
  return cls;
}
function classFindings(cls, container) {
  const top = topOf(cls, container);
  return state.report.findings.filter(f => f.cls && (f.container || "") === container && (f.cls === top || f.cls.startsWith(top + "$") || (f.related || []).some(x => x.cls === top)));
}

let loadSeq = 0;
async function loadClass(cls, container, engine, focus) {
  const v = state.viewer;
  v.cls = topOf(cls, container); v.container = container; v.engine = engine;
  $$("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.e === engine));
  $("#crumb").textContent = (container ? container + " › " : "") + shortCls(v.cls);
  $$(".tree-item").forEach(t => t.classList.toggle("active", t.dataset.n === v.cls && t.dataset.c === container));
  const fs = classFindings(v.cls, container);
  $("#classFindings").innerHTML = fs.map((f, i) => `<span class="cf s-${f.severity}" data-i="${i}">${esc(SEV_EN[f.severity])} · ${esc(f.title)}</span>`).join("");
  $$("#classFindings .cf").forEach(c => c.onclick = () => jumpTo(needlesOf([fs[+c.dataset.i]])));
  const code = $("#code");
  code.innerHTML = `<span class="loading">${engine === "asm" ? "Reading bytecode" : (engine === "cfr" ? "CFR" : "Vineflower") + " is decompiling"}…</span>`;
  const seq = ++loadSeq;
  try {
    const ot = ownerOf(state.report.id);
    const j = await api(`/api/job/${encodeURIComponent(state.report.id)}/source?engine=${engine}&container=${encodeURIComponent(container)}&cls=${encodeURIComponent(v.cls)}`, ot ? { headers: { "X-Owner-Token": ot } } : undefined);
    if (seq !== loadSeq) return;
    renderCode(j.source, engine, fs, focus);
  } catch (e) {
    if (seq === loadSeq) code.innerHTML = `<span class="loading">Error: ${esc(e.message)}</span>`;
  }
}
function needlesOf(fs) {
  const out = [];
  const add = (s, sev) => {
    if (!s) return;
    s = String(s).replace(/^\[[^\]]+\]\s*/, "").replace(/…$/, "");
    if (s.length > 40) s = s.slice(0, 40);
    if (s.length >= 3) out.push({ s, sev });
  };
  for (const f of fs) {
    add(f.needle, f.severity);
    add(f.evidence, f.severity);
    for (const x of f.related || []) { add(x.needle, f.severity); add(x.evidence, f.severity); }
  }
  return out;
}

const JAVA_KW = new Set("abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while var record yield sealed permits non-sealed true false null".split(" "));
function tokenize(src, engine) {
  if (engine === "asm") {
    const re = /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*")|\b([A-Z][A-Z0-9_]{2,})\b|(\b-?\d+\b)|(L[\w\/$]+;)/g;
    return lex(src, re, m => m[1] ? "c" : m[2] ? "s" : m[3] ? "o" : m[4] ? "n" : "t");
  }
  const re = /(\/\*[\s\S]*?\*\/|\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|(@[A-Za-z_][\w.]*)|\b(\d[\d_]*(?:\.\d+)?[lLfFdD]?|0x[0-9a-fA-F_]+[lL]?)\b|\b([A-Za-z_$][\w$]*)\b/g;
  return lex(src, re, m => m[1] ? "c" : m[2] ? "s" : m[3] ? "a" : m[4] ? "n" : m[5] ? (JAVA_KW.has(m[5]) ? "k" : /^[A-Z]/.test(m[5]) ? "t" : null) : null);
}
function lex(src, re, cls) {
  const toks = [];
  let last = 0, m;
  while ((m = re.exec(src))) {
    if (m.index > last) toks.push([null, src.slice(last, m.index)]);
    toks.push([cls(m), m[0]]);
    last = re.lastIndex;
  }
  if (last < src.length) toks.push([null, src.slice(last)]);
  return toks;
}
function renderCode(src, engine, fs, focus) {
  const lines = [[]];
  for (const [c, text] of tokenize(src, engine)) {
    text.split("\n").forEach((p, i) => {
      if (i > 0) lines.push([]);
      if (p) lines[lines.length - 1].push(c ? `<span class="t-${c}">${esc(p)}</span>` : esc(p));
    });
  }
  const raw = src.split("\n");
  const needles = needlesOf(fs);
  const rank = s => SEV.indexOf(s);
  const hits = [];
  const html = lines.map((parts, i) => {
    let best = null;
    const line = raw[i] || "";
    for (const n of needles) if (line.includes(n.s) && (best === null || rank(n.sev) < rank(best))) best = n.sev;
    if (best) hits.push(i);
    return `<span class="l${best ? " hit s-" + best : ""}">${parts.join("")}</span>`;
  }).join("");
  const code = $("#code");
  code.innerHTML = html;
  code.scrollTop = 0;
  state.viewer.hits = hits;
  state.viewer.hitIdx = -1;
  if (focus) jumpTo(needlesOf([focus]));
  else if (hits.length) stepHit(1);
  else $("#hitInfo").textContent = "0 hits";
}
function jumpTo(needles) {
  const v = state.viewer;
  const lines = $$("#code .l");
  for (let k = 0; k < v.hits.length; k++) {
    const text = lines[v.hits[k]].textContent;
    if (needles.some(n => text.includes(n.s))) { v.hitIdx = k - 1; stepHit(1); return; }
  }
  if (v.hits.length) stepHit(1);
}
function stepHit(d) {
  const v = state.viewer;
  if (!v.hits.length) return;
  v.hitIdx = (v.hitIdx + d + v.hits.length) % v.hits.length;
  const lines = $$("#code .l");
  $$("#code .l.cur").forEach(l => l.classList.remove("cur"));
  const el = lines[v.hits[v.hitIdx]];
  el.classList.add("cur");
  el.scrollIntoView({ block: "center" });
  $("#hitInfo").textContent = `${v.hitIdx + 1}/${v.hits.length}`;
}

api("/api/stats").then(s => { $("#stats").textContent = `${s.rules} rules · ${s.families} known families · ${s.scanned} files scanned`; }).catch(() => {});
loadMe().then(route);
