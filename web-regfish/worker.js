"use strict";
importScripts("engine.js?v=15");
let ready = null;
let last = null;
let deep = null;

function init() {
  if (!ready) ready = fetch("rules.json?v=5").then(r => r.json()).then(rules => RatEngine.init(rules));
  return ready;
}
let port = null;
const post = m => (port || self).postMessage(m);
const tick = () => new Promise(r => setTimeout(r, 0));

self.onmessage = e => {
  if (e.data && e.data.cmd === "port" && e.ports[0]) { port = e.ports[0]; port.onmessage = handle; return; }
  handle(e);
};
const handle = async e => {
  const m = e.data;
  try {
    await init();
    if (m.cmd === "scan") {
      last = null; deep = null;
      const res = await RatEngine.scan(new Uint8Array(m.buffer), m.name, (stage, p) => post({ type: "progress", stage, p }), m.sha256);
      last = { containers: res.containers, S: res.state, hashes: res.hashes, size: res.size, ms: res.ms, name: m.name };
      post({ type: "done", report: res.report });
    } else if (m.cmd === "site") {
      last = null; deep = null;
      post({ type: "done", report: RatEngine.scanSite(m.data) });
    } else if (m.cmd === "deep") {
      if (!last) return post({ type: "error", id: "deep", error: "Class data is no longer in memory – scan the file again." });
      await deepScan();
    } else if (m.cmd === "srczip") {
      if (!last) return post({ type: "error", id: m.id, error: "Class data is no longer in memory – scan the file again." });
      if (!deep) await deepScan();
      post({ type: "zip", id: m.id, blob: await buildSourceZip(m.report) });
    } else if (m.cmd === "disasm" || m.cmd === "java") {
      const c = last && last.containers.find(x => x.path === m.container);
      if (!c) return post({ type: "source", id: m.id, source: "// Class data is no longer in memory – scan the file again." });
      if (m.cmd === "java") {
        const src = deep && deep.sources.get(m.container + "!" + m.cls);
        if (src) return post({ type: "source", id: m.id, source: src.text });
      }
      const names = [...c.classes.keys()].filter(n => n === m.cls || n.startsWith(m.cls + "$")).sort((a, b) => (a === m.cls ? -1 : b === m.cls ? 1 : a.localeCompare(b)));
      post({ type: "source", id: m.id, source: names.map(n => RatEngine.disassemble(c.classes.get(n))).join("\n\n") || "// Class not found." });
    }
  } catch (err) {
    post({ type: "error", id: m.id ?? (m.cmd === "deep" ? "deep" : undefined), error: err && err.message ? err.message : String(err) });
  }
};

let vfMod = null;
const loadVineflower = () => (vfMod = vfMod || import("./vf/vf.js"));
const outerOf = n => { const i = n.indexOf("$"); return i > 0 ? n.slice(0, i) : null; };
const topsOf = c => [...c.classes.keys()].filter(n => { const o = outerOf(n); return !o || !c.classes.has(o); }).sort();
const VF_OPTS = { banner: "", "indent-string": "    ", "decompile-generic-signatures": "1", "remove-synthetic": "1", "remove-bridge": "1", "decompile-inner": "1" };
const quiet = { writeMessage: () => {} };

let deepRun = null;
function deepScan() { if (deep) return Promise.resolve(deep); if (!deepRun) deepRun = runDeep().finally(() => { deepRun = null; }); return deepRun; }
async function runDeep() {
  const t0 = Date.now(), L = last, S = L.S;
  const status = (phase, done, total, extra) => post({ type: "deepprogress", phase, done, total, ...extra });
  status("deobfuscate", 0, 1);
  const deob = await RatEngine.deobfuscate(S, (d, t) => status("deobfuscate", d, t));
  RatEngine.addDecrypted(S, deob);
  const patched = new Map();
  for (const c of L.containers) {
    const map = new Map();
    for (const [n, b] of c.classes) { const ed = deob.patches.get(n); map.set(n, ed ? RatEngine.patchClass(b, ed) : b); }
    patched.set(c.path, map);
  }
  const all = new Map();
  for (const c of L.containers) for (const [n, b] of patched.get(c.path)) if (!all.has(n)) all.set(n, b);
  const total = L.containers.reduce((a, c) => a + topsOf(c).length, 0);
  const sources = new Map();
  let done = 0, lines = 0, failed = 0;
  status("decompile", 0, total, { lines: 0, decrypted: deob.solved });
  const { decompile } = total ? await loadVineflower() : { decompile: null };
  for (const c of L.containers) {
    const own = patched.get(c.path), tops = topsOf(c);
    const source = async n => own.get(n) || all.get(n) || null;
    for (let i = 0; i < tops.length; i += 20) {
      const batch = tops.slice(i, i + 20);
      let res = null;
      try { res = await decompile(batch, { source, options: VF_OPTS, logger: quiet }); } catch (err) { res = null; }
      for (const n of batch) {
        let text = res && res[n];
        if (!text && !res) { try { const r1 = await decompile([n], { source, options: VF_OPTS, logger: quiet }); text = r1 && r1[n]; } catch (err) {} }
        const java = !!text;
        if (!java) { failed++; text = "// Vineflower could not decompile this class – bytecode listing instead.\n\n" + RatEngine.disassemble(c.classes.get(n)); }
        sources.set(c.path + "!" + n, { java, text, container: c.path, name: n });
        lines += RatEngine.scanSource(S, c.path, n, text);
      }
      done += batch.length;
      status("decompile", done, total, { lines, decrypted: deob.solved });
      await tick();
    }
  }
  const stats = { classes: total, decompiled: total - failed, failed, lines, sites: deob.sites, decrypted: deob.solved, decryptors: deob.decryptors.slice(0, 20), patchedClasses: deob.patches.size, ms: Date.now() - t0 };
  const report = RatEngine.deepen(S, deob, stats, L.hashes, L.name, L.size, L.ms + stats.ms);
  deep = { sources, deob, report };
  post({ type: "deepdone", report });
  return deep;
}

const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(u) { let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = CRC[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
async function deflate(u) {
  if (typeof CompressionStream === "undefined") return null;
  try { return new Uint8Array(await new Response(new Blob([u]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer()); } catch (e) { return null; }
}
function safePath(p) { return p.replace(/\\/g, "/").split("/").filter(x => x && x !== "." && x !== "..").map(x => x.replace(/[<>:"|?*\x00-\x1f]/g, "_").slice(0, 120)).join("/"); }

async function buildSourceZip(reportIn) {
  const report = (deep && deep.report) || reportIn, fileName = last.name;
  const enc = new TextEncoder(), files = [];
  const base = safePath((fileName || "file").replace(/\.[a-z0-9]{1,5}$/i, "")) || "file";
  const now = new Date(), dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1), dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  const add = (path, data) => files.push({ path: base + "/" + path, data: typeof data === "string" ? enc.encode(data) : data });
  const st = report.deep || {};
  add("README.txt", [
    "RatScanner – deobfuscated source", "",
    "File:     " + fileName,
    "Verdict:  " + report.verdict + " (" + report.score + "/100)",
    "SHA-256:  " + (report.hashes ? report.hashes.sha256 : "-"), "",
    "Deep scan: " + (st.decompiled ?? 0) + " of " + (st.classes ?? 0) + " classes decompiled with Vineflower 1.12, " + (st.lines ?? 0).toLocaleString("en-US") + " lines read.",
    "Deobfuscation: " + (st.decrypted ?? 0) + " hidden strings decrypted by emulation and written back into the code as plain text.",
    "", "src/          Deobfuscated, decompiled Java source (.java)", "resources/    Text files from the archive (fabric.mod.json, configs, manifest ...)", "nested/       The same for JARs inside the JAR",
    "deobfuscation/decrypted-strings.txt   Every decrypted string with the class, method and line it is used in", "report.json   Full scan report", "",
    "Decompiled code is a reconstruction and may not compile as-is.",
    "Nothing in this ZIP can run: no .class, .jar or binary files are included."
  ].join("\r\n") + "\r\n");
  add("report.json", JSON.stringify(report, null, 2));
  if (deep) {
    const lines = deep.deob.results.map(d => (d.container ? d.container + " › " : "") + d.cls.replace(/\//g, ".") + "." + d.method.split("(")[0] + (d.line ? ":" + d.line : "") + "   [" + d.via + "]\r\n    " + JSON.stringify(d.value));
    add("deobfuscation/decrypted-strings.txt", lines.length ? lines.join("\r\n\r\n") + "\r\n" : "No encrypted strings were found.\r\n");
    for (const s of deep.sources.values()) {
      const pre = s.container ? "nested/" + safePath(s.container.replace(/!\//g, "/")) + "/" : "";
      add(pre + "src/" + safePath(s.name) + (s.java ? ".java" : ".bytecode.txt"), s.text);
    }
  }
  for (const c of last.containers) {
    const pre = c.path ? "nested/" + safePath(c.path.replace(/!\//g, "/")) + "/" : "";
    for (const [name, bytes] of (c.text || new Map())) add(pre + "resources/" + safePath(name), bytes);
  }
  const parts = [], central = []; let off = 0;
  for (const f of files) {
    const name = enc.encode(f.path), crc = crc32(f.data), comp = f.data.length > 64 ? await deflate(f.data) : null;
    const useDeflate = comp && comp.length < f.data.length, body = useDeflate ? comp : f.data;
    const h = new DataView(new ArrayBuffer(30));
    h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, useDeflate ? 8 : 0, true);
    h.setUint16(10, dosTime, true); h.setUint16(12, dosDate, true); h.setUint32(14, crc, true); h.setUint32(18, body.length, true); h.setUint32(22, f.data.length, true); h.setUint16(26, name.length, true);
    parts.push(new Uint8Array(h.buffer), name, body);
    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true); cd.setUint16(4, 20, true); cd.setUint16(6, 20, true); cd.setUint16(8, 0x0800, true); cd.setUint16(10, useDeflate ? 8 : 0, true);
    cd.setUint16(12, dosTime, true); cd.setUint16(14, dosDate, true); cd.setUint32(16, crc, true); cd.setUint32(20, body.length, true); cd.setUint32(24, f.data.length, true); cd.setUint16(28, name.length, true); cd.setUint32(42, off, true);
    central.push(new Uint8Array(cd.buffer), name);
    off += 30 + name.length + body.length;
  }
  const cdSize = central.reduce((a, b) => a + b.length, 0), end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true); end.setUint32(12, cdSize, true); end.setUint32(16, off, true);
  return new Blob([...parts, ...central, new Uint8Array(end.buffer)], { type: "application/zip" });
}
