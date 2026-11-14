// RatScanner for Windows: a local-only scanner. Serves the bundled site on 127.0.0.1 and opens it in an app window.
/* global __mocksite, __discordmod, __desktopConfig */
const http = require('http'), path = require('path'), fs = require('fs'), os = require('os');
const { spawn } = require('child_process');
const sea = (() => { try { const s = require('node:sea'); return s.isSea() ? s : null; } catch (e) { return null; } })();
const DEV_ROOT = process.env.RATSCANNER_SITE;
const { createDiscord } = typeof __discordmod !== 'undefined' ? __discordmod : require('../discord.js');
const desktopConfig = typeof __desktopConfig !== 'undefined' ? __desktopConfig : {};
let appUrl = '';

const dataDir = path.join(process.env.LOCALAPPDATA || os.homedir(), 'RatScanner');
try { fs.mkdirSync(dataDir, { recursive: true }); } catch (e) {}
const logFile = path.join(dataDir, 'ratscanner.log');
const log = (...a) => { try { fs.appendFileSync(logFile, new Date().toISOString() + ' ' + a.join(' ') + '\n'); } catch (e) {} };
const discord = createDiscord({ dataDir, config: desktopConfig, appUrl: () => appUrl, openExternal: u => spawn('rundll32.exe', ['url.dll,FileProtocolHandler', u], { stdio: 'ignore', detached: true, windowsHide: true }).unref(), log });

function readSite(rel) {
  if (sea) { try { return Buffer.from(sea.getAsset('site/' + rel)); } catch (e) { return null; } }
  if (!DEV_ROOT) return null;
  const f = path.join(DEV_ROOT, rel);
  if (!f.startsWith(path.resolve(DEV_ROOT) + path.sep)) return null;
  try { return fs.readFileSync(f); } catch (e) { return null; }
}

const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.wasm': 'application/wasm', '.png': 'image/png' };
const LOCAL_CSS = 'nav a[href="#/plans"], nav a[href="#/leaderboard"], nav a[href="#/supporters"], #cfCheck, #quota, .gate { display: none !important; }';
const STRICT = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://cdn.discordapp.com; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'";
const ENGINE = "default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'";
let lastHit = Date.now();
const startedAt = Date.now();
const IDLE_EXIT = 3 * 60e3;
const HEARTBEAT_JS = "(function(){function p(){fetch('/api/ping',{cache:'no-store'}).catch(function(){})}p();setInterval(p,15000);document.addEventListener('visibilitychange',p)})();";

const server = http.createServer((q, r) => {
  lastHit = Date.now();
  const host = (q.headers.host || '').split(':')[0];
  if (!['127.0.0.1', 'localhost'].includes(host)) { r.writeHead(403); return r.end(); }
  let p;
  try { p = decodeURIComponent(new URL(q.url, 'http://x').pathname); } catch (e) { r.writeHead(400); return r.end(); }
  const chunks = []; let size = 0;
  q.on('data', d => { size += d.length; if (size < 1e6) chunks.push(d); });
  q.on('end', () => {
    const J = (o, c = 200) => { r.writeHead(c, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (p === '/api/ping') return J({ ok: true });
    if (p === '/heartbeat.js') { r.writeHead(200, { 'content-type': 'text/javascript', 'cache-control': 'no-store' }); return r.end(HEARTBEAT_JS); }
    if (p === '/api/me.php') return J(discord.me());
    if (p === '/api/login.php') return discord.login(q, r);
    if (p === '/api/logout.php') return J(discord.logout());
    if (discord.enabled && !discord.me().loggedIn && (p === '/api/quota.php' || p === '/api/fetch.php' || p === '/api/lookup.php')) return J({ error: 'Log in with Discord first.', needLogin: true }, 401);
    if (p === '/api/quota.php') return J({ ticket: '0'.repeat(32), left: 1e9 });
    if (p === '/api/fetch.php') {
      let j = {}; try { j = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch (e) {}
      return __mocksite.site(String(j.url || '')).then(d => {
        if (d.error) return J({ error: d.error }, 400);
        if (d.file) { r.writeHead(200, { 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(new URL(d.file.url).pathname.split('/').pop() || 'download.jar') }); return r.end(d.file.body); }
        J(d);
      }).catch(e => J({ error: 'Download failed: ' + e.message }, 400));
    }
    if (p.startsWith('/api/')) return J({ ok: true, users: [], plans: [], supporters: [], files: 0 });
    if (p === '/local.css') { r.writeHead(200, { 'content-type': 'text/css' }); return r.end(LOCAL_CSS); }
    const rel = p === '/' ? 'index.html' : p.replace(/^\/+/, '');
    if (rel.includes('..') || rel.includes('\\')) { r.writeHead(404); return r.end(); }
    const body = readSite(rel);
    if (!body) { r.writeHead(404); return r.end(); }
    const name = path.posix.basename(rel), engine = ['decompiler.html', 'host.js', 'worker.js'].includes(name);
    const headers = { 'content-type': types[path.extname(rel)] || 'application/octet-stream', 'content-security-policy': engine ? ENGINE : STRICT, 'x-content-type-options': 'nosniff', 'cache-control': 'no-store' };
    if (name === 'index.html') headers['clear-site-data'] = '"cache"';
    r.writeHead(200, headers);
    r.end(name === 'index.html' ? body.toString('utf8').replace('</head>', '<link rel="stylesheet" href="/local.css"><script src="/heartbeat.js"></script></head>') : body);
  });
});

function findBrowser() {
  const pf = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean);
  const rels = ['Microsoft\\Edge\\Application\\msedge.exe', 'Google\\Chrome\\Application\\chrome.exe', 'BraveSoftware\\Brave-Browser\\Application\\brave.exe'];
  for (const rel of rels) for (const base of pf) { const f = path.join(base, rel); if (fs.existsSync(f)) return f; }
  return null;
}

server.listen(0, '127.0.0.1', () => {
  const url = appUrl = 'http://127.0.0.1:' + server.address().port + '/';
  log('listening', url);
  if (process.platform !== 'win32') { console.log('RatScanner running at ' + url); return; }
  const browser = findBrowser();
  if (browser) {
    const profile = path.join(dataDir, 'AppWindow');
    const child = spawn(browser, ['--app=' + url, '--user-data-dir=' + profile, '--no-first-run', '--no-default-browser-check', '--window-size=1280,860', '--disable-features=Translate'], { stdio: 'ignore', windowsHide: false });
    child.on('exit', code => log('browser launcher exited', code));
    child.on('error', e => { log('browser error', e.message); openDefault(url); });
  } else openDefault(url);
  setInterval(() => { if (Date.now() - startedAt > 2 * 60e3 && Date.now() - lastHit > IDLE_EXIT) { log('no window for 3 min, exiting'); process.exit(0); } }, 20e3);
});

function openDefault(url) {
  spawn('cmd', ['/c', 'start', '""', url], { stdio: 'ignore', windowsHide: true, detached: true }).unref();
}
process.on('uncaughtException', e => log('error', e && e.stack || e));
