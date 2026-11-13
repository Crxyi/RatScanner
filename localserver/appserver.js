// Server for the RatScanner Mac app: only reachable from this Mac (127.0.0.1), no login, no limits.
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const { createDiscord } = require(path.join(__dirname, 'discord.js'));
const dataDir = path.join(os.homedir(), 'Library', 'Application Support', 'RatScanner');
try { fs.mkdirSync(dataDir, { recursive: true }); } catch (e) {}
let config = {}; try { config = JSON.parse(fs.readFileSync(path.join(__dirname, 'desktop-config.json'), 'utf8')); } catch (e) {}
let appUrl = '';
const discord = createDiscord({ dataDir, config, appUrl: () => appUrl, openExternal: u => require('child_process').spawn('/usr/bin/open', [u], { stdio: 'ignore', detached: true }).unref(), log: (...a) => console.log(...a) });
const root = path.resolve(process.argv[2]);
const port = +(process.argv[3] || 0);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.wasm': 'application/wasm' };
const LOCAL_CSS = `nav a[href="#/plans"], nav a[href="#/leaderboard"], nav a[href="#/supporters"], #cfCheck, #quota, .gate { display: none !important; }`;
const STRICT = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://cdn.discordapp.com; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'";
const ENGINE = "default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'";
let site = null;
const server = http.createServer((q, r) => {
  const host = (q.headers.host || '').split(':')[0];
  if (!['127.0.0.1', 'localhost'].includes(host)) { r.writeHead(403); return r.end(); }
  const u = new URL(q.url, 'http://x'), p = decodeURIComponent(u.pathname);
  const chunks = []; let size = 0;
  q.on('data', d => { size += d.length; if (size < 1e6) chunks.push(d); });
  q.on('end', () => {
    const body = Buffer.concat(chunks).toString();
    const J = (o, c = 200) => { r.writeHead(c, { 'content-type': 'application/json', 'cache-control': 'no-store' }); r.end(JSON.stringify(o)); };
    if (p === '/api/me.php') return J(discord.me());
    if (p === '/api/login.php') return discord.login(q, r);
    if (p === '/api/logout.php') return J(discord.logout());
    if (discord.enabled && !discord.me().loggedIn && (p === '/api/quota.php' || p === '/api/fetch.php' || p === '/api/lookup.php')) return J({ error: 'Log in with Discord first.', needLogin: true }, 401);
    if (p === '/api/quota.php') return J({ ticket: '0'.repeat(32), left: 1e9 });
    if (p === '/api/fetch.php') {
      let j = {}; try { j = JSON.parse(body || '{}'); } catch (e) {}
      site = site || require(path.join(__dirname, 'mocksite.js'));
      return site.site(String(j.url || '')).then(d => {
        if (d.error) return J({ error: d.error }, 400);
        if (d.file) { r.writeHead(200, { 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(new URL(d.file.url).pathname.split('/').pop() || 'download.jar') }); return r.end(d.file.body); }
        J(d);
      }).catch(e => J({ error: 'Download failed: ' + e.message }, 400));
    }
    if (p.startsWith('/api/')) return J({ ok: true, users: [], plans: [], supporters: [], files: 0 });
    if (p === '/local.css') { r.writeHead(200, { 'content-type': 'text/css' }); return r.end(LOCAL_CSS); }
    const f = path.join(root, p === '/' ? 'index.html' : p);
    if (!f.startsWith(root + path.sep) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { r.writeHead(404); return r.end(); }
    const name = path.basename(f), engine = ['decompiler.html', 'host.js', 'worker.js'].includes(name);
    const headers = { 'content-type': types[path.extname(f)] || 'application/octet-stream', 'content-security-policy': engine ? ENGINE : STRICT, 'x-content-type-options': 'nosniff', 'cache-control': 'no-cache' };
    if (name === 'index.html') { r.writeHead(200, headers); return r.end(fs.readFileSync(f, 'utf8').replace('</head>', '<link rel="stylesheet" href="/local.css"></head>')); }
    r.writeHead(200, headers);
    fs.createReadStream(f).pipe(r);
  });
});
server.listen(port, '127.0.0.1', () => { appUrl = 'http://127.0.0.1:' + server.address().port + '/'; console.log('LISTENING ' + server.address().port); });
process.stdin.on('end', () => process.exit(0));
process.stdin.resume();
