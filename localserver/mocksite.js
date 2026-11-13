// Test-only stand-in for api/fetch.php: downloads page + scripts as text (nothing is executed).
const tls = require('tls');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 RatScanner/1.0';
const SL2 = new Set('co.uk org.uk com.au com.br co.jp'.split(' '));
const reg = h => { const p = h.split('.'); if (p.length <= 2) return h; const two = p.slice(-2).join('.'); return SL2.has(two) ? p.slice(-3).join('.') : two; };
async function get(url, max, timeout) {
  const chain = [];
  for (let hop = 0; hop < 8; hop++) {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) return { error: 'only http(s)' };
    if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(u.hostname)) return { error: 'private address refused' };
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeout * 1000);
    let r;
    try { r = await fetch(url, { redirect: 'manual', signal: ac.signal, headers: { 'user-agent': UA, accept: 'text/html,*/*' } }); } catch (e) { clearTimeout(t); return { error: 'connection failed (' + (e.cause && e.cause.code || e.message) + ')', chain }; }
    chain.push({ url, code: r.status });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { clearTimeout(t); url = new URL(loc, url).href; continue; }
    const headers = {}; r.headers.forEach((v, k) => headers[k] = v.slice(0, 400));
    const page = /text\/html|xhtml/i.test(headers['content-type'] || '');
    const lim = page ? 3 << 20 : max;
    const chunks = []; let size = 0, truncated = false;
    try { for await (const c of r.body) { size += c.length; if (size > lim) { truncated = true; break; } chunks.push(c); } } catch (e) {}
    clearTimeout(t);
    return { url, code: r.status, headers, body: Buffer.concat(chunks), page, truncated, chain };
  }
  return { error: 'too many redirects', chain };
}
function cert(host) {
  return new Promise(res => { const s = tls.connect(443, host, { servername: host, timeout: 5000 }, () => { const c = s.getPeerCertificate(); s.end(); res(c && c.valid_from ? { issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || '', subject: c.subject && c.subject.CN, from: c.valid_from, to: c.valid_to } : null); }); s.on('error', () => res(null)); s.on('timeout', () => { s.destroy(); res(null); }); });
}
async function rdap(d) {
  try { const r = await fetch('https://rdap.org/domain/' + d, { headers: { accept: 'application/rdap+json', 'user-agent': 'RatScanner/1.0' }, signal: AbortSignal.timeout(6000) }); if (!r.ok) return null; const j = await r.json(); const o = { domain: d };
    for (const e of j.events || []) { if (e.eventAction === 'registration') o.created = e.eventDate; if (e.eventAction === 'expiration') o.expires = e.eventDate; }
    for (const en of j.entities || []) if ((en.roles || []).includes('registrar')) for (const v of (en.vcardArray || [])[1] || []) if (v[0] === 'fn') o.registrar = v[3];
    return o; } catch (e) { return null; }
}
async function site(url) {
  const r = await get(url, 100 << 20, 30);
  if (r.error) return { error: 'Download failed: ' + r.error };
  if (!r.page && !/^\s*(<!doctype html|<html)/i.test(r.body.slice(0, 512).toString())) return { file: r };
  const html = r.body.toString('utf8');
  const srcs = [];
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) { try { const u = new URL(m[1].replace(/&amp;/g, '&'), r.url).href; if (/^https?:/.test(u) && !srcs.includes(u)) srcs.push(u); } catch (e) {} }
  const scripts = [];
  for (const s of srcs.slice(0, 15)) { const g = await get(s, 1536 << 10, 8); scripts.push(g.error ? { url: s, error: g.error } : { url: s, final: g.url, code: g.code, size: g.body.length, truncated: g.truncated, body: g.body.toString('utf8') }); }
  for (const s of srcs.slice(15)) scripts.push({ url: s, skipped: 'limit' });
  const host = new URL(r.url).hostname, start = new URL(r.chain[0].url).hostname;
  return { kind: 'page', url: r.chain[0].url, final: r.url, code: r.code, ip: null, chain: r.chain, headers: r.headers, cert: r.url.startsWith('https:') ? await cert(host) : null,
    domain: await rdap(reg(host)), startDomain: reg(start) !== reg(host) ? await rdap(reg(start)) : null, truncated: r.truncated, html, scripts };
}
module.exports = { site };
