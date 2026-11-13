// Discord login for the desktop apps: OAuth2 code flow with PKCE, so no client secret is shipped in the app.
// The Discord application needs "Public Client" enabled and the redirect http://127.0.0.1:53682/callback.
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const CALLBACK_PORT = 53682;
const REDIRECT = 'http://127.0.0.1:' + CALLBACK_PORT + '/callback';
const API = 'https://discord.com/api/v10';
const b64url = b => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function createDiscord({ dataDir, config, appUrl, log = () => {} }) {
  const cfg = config || {};
  const file = path.join(dataDir, 'discord-session.json');
  let session = null, pending = null, cb = null;
  try { session = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {}
  const save = () => { try { if (session) fs.writeFileSync(file, JSON.stringify(session), { mode: 0o600 }); else fs.rmSync(file, { force: true }); } catch (e) { log('session save failed', e.message); } };
  const enabled = !!cfg.clientId;

  function planOf(roles) {
    const r = new Set(roles || []);
    if (cfg.roleEnterprise && r.has(cfg.roleEnterprise)) return 'Enterprise';
    if (cfg.rolePro && r.has(cfg.rolePro)) return 'Pro';
    if (cfg.roleStarter && r.has(cfg.roleStarter)) return 'Starter';
    return null;
  }

  async function api(p, token, init = {}) {
    const r = await fetch(API + p, { ...init, headers: { authorization: 'Bearer ' + token, 'user-agent': 'RatScanner-Desktop (local app, 1.0)', ...(init.headers || {}) }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error('Discord answered ' + r.status);
    return r.json();
  }

  function page(res, code, title, text, redirect) {
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'", ...(redirect ? { refresh: '1;url=' + redirect } : {}) });
    res.end(`<!doctype html><meta charset="utf-8"><title>RatScanner</title><body style="background:#0b0b0d;color:#e8e8ea;font:15px -apple-system,Segoe UI,sans-serif;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><b style="font-size:18px">${title}</b><p style="color:#8a8a94">${text}</p></div></body>`);
  }

  function stopCallback() { if (cb) { try { cb.close(); } catch (e) {} cb = null; } }

  function startCallback() {
    return new Promise((resolve, reject) => {
      if (cb) return resolve();
      const s = http.createServer(async (q, r) => {
        const u = new URL(q.url, 'http://127.0.0.1');
        if (u.pathname !== '/callback') { r.writeHead(404); return r.end(); }
        const back = appUrl() + '#/';
        const p = pending;
        if (!p || u.searchParams.get('state') !== p.state) return page(r, 400, 'Login expired', 'Please start the login again from RatScanner.', back);
        pending = null;
        if (u.searchParams.get('error')) { setTimeout(stopCallback, 500); return page(r, 200, 'Login cancelled', 'Taking you back to RatScanner…', back); }
        try {
          const body = new URLSearchParams({ client_id: cfg.clientId, grant_type: 'authorization_code', code: u.searchParams.get('code') || '', redirect_uri: REDIRECT, code_verifier: p.verifier });
          const tr = await fetch(API + '/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(10000) });
          const tok = await tr.json();
          if (!tr.ok || !tok.access_token) throw new Error(tok.error_description || tok.error || 'token exchange failed (is "Public Client" enabled for this Discord app?)');
          const me = await api('/users/@me', tok.access_token);
          let roles = [];
          if (cfg.guildId && String(tok.scope || '').includes('guilds.members.read')) { try { roles = (await api('/users/@me/guilds/' + cfg.guildId + '/member', tok.access_token)).roles || []; } catch (e) {} }
          session = { id: me.id, name: me.global_name || me.username, username: me.username, avatar: me.avatar ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png?size=64` : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(me.id) >> 22n) % 6n)}.png`, roles, plan: planOf(roles), since: Date.now(), refresh: tok.refresh_token || null };
          save();
          log('discord login', session.username);
          page(r, 200, 'Logged in as ' + session.name.replace(/[<>&"]/g, ''), 'Taking you back to RatScanner…', back);
        } catch (e) {
          log('discord login failed', e.message);
          page(r, 500, 'Login failed', String(e.message).replace(/[<>&"]/g, ''), back);
        }
        setTimeout(stopCallback, 1000);
      });
      s.on('error', e => reject(new Error(e.code === 'EADDRINUSE' ? 'Port ' + CALLBACK_PORT + ' is in use by another program – close it and try again.' : e.message)));
      s.listen(CALLBACK_PORT, '127.0.0.1', () => { cb = s; resolve(); });
    });
  }

  return {
    enabled,
    me() {
      const base = { local: true, discordEnabled: enabled, invite: cfg.invite || null };
      if (!session) return { ...base, loggedIn: false };
      return { ...base, loggedIn: true, user: { name: session.name, avatar: session.avatar, plan: session.plan || 'Local', limit: 1e9, usedToday: 0 } };
    },
    async login(req, res) {
      if (!enabled) { res.writeHead(302, { location: '/#/' }); return res.end(); }
      try { await startCallback(); } catch (e) { res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' }); return res.end(e.message); }
      const verifier = b64url(crypto.randomBytes(48));
      pending = { state: b64url(crypto.randomBytes(18)), verifier, at: Date.now() };
      setTimeout(() => { if (pending && Date.now() - pending.at > 9 * 60e3) { pending = null; stopCallback(); } }, 10 * 60e3);
      const scope = cfg.guildId ? 'identify guilds.members.read' : 'identify';
      const u = 'https://discord.com/oauth2/authorize?' + new URLSearchParams({ response_type: 'code', client_id: cfg.clientId, scope, redirect_uri: REDIRECT, state: pending.state, code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256' });
      res.writeHead(302, { location: u, 'cache-control': 'no-store' });
      res.end();
    },
    logout() { session = null; save(); return { ok: true }; }
  };
}
module.exports = { createDiscord, CALLBACK_PORT, REDIRECT };
