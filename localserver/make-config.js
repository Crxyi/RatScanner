// Writes desktop-config.json (public Discord IDs only – never the client secret or bot token) from ../ratscanner.env.
const fs = require('fs'), path = require('path');
const env = {};
try { for (const l of fs.readFileSync(path.join(__dirname, '..', 'ratscanner.env'), 'utf8').split(/\r?\n/)) { const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/); if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, ''); } } catch (e) {}
const id = v => /^\d{5,25}$/.test(v || '') ? v : null;
const cfg = { clientId: id(process.env.DISCORD_DESKTOP_CLIENT_ID || env.DISCORD_DESKTOP_CLIENT_ID || env.DISCORD_CLIENT_ID), guildId: id(env.DISCORD_GUILD_ID), invite: /^https:\/\/(discord\.gg|discord\.com\/invite)\//.test(env.DISCORD_INVITE_URL || '') ? env.DISCORD_INVITE_URL : null,
  roleStarter: id(env.DISCORD_ROLE_STARTER), rolePro: id(env.DISCORD_ROLE_PRO), roleEnterprise: id(env.DISCORD_ROLE_ENTERPRISE) };
fs.writeFileSync(path.join(__dirname, 'desktop-config.json'), JSON.stringify(cfg, null, 1));
console.log('desktop-config.json:', Object.entries(cfg).map(([k, v]) => k + (v ? ' ✓' : ' –')).join(', '));
