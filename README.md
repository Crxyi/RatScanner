# RatScanner

Web scanner for Minecraft mods, plugins, clients and programs. `.jar` files are analysed with **ASM** (bytecode), **Vineflower** and **CFR**; `.exe`/`.dll`/ELF/Mach-O files and scripts get a PE/import/packer/string analysis (JARs embedded in programs are unpacked and scanned with all Java engines).

**Uploaded files are never executed.** The server only reads bytes: no `java -jar`, no class loading, no `ClassLoader`/`defineClass`, and uploaded files are never offered for download.

## Desktop apps (local only)

**Windows:** download `RatScanner.exe` from the [latest release](https://github.com/Crxyi/RatScanner/releases/latest) and double-click it. It runs the scanner on `127.0.0.1` only and opens it in an app window (Edge/Chrome app mode) – no login, no limits, nothing is uploaded. The file is not code-signed, so Windows SmartScreen may show "Windows protected your PC" → *More info* → *Run anyway*. Built with `localserver/win/build.sh` (Node.js single executable application).

**macOS:** `localserver/mac/build.sh` builds `RatScanner.app` (native WebKit window, bundled Node.js) into `~/Applications`.

Scanned files are never executed by either app – they are only read.

## Run locally

```bash
gradle fatJar
java -Xmx2g -jar build/libs/ratscanner.jar
```

Open http://localhost:8080.

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default `8080`) |
| `DATA_DIR` | reports, users, session key (default `data`) |
| `SCAN_WORKERS` | parallel scans (default `2`) |
| `SCANS_PER_HOUR` | scans per IP per hour (default `40`, accounts get 2×) |
| `PUBLIC_URL` | public base URL, e.g. `https://ratscanner.example.com` (needed for the Discord redirect, enables `Secure` cookies) |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Discord login + leaderboard |
| `REQUIRE_LOGIN` | set to any value to only allow scans when logged in |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | Cloudflare Turnstile bot protection on every scan |
| `TRUST_CLOUDFLARE` | trust `CF-Connecting-IP` (only when the server is reachable **only** through Cloudflare) |
| `TRUST_PROXY` | trust `X-Forwarded-For` from another reverse proxy |
| `SESSION_SECRET` | optional fixed secret for login cookies (otherwise generated into `data/session.key`) |

### Discord login

1. https://discord.com/developers/applications → *New Application* → *OAuth2*.
2. Add the redirect `PUBLIC_URL/auth/callback` (locally `http://localhost:8080/auth/callback`).
3. Copy *Client ID* and *Client Secret* into `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET`.

Only the `identify` scope is requested (name + avatar). The leaderboard counts **different** files (SHA-256) per user.

### Cloudflare

1. Put the domain behind Cloudflare (orange cloud), SSL mode *Full (strict)*.
2. Dashboard → *Turnstile* → add the site → set `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET`.
3. Set `TRUST_CLOUDFLARE=1` and firewall the origin so it only accepts Cloudflare IPs.
4. Recommended: a WAF rate-limit rule on `/api/scan*`.

Cloudflare test keys for local testing: site key `1x00000000000000000000AA`, secret `1x0000000000000000000000000000000AA`.

### Docker

```bash
docker build -t ratscanner .
docker run -d -p 8080:8080 -v ratscanner-data:/app/data --read-only --tmpfs /tmp --security-opt no-new-privileges ratscanner
```

The container runs as a non-root user; the root filesystem can be read-only.

## Code map

- `Rules.java` – signatures: method calls → capabilities, string rules, combination rules
- `Analyzer.java` – ASM analysis, string reconstruction
- `StringEmulator.java` – emulates character-arithmetic / byte-array string encryption (SilentNet style)
- `Decompilers.java` – Vineflower, CFR, ASM textifier
- `SourceScanner.java` – re-checks decompiled source
- `BinaryScanner.java` – PE/ELF/Mach-O/script analysis
- `Scanner.java` – pipeline: unpacking, resources, metadata, entrypoints, scoring
- `Auth.java` – Discord OAuth, Turnstile, rate limits, leaderboard
- `src/main/resources/rules/iocs.json` – known malware families and hashes (extendable without code changes)
- `src/main/resources/web/` – website

## API

- `POST /api/scan?name=x.jar&full=1` (body = file, header `X-Turnstile-Token` when Turnstile is on) → `{id}`
- `POST /api/scan-url` `{"url": "...", "full": true, "turnstile": "..."}` → `{id}`
- `GET /api/job/{id}` → status + report
- `GET /api/job/{id}/source?container=&cls=&engine=vineflower|cfr|asm`
- `GET /api/job/{id}/report.json`
- `GET /api/hash/{sha256}`
- `GET /api/me`, `GET /api/leaderboard`, `GET /auth/login`, `POST /auth/logout`
