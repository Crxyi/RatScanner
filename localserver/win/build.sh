#!/bin/sh
# Builds RatScanner.exe (Windows x64, local-only) as a Node.js single executable application.
# Needs the official Windows node.exe of the SAME version as the local node: NODE_WIN=/path/to/node.exe ./build.sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/dist"
: "${NODE_WIN:?set NODE_WIN to the Windows node.exe (node-v$(node -v | cut -c2-)-win-x64)}"
/bin/rm -rf "$OUT"; mkdir -p "$OUT"

{ printf 'const __mocksite = (function () { const module = { exports: {} };\n'
  cat "$PROJ/localserver/mocksite.js"
  printf '\nreturn module.exports; })();\n'
  printf 'const __discordmod = (function () { const module = { exports: {} };\n'
  cat "$PROJ/localserver/discord.js"
  printf '\nreturn module.exports; })();\n'
  node "$PROJ/localserver/make-config.js" >&2
  printf 'const __desktopConfig = %s;\n' "$(cat "$PROJ/localserver/desktop-config.json")"
  cat "$HERE/main.js"; } > "$OUT/bundle.js"

node -e '
const fs = require("fs"), path = require("path");
const [site, out] = process.argv.slice(1);
const assets = {};
(function walk(d, rel) {
  for (const n of fs.readdirSync(d)) {
    const f = path.join(d, n), r = rel ? rel + "/" + n : n;
    if (n === "api" || n === ".htaccess" || n === ".DS_Store") continue;
    if (fs.statSync(f).isDirectory()) walk(f, r); else assets["site/" + r] = f;
  }
})(site, "");
fs.writeFileSync(path.join(out, "sea-config.json"), JSON.stringify({ main: path.join(out, "bundle.js"), output: path.join(out, "sea-prep.blob"), disableExperimentalSEAWarning: true, useCodeCache: false, useSnapshot: false, assets }, null, 1));
console.log(Object.keys(assets).length + " site files");
' "$PROJ/web-regfish" "$OUT"

node --experimental-sea-config "$OUT/sea-config.json"
cp "$NODE_WIN" "$OUT/RatScanner.exe"
[ -n "$SET_ICON" ] && NODE_PATH="${RESEDIT_PATH:-}" node "$HERE/set-icon.js" "$OUT/RatScanner.exe" "$HERE/icon.ico"
${POSTJECT:-npx --yes postject} "$OUT/RatScanner.exe" NODE_SEA_BLOB "$OUT/sea-prep.blob" --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 --overwrite

# Windows GUI subsystem: no black console window behind the app.
node -e '
const fs = require("fs"), f = process.argv[1], b = fs.readFileSync(f);
const pe = b.readUInt32LE(0x3c); if (b.readUInt32LE(pe) !== 0x4550) throw new Error("no PE header");
b.writeUInt16LE(2, pe + 24 + 68); fs.writeFileSync(f, b); console.log("subsystem set to GUI");
' "$OUT/RatScanner.exe"

/bin/rm -f "$OUT/bundle.js" "$OUT/sea-prep.blob" "$OUT/sea-config.json"
ls -la "$OUT/RatScanner.exe"
