#!/bin/sh
# Builds RatScanner.app (local-only, runs the scanner on this Mac) and installs it to ~/Applications.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/dist/RatScanner.app"
WORK="$HERE/dist/work"
/bin/rm -rf "$HERE/dist"
mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources/server" "$OUT/Contents/Resources/site" "$WORK"

swiftc -O -target arm64-apple-macos13 -o "$OUT/Contents/MacOS/RatScanner" "$HERE/main.swift" -framework Cocoa -framework WebKit

NODE="$(command -v node)"
lipo "$NODE" -thin arm64 -output "$OUT/Contents/Resources/node" 2>/dev/null || cp "$NODE" "$OUT/Contents/Resources/node"
chmod +x "$OUT/Contents/Resources/node"

node "$PROJ/localserver/make-config.js"
cp "$PROJ/localserver/appserver.js" "$PROJ/localserver/mocksite.js" "$PROJ/localserver/discord.js" "$PROJ/localserver/desktop-config.json" "$OUT/Contents/Resources/server/"
rsync -a --exclude api --exclude .htaccess "$PROJ/web-regfish/" "$OUT/Contents/Resources/site/"

qlmanage -t -s 1024 -o "$WORK" "$HERE/icon.svg" >/dev/null 2>&1
ICONSET="$WORK/AppIcon.iconset"; mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s "$WORK/icon.svg.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); sips -z $d $d "$WORK/icon.svg.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$OUT/Contents/Resources/AppIcon.icns"

cat > "$OUT/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>RatScanner</string>
  <key>CFBundleDisplayName</key><string>RatScanner</string>
  <key>CFBundleIdentifier</key><string>org.ratscanner.mac</string>
  <key>CFBundleExecutable</key><string>RatScanner</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
  <key>CFBundleDocumentTypes</key>
  <array><dict>
    <key>CFBundleTypeName</key><string>File to scan</string>
    <key>CFBundleTypeRole</key><string>Viewer</string>
    <key>LSHandlerRank</key><string>Alternate</string>
    <key>LSItemContentTypes</key><array><string>public.data</string></array>
  </dict></array>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$OUT" >/dev/null 2>&1 || true
/bin/rm -rf "$WORK"
mkdir -p "$HOME/Applications"
/bin/rm -rf "$HOME/Applications/RatScanner.app"
cp -R "$OUT" "$HOME/Applications/RatScanner.app"
echo "Built: $HOME/Applications/RatScanner.app"
