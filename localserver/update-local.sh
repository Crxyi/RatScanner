#!/bin/sh
rsync -a --delete --exclude api/config.php "$HOME/Desktop/RatScanner/web-regfish/" "$HOME/RatScanner-Local/site/"
cp "$HOME/Desktop/RatScanner/localserver/server.js" "$HOME/Desktop/RatScanner/localserver/mocksite.js" "$HOME/RatScanner-Local/"
launchctl kickstart -k "gui/$(id -u)/org.ratscanner.localserver"
echo "Local RatScanner updated."
