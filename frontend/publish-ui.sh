#!/bin/sh
# UI release publisher (docker-compose service "ui-release", scripts/release.sh). Runs from the new web image with the
# shared "ui" volume at /target; nginx (service "web") serves that volume read-only and is never restarted for a UI release.
#
#   publish-ui <release>          copy this image's UI into /target/releases/<release>, add its hashed assets to the shared
#                                 pool, verify every asset index.html references exists, then switch /target/current to it
#                                 atomically (rename of a symlink: a request sees the old or the new release, never neither)
#   publish-ui --switch <release> point /target/current at an existing release (rollback: nothing is rebuilt)
#   publish-ui --list             releases on the volume, newest first, and the current one
#
# Hashed assets of the last KEEP_RELEASES releases stay in the pool, so a browser still running the previous release can
# load its lazy chunks after the switch (no blank page, no 404 on a route the user opens next).
set -eu
T=/target
KEEP="${KEEP_RELEASES:-5}"
valid() { case "$1" in ""|*[!A-Za-z0-9._-]*) echo "invalid release name: $1" >&2; exit 2;; esac; }
switch() {
  test -f "$T/releases/$1/index.html" || { echo "release $1 is not on the volume" >&2; exit 3; }
  ln -sfn "releases/$1" "$T/.current.new"
  mv -T "$T/.current.new" "$T/current"
  echo "current -> $1"
}
case "${1:-}" in
  --list)
    echo "current: $(readlink "$T/current" 2>/dev/null | sed 's#releases/##')"
    ls -1t "$T/releases" 2>/dev/null | grep -v '^\.' || true
    exit 0;;
  --switch)
    valid "${2:-}"; switch "$2"; exit 0;;
esac
R="${1:-}"; valid "$R"
test -w "$T" || { echo "$T is not writable by uid $(id -u): the ui volume must be owned by 10101 (docs/deployment-guide.md)" >&2; exit 5; }
mkdir -p "$T/releases" "$T/assets"
tmp="$T/releases/.tmp-$R"
rm -rf "$tmp"
cp -a /srv/ui/releases/image "$tmp"
# one file at a time: BusyBox "cp -an dir/. dest/" copies nothing when not run as root
for f in /srv/ui/assets/*; do b="${f##*/}"; [ -e "$T/assets/$b" ] || cp -p "$f" "$T/assets/$b"; done
for a in $(grep -o 'assets/[A-Za-z0-9._-]*' "$tmp/index.html" | sort -u); do
  test -s "$T/$a" || { echo "missing asset $a: not switching" >&2; rm -rf "$tmp"; exit 4; }
done
rm -rf "$T/releases/$R"
mv "$tmp" "$T/releases/$R"
switch "$R"
# prune: keep the newest KEEP releases and the current one; keep every asset a kept release lists
cur="$(readlink "$T/current" | sed 's#releases/##')"
ls -1t "$T/releases" | grep -v '^\.' | tail -n +"$((KEEP + 1))" | while read -r old; do
  [ "$old" = "$cur" ] || rm -rf "$T/releases/$old"
done
keep="$(mktemp)"
cat "$T"/releases/*/.assets 2>/dev/null | sort -u > "$keep"
if [ -s "$keep" ]; then
  ls -1 "$T/assets" | grep -vxF -f "$keep" | while read -r f; do rm -f "$T/assets/$f"; done
fi
rm -f "$keep"
echo "published $R ($(wc -l < "$T/releases/$R/.assets") assets); releases kept: $(ls -1 "$T/releases" | grep -vc '^\.')"
