#!/bin/sh
set -eu
bin="$1"
session="$2"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf 'nick testbot\nsasl-password secret\n' > "$tmp/bot.cfg"
printf 'a long unique testing password 2026\n' > "$tmp/bot.pass"
chmod 600 "$tmp/bot.pass"

"$bin" config encrypt "$tmp/bot.cfg" --output "$tmp/bot.nxt" --password-file "$tmp/bot.pass"

# .cfg-save through the cached session key: new nonce, same salt, and the
# file must still decrypt with the original password afterwards.
before="$(sha256sum "$tmp/bot.nxt" | cut -d' ' -f1)"
dd if="$tmp/bot.nxt" bs=1 skip=18 count=16 of="$tmp/salt-before" status=none
dd if="$tmp/bot.nxt" bs=1 skip=34 count=24 of="$tmp/nonce-before" status=none

"$session" "$tmp/bot.nxt" "$tmp/bot.pass"

after="$(sha256sum "$tmp/bot.nxt" | cut -d' ' -f1)"
test "$before" != "$after"
dd if="$tmp/bot.nxt" bs=1 skip=18 count=16 of="$tmp/salt-after" status=none
dd if="$tmp/bot.nxt" bs=1 skip=34 count=24 of="$tmp/nonce-after" status=none
cmp "$tmp/salt-before" "$tmp/salt-after"
if cmp -s "$tmp/nonce-before" "$tmp/nonce-after"; then
  echo 'ERROR: config AEAD nonce reused' >&2; exit 1
fi

"$bin" config decrypt "$tmp/bot.nxt" --output "$tmp/autosaved.cfg" --password-file "$tmp/bot.pass"
printf '# cfg-save verified\n' >> "$tmp/bot.cfg"
cmp "$tmp/bot.cfg" "$tmp/autosaved.cfg"
test "$(stat -c %a "$tmp/bot.nxt")" = 600
test -z "$(find "$tmp" -name '*.tmp-*' -print -quit)"

echo '[+] NXT config session autosave tests passed'
