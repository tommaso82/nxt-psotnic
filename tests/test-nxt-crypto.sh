#!/bin/sh
set -eu
bin="$1"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf 'nick testbot\nsasl-password secret\n' > "$tmp/bot.cfg"
printf 'a long unique testing password 2026\n' > "$tmp/valid.pass"
printf 'wrong password\n' > "$tmp/wrong.pass"
chmod 600 "$tmp/"*.pass
"$bin" config encrypt "$tmp/bot.cfg" --output "$tmp/bot.nxt" --password-file "$tmp/valid.pass"
"$bin" config decrypt "$tmp/bot.nxt" --output "$tmp/recovered.cfg" --password-file "$tmp/valid.pass"
cmp "$tmp/bot.cfg" "$tmp/recovered.cfg"
"$bin" config preview "$tmp/bot.nxt" --password-file "$tmp/valid.pass" > "$tmp/preview.cfg"
cmp "$tmp/bot.cfg" "$tmp/preview.cfg"
test "$(stat -c %a "$tmp/recovered.cfg")" = 600
test "$(stat -c %a "$tmp/bot.nxt")" = 600
if "$bin" config decrypt "$tmp/bot.nxt" --output "$tmp/invalid.cfg" --password-file "$tmp/wrong.pass"; then
  echo 'Wrong password accepted!' >&2; exit 1
fi
test ! -e "$tmp/invalid.cfg"
if "$bin" config encrypt "$tmp/bot.cfg" --output "$tmp/bot.nxt" --password-file "$tmp/valid.pass"; then
  echo 'Overwrite accepted!' >&2; exit 1
fi
printf 'X' | dd of="$tmp/bot.nxt" bs=1 seek=23 conv=notrunc status=none
if "$bin" config decrypt "$tmp/bot.nxt" --output "$tmp/tampered.cfg" --password-file "$tmp/valid.pass"; then
  echo 'Tampered ciphertext accepted!' >&2; exit 1
fi
test ! -e "$tmp/tampered.cfg"
printf 'a long unique testing password 2026\n' | "$bin" config encrypt "$tmp/bot.cfg" --output "$tmp/stdin.nxt" --password-stdin
printf 'a long unique testing password 2026\n' | "$bin" config decrypt "$tmp/stdin.nxt" --output "$tmp/stdin.cfg" --password-stdin
cmp "$tmp/bot.cfg" "$tmp/stdin.cfg"
echo '[+] NXT Crypt standalone tests passed'
