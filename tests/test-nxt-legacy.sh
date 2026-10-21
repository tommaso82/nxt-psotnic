#!/bin/sh
set -eu
bin="$1"; fixture0="$2"; fixture1="$3"; fixture2="$4"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '# legacy fixture\nnick legacybot\nsasl-password legacysecret\nrealname Legacy Fixture\n' > "$tmp/expected.cfg"
printf 'This is a long unique password for CI tests\n' > "$tmp/new.pass"
chmod 600 "$tmp/new.pass"
"$fixture0" "$tmp/old.cfg"
before="$(sha256sum "$tmp/old.cfg" | awk '{print $1}')"
"$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --output "$tmp/seed.cfg"
cmp "$tmp/expected.cfg" "$tmp/seed.cfg"
test "$(stat -c %a "$tmp/seed.cfg")" = 600
"$bin" config import "$tmp/old.cfg" --binary "$fixture0" --output "$tmp/o0.cfg"
cmp "$tmp/expected.cfg" "$tmp/o0.cfg"
"$bin" config import "$tmp/old.cfg" --binary "$fixture1" --output "$tmp/o1.cfg"
cmp "$tmp/expected.cfg" "$tmp/o1.cfg"
"$bin" config import "$tmp/old.cfg" --binary "$fixture2" --output "$tmp/o2.cfg"
cmp "$tmp/expected.cfg" "$tmp/o2.cfg"
"$bin" config import "$tmp/old.cfg" --binary "$fixture2" --preview > "$tmp/preview.cfg"
cmp "$tmp/expected.cfg" "$tmp/preview.cfg"
"$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --to nxt --output "$tmp/migrated.nxt" --password-file "$tmp/new.pass"
"$bin" config decrypt "$tmp/migrated.nxt" --output "$tmp/recovered.cfg" --password-file "$tmp/new.pass"
cmp "$tmp/expected.cfg" "$tmp/recovered.cfg"
test "$(stat -c %a "$tmp/migrated.nxt")" = 600
printf 'static unsigned char cfg_seed[] = "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00";\n' > "$tmp/bad-seed.h"
if "$bin" config import "$tmp/old.cfg" --seed-file "$tmp/bad-seed.h" --output "$tmp/unexpected.cfg"; then
 echo 'Wrong seed accepted' >&2;exit 1
fi
test ! -e "$tmp/unexpected.cfg"
if "$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --output "$tmp/seed.cfg";then
 echo 'Overwrite accepted' >&2;exit 1
fi
after="$(sha256sum "$tmp/old.cfg" | awk '{print $1}')"
test "$before" = "$after"
echo '[+] Legacy importer tests passed'
