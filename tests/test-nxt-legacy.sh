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
cp "$fixture2" "$tmp/stripped-old-bot"
strip "$tmp/stripped-old-bot"
"$bin" config import "$tmp/old.cfg" --binary "$tmp/stripped-old-bot" --output "$tmp/stripped.cfg"
cmp "$tmp/expected.cfg" "$tmp/stripped.cfg"
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
# .nxt selects encrypted output unless the format is explicitly specified.
"$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --output "$tmp/inferred.cfg.nxt" --password-file "$tmp/new.pass"
"$bin" config decrypt "$tmp/inferred.cfg.nxt" --output "$tmp/inferred.cfg" --password-file "$tmp/new.pass"
cmp "$tmp/expected.cfg" "$tmp/inferred.cfg"
"$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --to nxt --output "$tmp/appended.cfg" --password-file "$tmp/new.pass"
test -f "$tmp/appended.cfg.nxt"
test ! -e "$tmp/appended.cfg"
"$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --to nxt --output "$tmp/exact.nxt" --password-file "$tmp/new.pass"
test -f "$tmp/exact.nxt"
test ! -e "$tmp/exact.nxt.nxt"
if "$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --to plain --output "$tmp/reject.nxt"; then
  echo 'Contradictory plaintext extension accepted' >&2; exit 1
fi
test ! -e "$tmp/reject.nxt"
if "$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --preview --to nxt > "$tmp/bad-preview"; then
  echo 'Preview with --to accepted' >&2; exit 1
fi
test ! -s "$tmp/bad-preview"
if "$bin" config import "$tmp/old.cfg" --seed-file tests/fixtures/legacy-seed.h --preview --output "$tmp/reject.cfg"; then
  echo 'Preview with --output accepted' >&2; exit 1
fi
test ! -e "$tmp/reject.cfg"
echo '[+] Legacy importer tests passed'
