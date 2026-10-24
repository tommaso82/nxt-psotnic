#!/bin/sh
set -eu
nxt="$1"
classic="$2"
fixture="$3"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# This is the actual original psotnic binary compiled from upstream sources.
test -x "$classic"
test -s "$classic"
test -s "$fixture"
printf '# compiled-classic-gay-psotnic\nnick actualclassic\nrealname Authentic classic build test\nsasl-password TestValue-not-a-real-password\n' > "$tmp/expected.cfg"

# The legacy ciphertext is generated with the seed emitted by original
# configure, using the ORIGINAL upstream class-blowfish.cpp.
"$fixture" "$tmp/real-classic.cfg"
sum_before="$(sha256sum "$tmp/real-classic.cfg" | cut -d' ' -f1)"

echo '[*] Reference test: original classic seed.h'
"$nxt" config import "$tmp/real-classic.cfg" --seed-file classic/seed.h --output "$tmp/seed.cfg"
cmp "$tmp/expected.cfg" "$tmp/seed.cfg"

echo '[*] Real binary test: unmodified classic/bin/psotnic'
"$nxt" config import "$tmp/real-classic.cfg" --binary "$classic" --output "$tmp/real-binary.cfg"
cmp "$tmp/expected.cfg" "$tmp/real-binary.cfg"

echo '[*] Real binary test: stripped copy of classic/bin/psotnic'
cp "$classic" "$tmp/stripped-classic"
strip "$tmp/stripped-classic"
"$nxt" config import "$tmp/real-classic.cfg" --binary "$tmp/stripped-classic" --output "$tmp/stripped.cfg"
cmp "$tmp/expected.cfg" "$tmp/stripped.cfg"

sum_after="$(sha256sum "$tmp/real-classic.cfg" | cut -d' ' -f1)"
test "$sum_before" = "$sum_after"

echo '[*] Real userlist: generated with upstream ul_seed'
"$fixture" "$tmp/real-classic.ul" ul
printf '# classic userlist\n21 42\n82 1700000000\n' > "$tmp/expected.ul"
"$nxt" userlist import "$tmp/real-classic.ul" --seed-file classic/seed.h --output "$tmp/userlist-seed.ul"
cmp "$tmp/expected.ul" "$tmp/userlist-seed.ul"

echo '[*] Recover ul_seed statically from real classic/bin/psotnic'
"$nxt" userlist import "$tmp/real-classic.ul" --binary "$classic" --output "$tmp/userlist-binary.ul"
cmp "$tmp/expected.ul" "$tmp/userlist-binary.ul"

echo '[*] Recover ul_seed from stripped real classic/bin/psotnic'
"$nxt" userlist import "$tmp/real-classic.ul" --binary "$tmp/stripped-classic" --output "$tmp/userlist-stripped.ul"
cmp "$tmp/expected.ul" "$tmp/userlist-stripped.ul"

echo '[*] Migrate original Blowfish UL directly to NXTCRYPT'
"$nxt" userlist import "$tmp/real-classic.ul" --seed-file classic/seed.h --to nxt --output "$tmp/userlist.nxt" --password 'classic-test-ul-secret'
"$nxt" userlist decrypt "$tmp/userlist.nxt" --output "$tmp/recovered.ul" --password 'classic-test-ul-secret'
cmp "$tmp/expected.ul" "$tmp/recovered.ul"

echo '[*] Cached-key encrypted userlist autosave, salt unchanged and nonce rotated'
printf 'classic-test-ul-secret\n' > "$tmp/ul.pass"
chmod 600 "$tmp/ul.pass"
before="$(sha256sum "$tmp/userlist.nxt" | cut -d' ' -f1)"
dd if="$tmp/userlist.nxt" bs=1 skip=18 count=16 of="$tmp/salt-before" status=none
dd if="$tmp/userlist.nxt" bs=1 skip=34 count=24 of="$tmp/nonce-before" status=none
/tmp/nxt-ul-session-test "$tmp/userlist.nxt" "$tmp/ul.pass"
after="$(sha256sum "$tmp/userlist.nxt" | cut -d' ' -f1)"
test "$before" != "$after"
dd if="$tmp/userlist.nxt" bs=1 skip=18 count=16 of="$tmp/salt-after" status=none
dd if="$tmp/userlist.nxt" bs=1 skip=34 count=24 of="$tmp/nonce-after" status=none
cmp "$tmp/salt-before" "$tmp/salt-after"
if cmp -s "$tmp/nonce-before" "$tmp/nonce-after"; then
  echo 'ERROR: userlist AEAD nonce reused' >&2;exit 1
fi
"$nxt" userlist decrypt "$tmp/userlist.nxt" --output "$tmp/autosaved.ul" --password-file "$tmp/ul.pass"
printf '# atomic autosave verified\n' >> "$tmp/expected.ul"
cmp "$tmp/expected.ul" "$tmp/autosaved.ul"
test "$(stat -c %a "$tmp/userlist.nxt")" = 600
test -z "$(find "$tmp" -name '*.tmp-*' -print -quit)"


# Userlist imports share the same filename/format rules as configs.
"$nxt" userlist import "$tmp/real-classic.ul" --seed-file classic/seed.h --output "$tmp/auto.ul.nxt" --password-file "$tmp/ul.pass"
"$nxt" userlist decrypt "$tmp/auto.ul.nxt" --output "$tmp/auto.ul" --password-file "$tmp/ul.pass"
printf '# classic userlist\n21 42\n82 1700000000\n' > "$tmp/original-expected.ul"
cmp "$tmp/original-expected.ul" "$tmp/auto.ul"
"$nxt" userlist import "$tmp/real-classic.ul" --seed-file classic/seed.h --to nxt --output "$tmp/appended.ul" --password-file "$tmp/ul.pass"
test -f "$tmp/appended.ul.nxt"
test ! -e "$tmp/appended.ul"
if "$nxt" userlist import "$tmp/real-classic.ul" --seed-file classic/seed.h --to plain --output "$tmp/plain.ul.nxt"; then
  echo 'Plaintext userlist with .nxt extension accepted' >&2; exit 1
fi
test ! -e "$tmp/plain.ul.nxt"
echo '[+] SUCCESS: recovered the correct cfg and ul seeds from genuinely compiled gay-psotnic binaries'
