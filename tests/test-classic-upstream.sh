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
echo '[+] SUCCESS: recovered the correct cfg seed from genuinely compiled gay-psotnic binaries'
