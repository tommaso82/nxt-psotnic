# NXT-Psotnic Config Crypto v1

This milestone adds **plaintext by default** and an explicit opt-in NXTCRYPT
format. The former Blowfish encryption is intentionally NOT used for new
configurations. Existing legacy encrypted configs must first be imported
using a future legacy-importer milestone; the original files are preserved.

## Build

Install \`libsodium-dev\`, \`pkg-config\`, a C++ compiler and Perl. Then
run the repository's normal \`./configure\` and \`make dynamic\` sequence.

## Usage

- \`./bin/psotnic -n\` creates a **plaintext** config.
- \`./bin/psotnic bot.cfg\` starts from plaintext.
- \`./bin/psotnic config encrypt bot.cfg --output bot.nxt\` encrypts a copy.
- \`./bin/psotnic config preview bot.nxt\` prints **all decrypted contents**, including passwords.
- \`./bin/psotnic config decrypt bot.nxt --output bot.cfg\` saves an unencrypted copy.
- \`./bin/psotnic --password-file /secure/bot.pass bot.nxt\` starts noninteractively.
- \`./bin/psotnic --password-stdin bot.nxt\` reads a password from standard input.
- \`./bin/psotnic --password "secret" bot.nxt\` is supported, but unsafe for normal use
  because command lines may be visible in history, process listings and logs.

Commands also support the three password options. Without one, they prompt on
/dev/tty with echo disabled (encrypt prompts twice). Outputs are created
with 0600 permissions; existing outputs are never overwritten.

## Algorithm and format

Binary format:
\`NXTCRYPT\` (8 bytes), version (1), KDF id (1), ops (4, big endian),
memory (4, big endian), random salt (16), random nonce (24), then
XChaCha20-Poly1305 ciphertext and authentication tag.
The entire 58-byte header is authenticated. Passwords are processed by
Argon2id13 using 32 MiB and three passes with the parameters recorded
in the header for compatibility. Invalid untrusted KDF parameters are bounded.

Argon2id only runs at startup/conversion, not in the IRC event loop.
Existing userlist \`.ul\` encryption is unaffected.

## Scope / limits

**Legacy seed recovery/import, plus SOCKS5/HTTP CONNECT, are NOT included.**
Full bot compilation and integration tests are required before merge.
Never put \`.cfg\`, \`.nxt\`, \`.pass\`, \`.ul\` or generated seed files in Git.
When a systemd service is started unattended, provision the password through a
protected file or systemd credentials. A stored password on the same host as
the ciphertext provides weaker protection than an independently kept password.
