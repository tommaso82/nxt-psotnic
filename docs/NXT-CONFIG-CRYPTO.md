# NXT-Psotnic Config Crypto v1

This milestone adds **plaintext by default** and an explicit opt-in NXTCRYPT
format. The former Blowfish encryption is intentionally NOT used for new
configurations. Existing legacy encrypted configs must first be imported
using the explicit legacy importer. The original files are always preserved.

## Build

Install `libsodium-dev`, `pkg-config`, a C++ compiler and Perl. Then
run the repository's normal `./configure` and `make dynamic` sequence.

## Usage

- `./bin/psotnic -n` creates a **plaintext** config.
- `./bin/psotnic bot.cfg` starts from plaintext.
- `./bin/psotnic config encrypt bot.cfg --output bot.nxt` encrypts a copy.
- `./bin/psotnic config preview bot.nxt` prints **all decrypted contents**, including passwords.
- `./bin/psotnic config decrypt bot.nxt --output bot.cfg` saves an unencrypted copy.
- `./bin/psotnic --password-file /secure/bot.pass bot.nxt` starts noninteractively.
- `./bin/psotnic --password-stdin bot.nxt` reads a password from standard input.
- `./bin/psotnic --password "secret" bot.nxt` is supported, but unsafe for normal use
  because command lines may be visible in history, process listings and logs.
- The partyline `.cfg-save` command works at runtime: with a plaintext config the
  file is atomically replaced; with an NXTCRYPT config the key derived at startup
  (cached in memory like the userlist session key) re-encrypts the file with a
  fresh nonce, so the config never lands on disk as plaintext.

Commands also support the three password options. Without one, they prompt on
/dev/tty with echo disabled (encrypt prompts twice). Outputs are created
with 0600 permissions; existing outputs are never overwritten.

## Legacy importer

Import a Psotnic Blowfish v3 config (12-byte header, independent per-line
8-byte Blowfish blocks). The importer NEVER runs supplied executable files.

- `./bin/psotnic config import old.cfg --seed-file old-seed.h --preview`
  prints the entire recovered configuration, **including credentials**.
- `./bin/psotnic config import old.cfg --seed-file old-seed.h --output new.cfg`
  saves plaintext (mode 0600, never overwrites).
- `./bin/psotnic config import old.cfg --binary ./old-psotnic --output new.cfg`
  searches the **data and instruction bytes** of the old ELF x86-64 executable
  for specific patterns of the compiler-generated `gen_cfg_seed` function.
- `./bin/psotnic config import old.cfg --binary ./old-psotnic --output new.nxt --to nxt`
  deciphers the legacy file in memory, asks for a NXT Crypt password (or accepts
  --password-file/--password-stdin/--password), and writes a new encrypted
  copy without intermediate plaintext files.

`--seed-file` and `--binary` are alternatives; one must be present.
`--preview` is explicit and always shows passwords in clear text.

**Limits:** Binary extraction is heuristic and only recognizes tested GCC
x86-64 ELF patterns (O0/O1/O2). Older 32-bit executables, different compilers,
other optimization modes, or heavily modified binaries may not be recoverable.
The file must validate plausibly as a config before any output is written.
Because legacy Blowfish is unauthenticated, plausibility checks are not a
cryptographic guarantee. `--seed-file` is preferred whenever available.

Userlist support now has its own import path and encrypted at-rest autosave.
See docs/USERLIST-CRYPTO.md for commands and compatibility details.

## Algorithm and format

Binary format:
`NXTCRYPT` (8 bytes), version (1), KDF id (1), ops (4, big endian),
memory (4, big endian), random salt (16), random nonce (24), then
XChaCha20-Poly1305 ciphertext and authentication tag.
The entire 58-byte header is authenticated. Passwords are processed by
Argon2id13 using 32 MiB and three passes with the parameters recorded
in the header for compatibility. Invalid untrusted KDF parameters are bounded.

Argon2id only runs at startup/conversion, not in the IRC event loop.
Existing userlist `.ul` encryption is unaffected.

## Scope / limits

**SOCKS5/HTTP CONNECT are NOT included.**
Full bot compilation and integration tests are required before merge.
Never put `.cfg`, `.nxt`, `.pass`, `.ul` or generated seed files in Git.
When a systemd service is started unattended, provision the password through a
protected file or systemd credentials. A stored password on the same host as
the ciphertext provides weaker protection than an independently kept password.
