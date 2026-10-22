# Encrypted storage

NXTCRYPT v1 protects configuration and userlist files at rest. New files are plaintext by default; `-n` and `-ne` offer encryption during setup. When both files are created encrypted, they share a password but use independent random salts and nonces. The wizard never creates intermediate plaintext copies.

## File operations

```sh
./bin/psotnic config encrypt bot.cfg --output bot.cfg.nxt
./bin/psotnic config decrypt bot.cfg.nxt --output bot.cfg
./bin/psotnic config preview bot.cfg.nxt
./bin/psotnic userlist encrypt bot.ul --output bot.ul.nxt
```

The `config` and `userlist` commands accept the same `encrypt`, `decrypt`, `preview` and `import` operations. Passwords are requested interactively unless `--password-file FILE` or `--password-stdin` is supplied. Avoid `--password TEXT`, which can expose secrets in process arguments. `preview` prints decrypted credentials to standard output.

New outputs are created with mode `0600` and are not allowed to overwrite existing files. Encrypted userlists must be referenced by their encrypted filename in the bot configuration.

## Legacy Blowfish migration

```sh
./bin/psotnic config import old.cfg --binary ./old-psotnic --output bot.cfg.nxt --to nxt
```

Use `userlist import` for old userlists, or `--seed-file FILE` instead of `--binary` when the original seed is available. `--to nxt` encrypts the recovered content without writing a plaintext intermediate file; the default output format is plaintext.

The importer reads but never executes the supplied binary. Binary seed recovery is heuristic, supports tested GCC x86-64 ELF patterns, and may fail with other builds. Prefer the original seed file when available. Keep legacy backups until the converted files have been verified.

## Format and saving

The binary format starts with a 58-byte authenticated header: `NXTCRYPT` magic (8 bytes), version (1), KDF identifier (1), Argon2id parameters (two 4-byte big-endian values), salt (16) and nonce (24). An XChaCha20-Poly1305 ciphertext and authentication tag follow. Default key derivation uses Argon2id13 with 32 MiB of memory and three passes; parameters read from files are bounded.

At startup, the bot derives and retains the keys needed for encrypted `.cfg-save` and userlist autosaves. Each save uses a fresh nonce and an atomic, permission-restricted file replacement; Argon2id is not rerun on every save. Userlist synchronization over the botnet is unchanged.

Encryption protects files at rest, not a compromised running process. Protect unattended password files and avoid committing credentials or recovered plaintext to the repository.
