# nxt-psotnic

nxt-psotnic is a fork of gay-psotnic 0.1.1, preserving full compatibility with classic Psotnic's IRC and botnet behavior. It streamlines configuration management with plaintext by default and optional NXTCRYPT encryption, alongside legacy Blowfish import and outbound SOCKS5 / HTTP CONNECT support.

Current version: **0.1.0-dev**. The executable is still named `psotnic`.

## Build

On Debian, install the build dependencies and run the following from the repository root:

```sh
sudo apt install build-essential perl
perl configure --disable-modules
make dynamic

# TLS is enabled automatically when libssl-dev is installed.

# Optional encrypted storage (requires libsodium-dev):
perl configure --enable-nxtcrypt --disable-modules
make dynamic
```

NXTCRYPT is not compiled by default. Enable it explicitly with `--enable-nxtcrypt`.

The executable is built at `bin/psotnic`.

## Getting started

```sh
./bin/psotnic -n
./bin/psotnic BOT_CONFIG
```

The wizard creates a configuration; use `-ne` for expert mode. Configurations and userlists are plaintext by default. When built with `--enable-nxtcrypt`, enabling encryption in the wizard creates an encrypted `.cfg.nxt` file and, if an initial userlist is created, an encrypted `.ul.nxt` file. Start the bot using the **actual filename** produced by the wizard.

Use `-d` to keep the bot in the foreground. Run `./bin/psotnic --help` for all startup options.

## Encrypted files

Legacy Blowfish import remains available in the default build. NXTCRYPT uses Argon2id and XChaCha20-Poly1305. Configuration saves and userlist autosaves retain encryption when the corresponding file is encrypted.

```sh
./bin/psotnic config encrypt bot.cfg --output bot.cfg.nxt
./bin/psotnic userlist encrypt bot.ul --output bot.ul.nxt
```

**Unattended startup.** Run `./bin/psotnic --key-cache bot.cfg.nxt` once and enter the password. The bot saves a private `bot.key` file containing randomized representations of the derived config and userlist keys, never the original password. Subsequent starts use `./bin/psotnic bot.cfg.nxt` without prompting; removing the cache restores password-based startup. Protect the cache like a decryption key. File-management `decrypt` and `preview` commands always require the password.

Classic Psotnic's Blowfish-encrypted configurations and userlists can be imported using the original bot binary. For supported builds, nxt-psotnic extracts the encryption seed directly from the binary without executing it; the original seed file can also be supplied. The `config` and `userlist` commands support import, decryption and preview. See [encrypted storage](docs/NXT-CONFIG-CRYPTO.md) for usage, supported formats and password handling.

## Outbound proxy

A single SOCKS5 or HTTP CONNECT proxy can route outgoing IRC connections and, optionally, outgoing botnet hub connections:

```text
proxy-type socks5
proxy-host proxy.example.net
proxy-port 1080
proxy-scope irc
```

Set `proxy-scope irc,hub` to include outgoing hub connections. Incoming connections remain direct; proxy failures never trigger a direct fallback. Authentication and other details are covered in [proxy configuration](docs/NXT-PROXY.md).

## Notes

Keep configuration files, userlists, passwords and seed files out of Git. The legacy `.bc update` functionality is disabled.

This project builds on the work credited in [AUTHORS](AUTHORS) and [AUTHORS-psotnic](AUTHORS-psotnic). The original license is retained in [COPYRIGHT.GPL](COPYRIGHT.GPL).
