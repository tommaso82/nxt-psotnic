# nxt-psotnic

nxt-psotnic is a fork of gay-psotnic 0.1.1. It retains the original IRC and botnet architecture while adding encrypted configuration and userlist files, migration from legacy Blowfish storage, and optional outbound proxy support.

Current version: **0.1.0-dev**. The executable is still named `psotnic`.

## Build

On Debian, install the build dependencies and run the following from the repository root:

```sh
sudo apt install build-essential perl libsodium-dev libssl-dev
perl configure --disable-modules
make dynamic
```

The executable is built at `bin/psotnic`.

## Getting started

```sh
./bin/psotnic -n
./bin/psotnic BOT_CONFIG
```

The wizard creates a configuration; use `-ne` for expert mode. Encryption is optional and disabled by default. When enabled, the wizard writes an encrypted `.cfg.nxt` file and, if an initial userlist is created, an encrypted `.ul.nxt` file. Start the bot using the **actual filename** produced by the wizard.

Use `-d` to keep the bot in the foreground. Run `./bin/psotnic --help` for all startup options.

## Encrypted files

NXTCRYPT uses Argon2id and XChaCha20-Poly1305. Configuration saves and userlist autosaves retain encryption when the corresponding file is encrypted.

```sh
./bin/psotnic config encrypt bot.cfg --output bot.cfg.nxt
./bin/psotnic userlist encrypt bot.ul --output bot.ul.nxt
```

The `config` and `userlist` commands also support decryption, preview and import of legacy Blowfish files. Run `./bin/psotnic config --help` or `./bin/psotnic userlist --help` for the available options. See [encrypted storage](docs/NXT-CONFIG-CRYPTO.md) for file format, migration and password handling.

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

Keep configuration files, userlists, passwords and seed files out of Git. The historical `.bc update` command uses a separate plaintext HTTP updater and should not be used until reviewed.

This project builds on the work credited in [AUTHORS](AUTHORS) and [AUTHORS-psotnic](AUTHORS-psotnic). The original license is retained in [COPYRIGHT.GPL](COPYRIGHT.GPL).
