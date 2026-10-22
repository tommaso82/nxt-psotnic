# NXT-Psotnic

NXT-Psotnic is a lightweight IRC bot forked from gay-psotnic. It preserves
the historical IRC and botnet behavior, and adds encrypted config/userlist
files and optional global SOCKS5 / HTTP CONNECT for outgoing connections.

The executable remains named **psotnic** for compatibility with existing scripts.
The startup/version banner displays NXT-Psotnic 0.1.0-dev and credits the
original gay-psotnic 0.1.1 release. Colors are limited to interactive
terminals (set NO_COLOR=1 to disable); redirected output is plain ASCII.
Run **./bin/psotnic** without arguments for a short getting-started summary,
**./bin/psotnic -h** or **--help** for the full guide, or
**./bin/psotnic config --help** / **userlist --help** for detailed file commands.

## Build (Debian)

    sudo apt update
    sudo apt install git build-essential perl libsodium-dev libssl-dev
    git clone -b feature/config-crypto-v1 --single-branch https://github.com/tommaso82/nxt-psotnic.git
    cd nxt-psotnic
    perl configure --disable-modules
    make dynamic
    ./bin/psotnic --help

The configure script probes libsodium by compiling and linking against -lsodium;
pkg-config is not required.

## Create and start a bot

Run from the repository root:

    ./bin/psotnic -n
    ./bin/psotnic -ne

The first command opens the normal configuration wizard; the second selects
expert mode. Save the configuration when prompted (the suggested filename is
the selected nickname with .cfg appended). For a main bot, the wizard can
also create an initial userlist.

Start using the **actual filename** chosen in the wizard:

    ./bin/psotnic mybot.cfg

To see startup logs rather than forking, set 'dontfork ON' in the config.
If you run from bin/ instead, adjust the relative path: ../mybot.cfg.

## Encrypt or import config/userlist

    ./bin/psotnic config encrypt mybot.cfg --output mybot.cfg.nxt
    ./bin/psotnic mybot.cfg.nxt

Commands prompt for a password by default. Non-interactive usage can specify
--password-file FILE (protect with chmod 600) or --password-stdin.
Avoid --password TEXT because process arguments may expose passwords.

To inspect/decrypt an NXT-encrypted config:

    ./bin/psotnic config preview mybot.cfg.nxt
    ./bin/psotnic config decrypt mybot.cfg.nxt --output recovered.cfg

To import historical Blowfish files, supply the original binary or seed file:

    ./bin/psotnic config import old.cfg --binary /path/to/old-psotnic --output mybot.cfg
    ./bin/psotnic userlist import old.ul --binary /path/to/old-psotnic --output mybot.ul

Use --to nxt during import to create an NXT-encrypted output directly.
Keep backups of the historical files until migration has been verified.

## Outgoing proxy (global)

Example SOCKS5 config directives:

    proxy-type socks5
    proxy-host proxy.example.net
    proxy-port 1080
    proxy-user username
    proxy-pass password
    proxy-scope irc

Supported types: none (default), socks5, http (HTTP CONNECT). Credentials
are optional. Scope 'irc' applies to all outgoing IRC servers;
'irc,hub' also covers outgoing hub connections. Incoming sockets are not
proxied and proxy failure does not cause a direct connection fallback.
See docs/NXT-PROXY.md for technical and security details.

Proxy credentials are not encrypted in transit to the proxy by SOCKS5
username/password or HTTP Basic alone; use a trusted proxy connection.

## Built-in command guide

    ./bin/psotnic --help
    ./bin/psotnic -h
    ./bin/psotnic --version
    ./bin/psotnic config --help
    ./bin/psotnic userlist --help

Please test with your real IRC/proxy environment before production.
The historical .bc update command still uses an old plaintext HTTP updater
and should not be used until it has been reviewed.
