# Outbound proxy

nxt-psotnic supports one global proxy for outgoing IRC connections and, optionally, outgoing botnet hub connections. Incoming connections are unaffected. There is no per-server override or fallback to a direct connection if the proxy fails.

## Configuration

Add these directives to the bot configuration:

```text
proxy-type socks5
proxy-host proxy.example.net
proxy-port 1080
proxy-scope irc
```

- `proxy-type`: `none` (default), `socks5`, or `http` (HTTP CONNECT).
- `proxy-host` and `proxy-port`: proxy hostname or IP address and TCP port.
- `proxy-scope`: `irc` (default) or `irc,hub` for outgoing hub connections too.
- `proxy-user` and `proxy-pass`: optional authentication credentials.

SOCKS5 supports username/password authentication; HTTP CONNECT uses Basic authentication when credentials are supplied. The configured password is redacted from bot configuration queries.

## Connection and security

The bot establishes the proxy tunnel before starting IRC registration, optional IRC TLS, or hub authentication. Destination hostnames are sent to the proxy for resolution; only the proxy endpoint is resolved locally. Handshakes are nonblocking and use the existing event loop.

SOCKS5 username/password and HTTP Basic **do not encrypt credentials on the connection to the proxy**. Use a trusted proxy and network, and protect the configuration file. IRC TLS protects traffic through the established tunnel, not the preceding proxy authentication.

The historical HTTP updater operates separately and does not use this proxy. Automated handshake tests are included, but deployment should also be checked against the intended IRC and proxy servers.
