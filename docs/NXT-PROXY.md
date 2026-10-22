# NXT-Psotnic: lightweight outbound proxy

Optional **global** proxy routing for outgoing IRC and, if selected, outgoing
HUB connections. Incoming botnet / partyline listeners are untouched. There
is no per-server override and no automatic direct fallback.

## Configuration

Example SOCKS5 (username/password, RFC 1929):

```text
proxy-type socks5
proxy-host proxy.example.net
proxy-port 1080
proxy-user myuser
proxy-pass mysecret
proxy-scope irc
```

Example HTTP CONNECT:

```text
proxy-type http
proxy-host 192.0.2.10
proxy-port 8080
proxy-scope irc,hub
```

- `proxy-type`: `none` (default), `socks5`, `http` (HTTP CONNECT).
- `proxy-host`: one global endpoint, IPv4, IPv6 or hostname.
- `proxy-port`: TCP port (mandatory when enabled).
- `proxy-user`, `proxy-pass`: optional Basic or RFC1929 credentials.
- `proxy-scope`: `irc` (default), or `irc,hub`.
- The configured password is redacted in bot configuration queries and
  acknowledgements, but remains available to the network handshake.
- Config files with proxy credentials should be encrypted using NXTCRYPT
  or protected with filesystem permissions.

## Connection behavior

An asynchronous TCP connection is established to the proxy rather than the
IRC/hub endpoint. SOCKS5 negotiates authentication (if configured) and a
TCP CONNECT request. HTTP CONNECT uses HTTP/1.1 and Basic proxy authentication
when configured. Destination hostnames are transmitted to the proxy, so the
proxy resolves them remotely; only the proxy's own address is resolved locally.
For builds compiled without ADNS, NXT defers original host lookups until the
global proxy scope is known to prevent eager destination DNS resolution.

The existing IRC registration and optional TLS are initiated **after** the
tunnel is authenticated. The outgoing botnet hub performs its normal
authentication/crypt setup after tunnel establishment, without changes to
botnet framing. Existing reconnect timers remain in charge of retries.
Never fall back to direct TCP if a configured proxy fails.

All handshakes run on the existing select() loop with bounded buffers.
There are no new threads, background processes or third-party dependencies.
Disabled proxies use the original direct connection path.

## Limits and security

SOCKS5 username/password and HTTP CONNECT Basic credentials are not encrypted
in transit to the proxy itself. Use a trusted proxy, trusted network, or a
secure transport to the proxy separately. IRC TLS still protects the IRC leg
through the tunnel but does not retroactively protect proxy authentication.
Only the two outgoing sockets (IRC and optional HUB) are routed through the
proxy; the historical HTTP updater remains independent and should be audited
before use.

Handshake regression tests: `tests/test-nxt-proxy.cpp`. CI builds the bot
both with default resolver support and with `--disable-adns`.

Do not merge this draft feature until a live IRC/hub handshake test has also
been completed with realistic proxy and network conditions.
