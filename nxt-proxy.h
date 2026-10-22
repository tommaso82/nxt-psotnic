#ifndef NXT_PROXY_H
#define NXT_PROXY_H
// Small, nonblocking outbound TCP CONNECT engine. No heap allocations.
// One instance per proxied outbound connection; never used on listeners.
#include <cstddef>
#include <cstdint>
#include <sys/select.h>
namespace nxtproxy {
enum Type { NONE=0, SOCKS5=1, HTTP_CONNECT=2 };
enum Phase { IDLE=0, TCP, SENDING, READING, ESTABLISHED, FAILED };
struct Session {
    int fd;
    Type type;
    Phase phase;
    unsigned char stage; // SOCKS5: 0 method, 1 authentication, 2 connect; HTTP: 0
    unsigned char tx[1536];
    unsigned char rx[2048];
    size_t txlen, txpos, rxlen, expected;
    char target[256], user[256], pass[256];
    uint16_t port;
    Session();
    void reset();
    bool begin(int socket_fd,Type protocol,const char *host,unsigned short dst_port,
               const char *username,const char *password);
    bool active(int socket_fd) const;
    bool want_write() const;
    bool want_read() const;
    // Return 1 on fully authenticated tunnel, 0 while negotiating, -1 on failure.
    int step(bool readable,bool writable);
private:
    bool compose();
    int consume();
    int fail();
};
const char *strip_host_prefix(const char *s);
extern Session irc;
extern Session hub;
extern bool defer_dns;
Type parse_type(const char *value);
}
#endif
