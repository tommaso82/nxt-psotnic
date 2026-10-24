#include "nxt-file.h"
#include <cstring>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <string>

namespace nxtfile {
bool has_nxt_extension(const char *path) {
    const size_t size = strlen(path);
    return size >= 4 && !strcasecmp(path + size - 4, ".nxt");
}
namespace {
bool has_magic(const char *path,const char *magic) {
    const int fd=::open(path,O_RDONLY);
    if(fd<0) return false;
    char header[8];
    size_t len=0;
    while(len<sizeof header) {
        const ssize_t n=::read(fd,header+len,sizeof header-len);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) break;
        len+=static_cast<size_t>(n);
    }
    ::close(fd);
    return len==sizeof header && !memcmp(header,magic,sizeof header);
}
}
bool is_nxt_file(const char *path) {
    return has_magic(path,"NXTCRYPT");
}
bool is_legacy_file(const char *path) {
    return has_magic(path,"psotnic\0");
}
void plaintext_guard(const char *path,const char *what) {
    if(has_nxt_extension(path))
        throw std::runtime_error(std::string("refusing to write plaintext ")+what+
                                 " into .nxt; explicitly encrypt first");
    if(is_nxt_file(path) || is_legacy_file(path))
        throw std::runtime_error(std::string("refusing to overwrite an encrypted ")+what+
                                 " with plaintext");
}
} // namespace nxtfile
