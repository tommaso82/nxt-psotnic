#include "nxt-file.h"
#include <cstring>
#include <strings.h>
#include <fstream>
#include <stdexcept>
#include <string>

namespace nxtfile {
bool has_nxt_extension(const char *path) {
    const size_t size = strlen(path);
    return size >= 4 && !strcasecmp(path + size - 4, ".nxt");
}
bool is_nxt_file(const char *path) {
    std::ifstream f(path,std::ios::binary);
    char b[8];return (bool)f.read(b,8) && memcmp(b,"NXTCRYPT",8)==0;
}
bool is_legacy_file(const char *path) {
    std::ifstream f(path,std::ios::binary);
    char b[8];return (bool)f.read(b,8) && memcmp(b,"psotnic",7)==0 && b[7]=='\0';
}
void plaintext_guard(const char *path,const char *what) {
    const size_t pathlen=strlen(path);
    if(pathlen>=4 && memcmp(path+pathlen-4,".nxt",4)==0)
        throw std::runtime_error(std::string("refusing to write plaintext ")+what+
                                 " into .nxt; explicitly encrypt first");
    if(is_nxt_file(path) || is_legacy_file(path))
        throw std::runtime_error(std::string("refusing to overwrite an encrypted ")+what+
                                 " with plaintext");
}
} // namespace nxtfile
