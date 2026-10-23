// Standalone regression for the optional unattended local key cache.
#include "../nxt-crypto.h"
#include <cstdio>
#include <string>
#include <stdexcept>
int main(int argc,char **argv) {
    if(argc!=4) return 2;
    try {
        nxtcrypto::begin_bootstrap();
        if(std::string(argv[1])=="create") {
            nxtcrypto::enable_key_cache();
            nxtcrypto::set_password_file(argv[3]);
        } else if(std::string(argv[1])!="cached") return 2;
        std::string plain=nxtcrypto::decrypt_file(argv[2]);
        nxtcrypto::finish_bootstrap();
        if(plain!="nick testbot\n") return 3;
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"%s\n",e.what());
        return 1;
    }
}
