// Standalone storage regression for live userlist autosave, no IRC needed.
#include "../nxt-crypto.h"
#include <sodium.h>
#include <string>
#include <cstdio>
#include <cstring>
#include <stdexcept>
int main(int argc,char **argv) {
    if(argc!=3) return 2;
    try {
        nxtcrypto::set_password_file(argv[2]);
        std::string old=nxtcrypto::load_userlist_data(argv[1]);
        if(old.find("21 42\n")==std::string::npos ||
           old.find("82 1700000000\n")==std::string::npos) return 3;
        const std::string updated=old+"# atomic autosave verified\n";
        nxtcrypto::save_userlist_data(updated,argv[1]);
        nxtcrypto::finish_bootstrap();
        if(!old.empty()) sodium_memzero(&old[0],old.size());
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"UL session failure: %s\n",e.what());
        return 1;
    }
}
