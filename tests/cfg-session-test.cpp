// Standalone storage regression for cached-key .cfg-save on encrypted
// configs, no IRC needed. Mirrors tests/ul-session-test.cpp.
#include "../nxt-crypto.h"
#include <sodium.h>
#include <string>
#include <cstdio>
#include <stdexcept>
int main(int argc,char **argv) {
    if(argc!=3) return 2;
    try {
        // Same startup order as the bot: bootstrap active while the config
        // is decrypted, so the session key gets cached for later saves.
        nxtcrypto::begin_bootstrap();
        nxtcrypto::set_password_file(argv[2]);
        std::string old=nxtcrypto::decrypt_file(argv[1]);
        if(!nxtcrypto::config_encrypted_session()) return 4;
        if(old.find("nick testbot\n")==std::string::npos) return 3;
        std::string updated=old+"# cfg-save verified\n";
        nxtcrypto::save_config_data(updated,argv[1]);
        nxtcrypto::finish_bootstrap();
        if(!old.empty()) sodium_memzero(&old[0],old.size());
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"CFG session failure: %s\n",e.what());
        return 1;
    }
}
