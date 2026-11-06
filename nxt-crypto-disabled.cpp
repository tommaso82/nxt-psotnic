// Plaintext-only implementation for --disable-nxtcrypt builds.
#include "nxt-crypto.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <stdexcept>

namespace nxtcrypto {
namespace {
void unavailable() {
    fputs("[-] NXTCRYPT support is disabled in this build\n",stderr);
    std::exit(1);
}
void fail() { throw std::runtime_error("NXTCRYPT support is disabled in this build"); }
}
void begin_bootstrap() {}
void finish_bootstrap() {}
void prepare_missing_userlist(const char *path) {
    const std::size_t len=strlen(path);
    if(len>=4 && strcmp(path+len-4,".nxt")==0) fail();
}
bool config_encrypted_session() { return false; }
bool userlist_encrypted_session() { return false; }
void begin_wizard_encryption() { fail(); }
void finish_wizard_encryption() {}
void enable_key_cache() { unavailable(); }
void set_password_argument(const char*) { unavailable(); }
void set_password_file(const char*) { unavailable(); }
void set_password_stdin() { unavailable(); }
std::string decrypt_file(const char*) { fail(); return std::string(); }
std::string load_userlist_data(const char*) { fail(); return std::string(); }
void encrypt_plaintext_to_file(const std::string&,const char*) { fail(); }
void save_config_data(std::string&,const char*) { fail(); }
void save_userlist_data(std::string&,const char*) { fail(); }
int config_command(int,char**) { unavailable(); return 1; }
int userlist_command(int,char**) { unavailable(); return 1; }
}
