// Plaintext-only implementation for --disable-nxtcrypt builds.
#include "nxt-crypto.h"
#include <cstdlib>
#include <cstdio>
#include <stdexcept>

namespace nxtcrypto {
namespace {
int unavailable() {
    fputs("[-] NXTCRYPT support was not compiled in\n",stderr);
    return 1;
}
void fail() { throw std::runtime_error("NXTCRYPT support is disabled in this build"); }
}
void begin_bootstrap() {}
void finish_bootstrap() {}
void prepare_missing_userlist(const char *path) {
    if(nxtfile::has_nxt_extension(path)) fail();
}
bool config_encrypted_session() { return false; }
bool userlist_encrypted_session() { return false; }
void begin_wizard_encryption() { fail(); }
void finish_wizard_encryption() {}
void enable_key_cache() { fail(); }
void set_password_argument(const char*) { fail(); }
void set_password_file(const char*) { fail(); }
void set_password_stdin() { fail(); }
std::string decrypt_file(const char*) { fail(); return std::string(); }
std::string load_userlist_data(const char*) { fail(); return std::string(); }
void encrypt_plaintext_to_file(const std::string&,const char*) { fail(); }
void save_config_data(std::string&,const char*) { fail(); }
void save_userlist_data(std::string&,const char*) { fail(); }
int config_command(int,char**) { return unavailable(); }
int userlist_command(int,char**) { return unavailable(); }
}
