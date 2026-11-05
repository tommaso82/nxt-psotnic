// Plaintext-only implementation for --disable-nxtcrypt builds.
#include "nxt-crypto.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <stdexcept>

namespace nxtcrypto {
namespace {
bool has_magic(const char *path,const char *magic) {
    std::ifstream f(path,std::ios::binary);
    char head[8];
    return bool(f.read(head,sizeof(head))) && memcmp(head,magic,sizeof(head))==0;
}
void unavailable() {
    fputs("[-] NXTCRYPT support is disabled in this build\n",stderr);
    std::exit(1);
}
void fail() { throw std::runtime_error("NXTCRYPT support is disabled in this build"); }
}
bool is_nxt_file(const char *path) { return has_magic(path,"NXTCRYPT"); }
bool is_legacy_file(const char *path) { return has_magic(path,"psotnic\0"); }
void plaintext_guard(const char *path,const char *what) {
    const std::size_t len=strlen(path);
    if(len>=4 && strcmp(path+len-4,".nxt")==0)
        throw std::runtime_error(std::string("refusing to write plaintext ")+what+" into .nxt");
    if(is_nxt_file(path) || is_legacy_file(path))
        throw std::runtime_error(std::string("refusing to overwrite an encrypted ")+what+" with plaintext");
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
