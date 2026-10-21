#ifndef NXT_PSOTNIC_CRYPTO_H
#define NXT_PSOTNIC_CRYPTO_H
#include <string>
namespace nxtcrypto {
bool is_nxt_file(const char *path);
bool is_legacy_file(const char *path);
void set_password_argument(const char *password);
void set_password_file(const char *path);
void set_password_stdin();
std::string decrypt_file(const char *path);
int config_command(int argc,char **argv);
}
#endif
