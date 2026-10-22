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
void encrypt_plaintext_to_file(const std::string& content, const char *path);
int config_command(int argc,char **argv);
int userlist_command(int argc,char **argv);
void begin_bootstrap();
void finish_bootstrap();
std::string load_userlist_data(const char *path);
void save_userlist_data(const std::string& content,const char *path);
bool userlist_encrypted_session();
}
#endif
