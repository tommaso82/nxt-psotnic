#ifndef NXT_PSOTNIC_LEGACY_H
#define NXT_PSOTNIC_LEGACY_H
#include <string>
namespace nxtlegacy {
std::string legacy_decrypt(const char *input,const char *seed_file,const char *binary);
int import_command(int argc,char **argv);
}
#endif
