#ifndef NXT_PSOTNIC_FILE_H
#define NXT_PSOTNIC_FILE_H

namespace nxtfile {
bool has_nxt_extension(const char *path);
bool is_nxt_file(const char *path);
bool is_legacy_file(const char *path);
void plaintext_guard(const char *path,const char *what);
}
#endif
