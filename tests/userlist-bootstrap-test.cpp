// Exercise the real NXTCRYPT bootstrap/saver without IRC or a synthetic botnet.
// Modes: create (password + key cache), cached (unattended), manual (password),
// plain (should not initialize any userlist crypto session).
#include "../nxt-crypto.h"
#include <sodium.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <stdexcept>

static long rss() {
    FILE *fp=fopen("/proc/self/status","r");
    if(!fp) return -1;
    char line[256];
    long value=-1;
    while(fgets(line,sizeof(line),fp))
        if(sscanf(line,"VmRSS: %ld kB",&value)==1) break;
    fclose(fp);
    return value;
}
int main(int argc,char **argv) {
    if(argc!=6) return 2;
    const std::string mode(argv[1]);
    const char *cfg=argv[2], *ul=argv[3], *password=argv[4];
    const size_t size=strtoul(argv[5],NULL,10);
    if(size>4*1024*1024) return 2;
    try {
        const long initial=rss();
        nxtcrypto::begin_bootstrap();
        if(mode=="create") {
            nxtcrypto::enable_key_cache();
            nxtcrypto::set_password_file(password);
        } else if(mode=="manual") {
            nxtcrypto::set_password_file(password);
        } else if(mode=="plain") {
            nxtcrypto::set_password_file(password);
        } else if(mode!="cached") return 2;
        const std::string cfg_plain=nxtcrypto::decrypt_file(cfg);
        if(cfg_plain!="nick testbot\n") return 3;
        struct stat st;
        if(lstat(ul,&st)==0) return 4;
        if(errno!=ENOENT) return 5;
        nxtcrypto::prepare_missing_userlist(ul);
        if(lstat(ul,&st)==0 || errno!=ENOENT) return 6;
        const bool active=nxtcrypto::userlist_encrypted_session();
        if(active!=(mode!="plain")) return 7;
        nxtcrypto::finish_bootstrap();
        const long after_init=rss();
        if(active && size) {
            std::string text("# synthetic userlist\n21 42\n82 1700000000\n");
            if(size>text.size()) text.append(size-text.size(),'x');
            nxtcrypto::save_userlist_data(text,ul);
            if(lstat(ul,&st)!=0 || st.st_size<(off_t)text.size()) return 8;
            sodium_memzero(&text[0],text.size());
        }
        struct rusage usage;
        getrusage(RUSAGE_SELF,&usage);
        printf("BOOTSTRAP_METRIC mode=%s bytes=%zu rss_initial_kib=%ld rss_after_init_kib=%ld rss_after_save_kib=%ld rss_peak_kib=%ld\n",
            mode.c_str(),size,initial,after_init,rss(),usage.ru_maxrss);
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"Bootstrap failure: %s\n",e.what());
        return 1;
    }
}
