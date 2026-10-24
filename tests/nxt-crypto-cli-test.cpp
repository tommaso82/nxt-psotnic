#include "../nxt-crypto.h"
#include "../nxt-legacy.h"
#include <cstdio>
#include <cstring>
int main(int argc,char **argv) {
    if(argc<2) {fprintf(stderr,"Missing config command\n");return 1;}
    if(argc>2 && !strcmp(argv[2],"import"))
        return nxtlegacy::import_command(argc,argv);
    return nxtcrypto::config_command(argc,argv);
}
