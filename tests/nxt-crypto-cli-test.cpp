#include "../nxt-crypto.h"
#include <cstdio>
int main(int argc,char **argv) {
    if(argc<2) {fprintf(stderr,"Missing config command\n");return 1;}
    return nxtcrypto::config_command(argc,argv);
}
