// Test-only legacy format fixture, intentionally resembles make-hiddenseed.c output.
#include "../prots.h"
#include <fstream>
#include <cstring>
#include <cstdio>
#include <vector>
__attribute__((noinline)) void gen_cfg_seed(unsigned char *out) {
    int i;
    out[0]=181;
    out[1]=146;
    out[2]=240;
    out[3]=222;
    out[4]=60;
    out[5]=26;
    out[6]=120;
    out[7]=86;
    out[8]=169;
    out[9]=184;
    out[10]=139;
    out[11]=154;
    out[12]=237;
    out[13]=252;
    out[14]=207;
    out[15]=222;
    for(i=0;i<16;++i) out[i]^=166;
}
int main(int argc,char **argv) {
    if(argc!=2) {fprintf(stderr,"Usage: legacy-fixture OUTPUT.cfg\n");return 2;}
    unsigned char seed[16];
    gen_cfg_seed(seed);
    CBlowFish blowfish;
    blowfish.Initialize(seed,16);
    memset(seed,0,sizeof(seed));
    std::ofstream f(argv[1],std::ios::binary);
    if(!f) return 2;
    psotnicHeader header;
    memset(&header,0,sizeof(header));
    strcpy(header.id,"psotnic");
    header.version=3;
    f.write(reinterpret_cast<const char*>(&header),sizeof(header));
    const char *lines[]={
        "# legacy fixture\n",
        "nick legacybot\n",
        "sasl-password legacysecret\n",
        "realname Legacy Fixture\n"
    };
    for(size_t i=0;i<sizeof(lines)/sizeof(lines[0]);++i) {
        const size_t count=strlen(lines[i]);
        std::vector<unsigned char> cipher(count+8,0);
        DWORD len=blowfish.Encode((unsigned char*)lines[i],cipher.data(),(DWORD)count);
        f.write(reinterpret_cast<const char*>(cipher.data()),len);
    }
    return f?0:1;
}
