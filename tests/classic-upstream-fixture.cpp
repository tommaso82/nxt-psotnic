// Integration fixture for the ACTUAL upstream psotnic/gay-psotnic build.
// Compile against original class-blowfish.cpp and the freshly generated
// classic/seed.h. The expected plaintext must match the test script.
// This does not invoke the original bot or publish its randomly generated seed.
#include "prots.h"
#include "seed.h"
#include <cstring>
#include <fstream>
#include <vector>
#include <cstdio>

int main(int argc,char **argv) {
    if(argc != 2) return 2;
    CBlowFish blowfish;
    blowfish.Initialize(cfg_seed,16);

    std::ofstream out(argv[1],std::ios::binary);
    if(!out) return 3;

    psotnicHeader h;
    memset(&h,0,sizeof h);
    strcpy(h.id,"psotnic");
    h.version=3;
    out.write(reinterpret_cast<const char*>(&h),sizeof h);

    const char *lines[] = {
        "# compiled-classic-gay-psotnic\n",
        "nick actualclassic\n",
        "realname Authentic classic build test\n",
        "sasl-password TestValue-not-a-real-password\n"
    };
    for(size_t i=0;i<sizeof(lines)/sizeof(lines[0]);++i) {
        const unsigned int len=strlen(lines[i]);
        std::vector<unsigned char> buffer(len+8);
        const unsigned int encrypted=blowfish.Encode(
            reinterpret_cast<unsigned char*>(const_cast<char*>(lines[i])),
            buffer.data(),len);
        out.write(reinterpret_cast<const char*>(buffer.data()),encrypted);
    }
    return out ? 0 : 4;
}
