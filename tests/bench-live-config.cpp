// Encrypt an arbitrary plaintext config with the actual pinned gay-psotnic seed.
// Benchmark fixture only; never part of the release build.
#include "prots.h"
#include "seed.h"
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <cstdio>

int main(int argc, char **argv) {
    if(argc!=3) return 2;
    std::ifstream in(argv[1],std::ios::binary);
    std::ofstream out(argv[2],std::ios::binary|std::ios::trunc);
    if(!in || !out) return 3;
    CBlowFish cipher;
    cipher.Initialize(cfg_seed,16);
    psotnicHeader h={};
    strcpy(h.id,"psotnic");
    h.version=3;
    out.write(reinterpret_cast<const char*>(&h),sizeof h);
    std::string line;
    while(std::getline(in,line)) {
        if(!line.empty() && line.back()=='\r') line.pop_back();
        line+='\n';
        std::vector<unsigned char> buf(line.size()+8);
        const unsigned int written=cipher.Encode(
            reinterpret_cast<unsigned char*>(&line[0]),
            buf.data(),static_cast<unsigned int>(line.size()));
        out.write(reinterpret_cast<const char*>(buf.data()),written);
        if(!out) return 4;
    }
    return out?0:5;
}
