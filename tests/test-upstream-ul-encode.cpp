// Test fixture only: Blowfish-encode a userlist using the original configure seed.
#include "prots.h"
#include "seed.h"
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if(argc != 3) return 2;
    std::ifstream in(argv[1], std::ios::binary);
    std::ofstream out(argv[2], std::ios::binary);
    if(!in || !out) return 3;
    CBlowFish blowfish;
    blowfish.Initialize(ul_seed, 16);
    psotnicHeader h;
    memset(&h, 0, sizeof h);
    strcpy(h.id, "psotnic");
    h.version = 3U + STATUS_ULCRYPT;
    out.write(reinterpret_cast<const char *>(&h), sizeof h);
    std::string line;
    while(std::getline(in, line)) {
        line += '\n';
        const unsigned int n = static_cast<unsigned int>(line.size());
        std::vector<unsigned char> encrypted(n + 8);
        const unsigned int len = blowfish.Encode(
            reinterpret_cast<unsigned char *>(&line[0]), encrypted.data(), n);
        out.write(reinterpret_cast<const char *>(encrypted.data()), len);
    }
    return out ? 0 : 4;
}
