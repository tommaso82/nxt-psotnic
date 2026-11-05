// Test fixture only: Blowfish-encode a userlist using the original configure seed.
#include "prots.h"
#include "seed.h"
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <iterator>

int main(int argc, char **argv) {
    if(argc != 3) return 2;
    CBlowFish blowfish;
    blowfish.Initialize(ul_seed, 16);
    if(!strcmp(argv[1], "--verify")) {
        std::ifstream in(argv[2], std::ios::binary);
        psotnicHeader head;
        if(!in.read(reinterpret_cast<char*>(&head), sizeof head) ||
           strcmp(head.id, "psotnic") || head.version != 3U + STATUS_ULCRYPT)
            return 3;
        std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)),
                                        std::istreambuf_iterator<char>());
        if(data.empty() || data.size() % 8) return 4;
        blowfish.Decode(data.data(), data.data(), data.size());
        const std::string text(data.begin(), data.end());
        return text.find("21 42") != std::string::npos &&
               text.find("leafbot") != std::string::npos ? 0 : 5;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::ofstream out(argv[2], std::ios::binary);
    if(!in || !out) return 3;
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
