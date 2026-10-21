// NXT Psotnic config encryption v1: Argon2id13 + XChaCha20-Poly1305.
// Format: NXTCRYPT[8], version[1], KDF[1], ops[4], RAM[4],
//         salt[16], nonce[24], ciphertext + authentication tag.
// The whole 58-byte header is authenticated as additional data.
#include "nxt-crypto.h"
#include <sodium.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace nxtcrypto {
namespace {
const unsigned char MAGIC[8]={'N','X','T','C','R','Y','P','T'};
const unsigned int OPS=3, RAM=32U*1024U*1024U;
const size_t HDR=8+1+1+4+4+crypto_pwhash_SALTBYTES+crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
const size_t MAXDATA=8U*1024U*1024U;
std::string password_arg, password_path;
bool stdin_password=false, has_password_arg=false;
void ready() { if(sodium_init()<0) throw std::runtime_error("libsodium initialization failed"); }
void wipe(std::string &s) { if(!s.empty()) sodium_memzero(&s[0],s.size()); s.clear(); }
void wipe(std::vector<unsigned char> &v) { if(!v.empty()) sodium_memzero(v.data(),v.size()); v.clear(); }
void be32(unsigned char *p, unsigned int n) {
    p[0]=(unsigned char)(n>>24);p[1]=(unsigned char)(n>>16);
    p[2]=(unsigned char)(n>>8);p[3]=(unsigned char)n;
}
unsigned int un32(const unsigned char *p) {
    return ((unsigned int)p[0]<<24)|((unsigned int)p[1]<<16)|((unsigned int)p[2]<<8)|p[3];
}
std::vector<unsigned char> load_bytes(const char *path) {
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    if(!f) throw std::runtime_error(std::string("cannot open input: ")+path);
    std::streampos size=f.tellg();
    if(size<0 || size>static_cast<std::streampos>(MAXDATA+HDR+crypto_aead_xchacha20poly1305_ietf_ABYTES))
        throw std::runtime_error("config exceeds 8 MiB limit");
    f.seekg(0);
    std::vector<unsigned char> buf(static_cast<size_t>(size));
    if(!buf.empty() && !f.read(reinterpret_cast<char*>(buf.data()),buf.size()))
        throw std::runtime_error("failed to read input");
    return buf;
}
void save_new(const char *path,const unsigned char *data,size_t count) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) throw std::runtime_error(std::string("cannot create output (existing file?): ")+path);
    try {
        size_t offset=0;
        while(offset<count) {
            ssize_t n=write(fd,data+offset,count-offset);
            if(n<0 && errno==EINTR) continue;
            if(n<=0) throw std::runtime_error("output write failed");
            offset+=(size_t)n;
        }
        if(fsync(fd)!=0) throw std::runtime_error("output sync failed");
        if(close(fd)!=0) {fd=-1;throw std::runtime_error("output close failed");}
    } catch(...) {if(fd>=0) close(fd); unlink(path);throw;}
}
std::string read_line(std::istream &input) {
    std::string line;
    if(!std::getline(input,line)) throw std::runtime_error("cannot read password");
    if(line.size()>4096) {wipe(line);throw std::runtime_error("password too long");}
    if(!line.empty() && line[line.size()-1]=='\r') line.erase(line.size()-1);
    if(line.empty()) throw std::runtime_error("password cannot be empty");
    return line;
}
std::string tty_password(bool confirm) {
    int fd=open("/dev/tty",O_RDWR|O_CLOEXEC);
    if(fd<0) throw std::runtime_error("password required: use --password-file or --password-stdin");
    FILE *tty=fdopen(fd,"r+");
    if(!tty) {close(fd);throw std::runtime_error("cannot open terminal");}
    struct termios oldattr,attr;
    if(tcgetattr(fd,&oldattr)!=0) {fclose(tty);throw std::runtime_error("cannot read tty attributes");}
    attr=oldattr;attr.c_lflag &= ~ECHO;
    if(tcsetattr(fd,TCSAFLUSH,&attr)!=0) {fclose(tty);throw std::runtime_error("cannot disable tty echo");}
    std::string first;
    try {
        for(int run=0;run<(confirm?2:1);++run) {
            std::string line;
            fprintf(tty,"%s",run?"Confirm password: ":"NXT password: ");fflush(tty);
            int c;
            while((c=fgetc(tty))!=EOF && c!='\n') {
                if(line.size()>=4096) {wipe(line);throw std::runtime_error("password too long");}
                line.push_back((char)c);
            }
            fprintf(tty,"\n");fflush(tty);
            if(line.empty()) throw std::runtime_error("no password supplied");
            if(run==0) first.swap(line);
            else {
                bool same=first.size()==line.size() && sodium_memcmp(first.data(),line.data(),first.size())==0;
                wipe(line);
                if(!same) throw std::runtime_error("password confirmation mismatch");
            }
        }
        tcsetattr(fd,TCSAFLUSH,&oldattr);fclose(tty);
        return first;
    } catch(...) {
        tcsetattr(fd,TCSAFLUSH,&oldattr);fclose(tty);wipe(first);throw;
    }
}
std::string password(bool confirm) {
    ready();
    if(has_password_arg) {
        if(password_arg.empty()) throw std::runtime_error("password cannot be empty");
        return password_arg;
    }
    if(!password_path.empty()) {
        int fd=open(password_path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if(fd<0) throw std::runtime_error("cannot open password file");
        struct stat info;
        if(fstat(fd,&info)!=0 || !S_ISREG(info.st_mode) || (info.st_mode&077)!=0) {
            close(fd);throw std::runtime_error("password file must be regular, permissions 0600");
        }
        FILE *fp=fdopen(fd,"r");
        if(!fp) {close(fd);throw std::runtime_error("cannot read password file");}
        std::string line;
        try {
            int c;
            while((c=fgetc(fp))!=EOF && c!='\n') {
                if(line.size()>=4096) {wipe(line);throw std::runtime_error("password too long");}
                line.push_back((char)c);
            }
            if(!line.empty() && line[line.size()-1]=='\r') line.erase(line.size()-1);
            if(line.empty()) throw std::runtime_error("password file is empty");
            fclose(fp);
            return line;
        } catch(...) {fclose(fp);wipe(line);throw;}
    }
    if(stdin_password) return read_line(std::cin);
    return tty_password(confirm);
}
std::vector<unsigned char> seal(const std::vector<unsigned char>& plain,std::string &pass) {
    ready();
    std::vector<unsigned char> out(HDR+plain.size()+crypto_aead_xchacha20poly1305_ietf_ABYTES);
    memcpy(out.data(),MAGIC,8);
    out[8]=1;out[9]=1;
    be32(out.data()+10,OPS);be32(out.data()+14,RAM);
    randombytes_buf(out.data()+18,crypto_pwhash_SALTBYTES);
    randombytes_buf(out.data()+18+crypto_pwhash_SALTBYTES,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if(crypto_pwhash(key,sizeof(key),pass.data(),pass.size(),out.data()+18,
        OPS,RAM,crypto_pwhash_ALG_ARGON2ID13)!=0) {
        sodium_memzero(key,sizeof(key));throw std::runtime_error("Argon2id failed");
    }
    unsigned long long length=0;
    int err=crypto_aead_xchacha20poly1305_ietf_encrypt(out.data()+HDR,&length,
        plain.data(),plain.size(),out.data(),HDR,NULL,
        out.data()+18+crypto_pwhash_SALTBYTES,key);
    sodium_memzero(key,sizeof(key));
    if(err!=0) throw std::runtime_error("encryption failed");
    out.resize(HDR+(size_t)length);
    return out;
}
std::string unseal(const std::vector<unsigned char>& in,std::string &pass) {
    ready();
    if(in.size()<HDR+crypto_aead_xchacha20poly1305_ietf_ABYTES ||
       memcmp(in.data(),MAGIC,8)!=0) throw std::runtime_error("not an NXTCRYPT file");
    if(in[8]!=1 || in[9]!=1) throw std::runtime_error("unsupported NXTCRYPT version or KDF");
    unsigned int ops=un32(in.data()+10),ram=un32(in.data()+14);
    if(ops<1 || ops>8 || ram<8U*1024U*1024U || ram>256U*1024U*1024U)
        throw std::runtime_error("unsupported NXTCRYPT KDF limits");
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if(crypto_pwhash(key,sizeof(key),pass.data(),pass.size(),in.data()+18,
        ops,ram,crypto_pwhash_ALG_ARGON2ID13)!=0) {
        sodium_memzero(key,sizeof(key));throw std::runtime_error("Argon2id failed");
    }
    std::vector<unsigned char> plain(in.size()-HDR);
    unsigned long long size=0;
    int err=crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(),&size,NULL,
        in.data()+HDR,in.size()-HDR,in.data(),HDR,
        in.data()+18+crypto_pwhash_SALTBYTES,key);
    sodium_memzero(key,sizeof(key));
    if(err!=0) {wipe(plain);throw std::runtime_error("wrong password or modified file");}
    std::string text(reinterpret_cast<const char*>(plain.data()),(size_t)size);
    wipe(plain);
    return text;
}
void usage() {
    fprintf(stderr,
        "Usage:\n"
        "  psotnic config encrypt INPUT --output OUTPUT [password option]\n"
        "  psotnic config decrypt INPUT --output OUTPUT [password option]\n"
        "  psotnic config preview INPUT [password option]\n"
        "Password: --password-file PATH | --password-stdin | --password TEXT (unsafe)\n");
}
} // namespace

bool is_nxt_file(const char *path) {
    std::ifstream f(path,std::ios::binary);
    char b[8];return (bool)f.read(b,8) && memcmp(b,MAGIC,8)==0;
}
bool is_legacy_file(const char *path) {
    std::ifstream f(path,std::ios::binary);
    char b[8];return (bool)f.read(b,8) && memcmp(b,"psotnic",7)==0 && b[7]=='\0';
}
void set_password_argument(const char *arg) {
    ready();wipe(password_arg);password_arg=arg;has_password_arg=true;
    password_path.clear();stdin_password=false;
}
void set_password_file(const char *path) {
    wipe(password_arg);has_password_arg=false;
    password_path=path;stdin_password=false;
}
void set_password_stdin() {
    wipe(password_arg);has_password_arg=false;
    password_path.clear();stdin_password=true;
}
std::string decrypt_file(const char *path) {
    std::vector<unsigned char> input=load_bytes(path);
    std::string pass=password(false);
    try {
        std::string out=unseal(input,pass);
        wipe(pass);wipe(input);wipe(password_arg);has_password_arg=false;
        return out;
    } catch(...) {
        wipe(pass);wipe(input);wipe(password_arg);has_password_arg=false;throw;
    }
}
int config_command(int argc,char **argv) {
    if(argc<4) {usage();return 1;}
    std::string action=argv[2];
    const char *input=argv[3], *output=NULL;
    try {
        for(int i=4;i<argc;++i) {
            if(!strcmp(argv[i],"--output") && i+1<argc) output=argv[++i];
            else if(!strcmp(argv[i],"--password") && i+1<argc) {
                ++i;set_password_argument(argv[i]);sodium_memzero(argv[i],strlen(argv[i]));
            }
            else if(!strcmp(argv[i],"--password-file") && i+1<argc) set_password_file(argv[++i]);
            else if(!strcmp(argv[i],"--password-stdin")) set_password_stdin();
            else throw std::runtime_error(std::string("unknown option: ")+argv[i]);
        }
        if(action=="encrypt") {
            if(!output) throw std::runtime_error("encrypt requires --output");
            if(is_nxt_file(input)||is_legacy_file(input))
                throw std::runtime_error("input is already encrypted");
            std::vector<unsigned char> clear=load_bytes(input);
            if(clear.empty()) throw std::runtime_error("cannot encrypt empty config");
            std::string pass=password(true);
            try {
                std::vector<unsigned char> cipher=seal(clear,pass);
                wipe(pass);wipe(clear);
                save_new(output,cipher.data(),cipher.size());wipe(cipher);
            } catch(...) {wipe(pass);wipe(clear);throw;}
            printf("[+] Encrypted config saved: %s\n",output);
        } else if(action=="decrypt" || action=="preview") {
            if(action=="decrypt" && !output) throw std::runtime_error("decrypt requires --output");
            if(action=="preview" && output) throw std::runtime_error("preview cannot use --output");
            std::string clear=decrypt_file(input);
            try {
                if(action=="preview") {
                    if(!clear.empty() && fwrite(clear.data(),1,clear.size(),stdout)!=clear.size())
                        throw std::runtime_error("preview output failed");
                } else {
                    save_new(output,reinterpret_cast<const unsigned char*>(clear.data()),clear.size());
                    printf("[+] Decrypted config saved: %s\n",output);
                }
                wipe(clear);
            } catch(...) {wipe(clear);throw;}
        } else {usage();throw std::runtime_error("unknown config action");}
        wipe(password_arg);has_password_arg=false;
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"[-] NXT config: %s\n",e.what());
        wipe(password_arg);has_password_arg=false;
        return 1;
    }
}
} // namespace nxtcrypto
