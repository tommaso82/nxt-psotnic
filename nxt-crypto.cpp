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
#include <strings.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace nxtcrypto {
bool cached_key(const char*,const unsigned char*,bool,unsigned char*,unsigned char* = NULL);
void write_key_cache();
namespace {
const unsigned char MAGIC[8]={'N','X','T','C','R','Y','P','T'};
const unsigned int OPS=3, RAM=32U*1024U*1024U;
const size_t HDR=8+1+1+4+4+crypto_pwhash_SALTBYTES+crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
const size_t MAXDATA=8U*1024U*1024U;
std::string password_arg, password_path;
bool stdin_password=false, has_password_arg=false;
bool bootstrap=false;
bool create_key_cache=false;
std::string cache_path;
std::string bootstrap_password;
bool wizard_active=false;
std::string wizard_password;
unsigned char ul_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]={0};
bool ul_active=false;
std::vector<unsigned char> ul_header;
std::string ul_path;
unsigned char cfg_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]={0};
bool cfg_active=false;
std::vector<unsigned char> cfg_header;
std::string cfg_path;
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
std::string unseal(const std::vector<unsigned char>& in,std::string &pass,unsigned char *export_key=NULL) {
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
    if(err==0 && export_key) memcpy(export_key,key,sizeof(key));
    sodium_memzero(key,sizeof(key));
    if(err!=0) {wipe(plain);throw std::runtime_error("wrong password or modified file");}
    std::string text(reinterpret_cast<const char*>(plain.data()),(size_t)size);
    wipe(plain);
    return text;
}

std::string unseal_cached(const std::vector<unsigned char>& in,const unsigned char *key) {
    std::vector<unsigned char> plain(in.size()-HDR);
    unsigned long long size=0;
    int err=crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(),&size,NULL,
        in.data()+HDR,in.size()-HDR,in.data(),HDR,
        in.data()+18+crypto_pwhash_SALTBYTES,key);
    if(err) {wipe(plain);throw std::runtime_error("cached key does not match encrypted file");}
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
        "Encrypted output automatically adds .nxt when missing.\n"
        "Plaintext output cannot use the .nxt extension.\n"
        "Password: --password-file PATH | --password-stdin | --password TEXT (unsafe)\n");
}
} // namespace

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
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]={0};
    std::string pass;
    try {
        bool cached=input.size()>=HDR+crypto_aead_xchacha20poly1305_ietf_ABYTES &&
            cached_key(path,input.data(),false,key);
        std::string out;
        if(cached) {
            try {out=unseal_cached(input,key);}
            catch(...) {sodium_memzero(key,sizeof(key));cached=false;}
        }
        if(!cached) {pass=password(false);out=unseal(input,pass,key);}
        if(bootstrap) {
            wipe(bootstrap_password); bootstrap_password=pass;
            // Cache the derived key so the running config can be re-encrypted
            // by .cfg-save later, exactly like the userlist session key.
            if(input.size()>=HDR) {
                sodium_memzero(cfg_key,sizeof cfg_key);
                memcpy(cfg_key,key,sizeof key);
                cfg_header.assign(input.begin(),input.begin()+HDR);
                cfg_path=path;
                cfg_active=true;
            }
        }
        sodium_memzero(key,sizeof key);
        wipe(pass);wipe(input);wipe(password_arg);has_password_arg=false;
        return out;
    } catch(...) {
        sodium_memzero(key,sizeof key);
        wipe(pass);wipe(input);wipe(password_arg);has_password_arg=false;throw;
    }
}

void begin_wizard_encryption() {
    // Prompt once, just before the first wizard save. Both output files
    // derive distinct keys because seal() generates a fresh salt for each.
    if(wizard_active || cfg_active || ul_active)
        throw std::runtime_error("cannot start wizard encryption in an existing session");
    std::string pass=password(true);
    wipe(wizard_password);
    wizard_password.swap(pass);
    wipe(pass);
    wipe(password_arg);has_password_arg=false;
    wizard_active=true;
}
void finish_wizard_encryption() {
    wizard_active=false;
    wipe(wizard_password);
}
void wizard_write_encrypted(std::string &plain,const char *path) {
    std::vector<unsigned char> bytes(plain.begin(),plain.end());
    std::vector<unsigned char> sealed;
    try {
        sealed=seal(bytes,wizard_password); // Fresh random salt & nonce for each file
        wipe(bytes);
        save_new(path,sealed.data(),sealed.size()); // Never overwrite existing files
        wipe(sealed);
    } catch(...) {
        wipe(bytes);wipe(sealed);
        throw;
    }
}
// The cache is an unattended-unlock credential, not a password substitute
// for explicit config/userlist CLI operations.
void enable_key_cache() { create_key_cache=true; }
void begin_bootstrap() { bootstrap=true; }
void finish_bootstrap() {
    try {write_key_cache();}
    catch(const std::exception &e) {fprintf(stderr,"[-] Cannot write local key cache: %s\n",e.what());}
    bootstrap=false;
    wipe(bootstrap_password);
    wipe(password_arg);has_password_arg=false;
}
bool userlist_encrypted_session() { return ul_active || wizard_active; }

std::string load_userlist_data(const char *path) {
    ready();
    std::vector<unsigned char> bytes=load_bytes(path);
    if(bytes.size()<HDR+crypto_aead_xchacha20poly1305_ietf_ABYTES ||
       memcmp(bytes.data(),MAGIC,8)!=0)
        throw std::runtime_error("not an NXT encrypted userlist");
    std::string pass;
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]={0};
    try {
        bool cached=bytes.size()>=HDR+crypto_aead_xchacha20poly1305_ietf_ABYTES &&
            cached_key(path,bytes.data(),true,key);
        std::string clear;
        if(cached) {
            try {clear=unseal_cached(bytes,key);}
            catch(...) {sodium_memzero(key,sizeof(key));cached=false;}
        }
        if(!cached) {
            pass=bootstrap_password.empty()?password(false):bootstrap_password;
            clear=unseal(bytes,pass,key);
        }
        sodium_memzero(ul_key,sizeof ul_key);
        memcpy(ul_key,key,sizeof key);
        ul_header.assign(bytes.begin(),bytes.begin()+HDR);
        ul_path=path;
        ul_active=true;
        sodium_memzero(key,sizeof key);
        wipe(bytes);wipe(pass);wipe(password_arg);has_password_arg=false;
        return clear;
    } catch(...) {
        sodium_memzero(key,sizeof key);
        wipe(bytes);wipe(pass);
        throw;
    }
}
// Atomic private replacement for config and userlist files: the temporary
// file is created with 0600 and the target is replaced by rename, so an
// autosave never leaves a partially written file behind.
// Writing the header, ciphertext and detached tag separately avoids a second
// full-size buffer and preserves the existing NXTCRYPT wire format.
void atomic_private_write(const char *target,
                     const unsigned char *part1,size_t len1,
                     const unsigned char *part2=NULL,size_t len2=0,
                     const unsigned char *part3=NULL,size_t len3=0) {
    struct stat st;
    const int stat_result=lstat(target,&st);
    if(stat_result==0 && (!S_ISREG(st.st_mode) || st.st_uid!=geteuid()))
        throw std::runtime_error("userlist target must be a regular file owned by this user");
    if(stat_result!=0 && errno!=ENOENT)
        throw std::runtime_error("userlist target is inaccessible");
    std::string tmp=std::string(target)+".tmp-XXXXXX";
    std::vector<char> name(tmp.begin(),tmp.end());
    name.push_back('\0');
    int fd=mkstemp(name.data());
    if(fd<0) throw std::runtime_error("cannot create temporary file");
    bool renamed=false;
    try {
        if(fchmod(fd,0600)!=0) throw std::runtime_error("cannot set file permissions");
        const unsigned char *parts[3]={part1,part2,part3};
        const size_t lengths[3]={len1,len2,len3};
        for(unsigned int i=0;i<3;++i) {
            size_t pos=0;
            if(lengths[i] && !parts[i]) throw std::runtime_error("missing userlist data");
            while(pos<lengths[i]) {
                ssize_t n=write(fd,parts[i]+pos,lengths[i]-pos);
                if(n<0 && errno==EINTR) continue;
                if(n<=0) throw std::runtime_error("userlist write failed");
                pos+=(size_t)n;
            }
        }
        if(fsync(fd)!=0) throw std::runtime_error("userlist fsync failed");
        if(close(fd)!=0) {fd=-1;throw std::runtime_error("userlist close failed");}
        fd=-1;
        if(rename(name.data(),target)!=0) throw std::runtime_error("userlist rename failed");
        renamed=true;
        std::string path(target);
        const size_t slash=path.find_last_of('/');
        const std::string folder=slash==std::string::npos?".":(slash==0?"/":path.substr(0,slash));
        int dir=open(folder.c_str(),O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if(dir>=0) {fsync(dir);close(dir);}
    } catch(...) {
        if(fd>=0) close(fd);
        if(!renamed) unlink(name.data());
        throw;
    }
}

const unsigned char CACHE_MAGIC[8]={'N','X','T','K','E','Y','0','1'};
const size_t CACHE_RECORD=34+32, CACHE_SIZE=8+1+16+2*CACHE_RECORD;
void cache_mask(unsigned char *mask,const unsigned char *seed,const unsigned char *header) {
    unsigned char input[16+34];
    memcpy(input,seed,16);memcpy(input+16,header,34);
    if(crypto_generichash(mask,32,input,sizeof(input),NULL,0)!=0)
        throw std::runtime_error("cache scrambling failed");
    sodium_memzero(input,sizeof(input));
}
bool cached_key(const char *path,const unsigned char *header,bool userlist,unsigned char *key,unsigned char *saved_header) {
    if(!bootstrap) return false;
    ready();
    if(cache_path.empty()) {
        cache_path=path;
        for(const char *suffix : {".cfg.nxt",".ul.nxt",".nxt"}) {
            const size_t len=strlen(suffix);
            if(cache_path.size()>=len &&
               !strncasecmp(cache_path.c_str()+cache_path.size()-len,suffix,len)) {
                cache_path.resize(cache_path.size()-len);
                break;
            }
        }
        cache_path+=".key";
    }
    int fd=open(cache_path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) return false;
    struct stat st;
    unsigned char state[CACHE_SIZE]={0};
    bool ok=fstat(fd,&st)==0 && S_ISREG(st.st_mode) &&
            st.st_uid==geteuid() && (st.st_mode&077)==0 &&
            st.st_size==static_cast<off_t>(sizeof(state));
    if(ok) {
        size_t pos=0;
        while(pos<sizeof(state)) {
            ssize_t n=read(fd,state+pos,sizeof(state)-pos);
            if(n<0 && errno==EINTR) continue;
            if(n<=0) {ok=false;break;}
            pos+=(size_t)n;
        }
    }
    close(fd);
    const unsigned int bit=userlist?2:1;
    const size_t off=25+(userlist?CACHE_RECORD:0);
    ok=ok && memcmp(state,CACHE_MAGIC,8)==0 &&
       (state[8]&~3U)==0 && (state[8]&bit)!=0 &&
       (header ? memcmp(state+off,header,34)==0 :
                 userlist && memcmp(state+off,MAGIC,8)==0 &&
                 state[off+8]==1 && state[off+9]==1 &&
                 un32(state+off+10)>=1 && un32(state+off+10)<=8 &&
                 un32(state+off+14)>=8U*1024U*1024U &&
                 un32(state+off+14)<=256U*1024U*1024U);
    if(ok) {
        if(saved_header) memcpy(saved_header,state+off,34);
        unsigned char mask[32];
        cache_mask(mask,state+9,state+off);
        for(size_t i=0;i<32;++i) key[i]=state[off+34+i]^mask[i];
        sodium_memzero(mask,sizeof(mask));
    }
    sodium_memzero(state,sizeof(state));
    return ok;
}
void write_key_cache() {
    if(!create_key_cache || cache_path.empty() || (!cfg_active && !ul_active)) return;
    unsigned char state[CACHE_SIZE]={0};
    memcpy(state,CACHE_MAGIC,8);
    state[8]=(cfg_active?1:0)|(ul_active?2:0);
    randombytes_buf(state+9,16);
    const unsigned char *headers[2]={cfg_active?cfg_header.data():NULL,
                                     ul_active?ul_header.data():NULL};
    const unsigned char *keys[2]={cfg_key,ul_key};
    for(size_t n=0;n<2;++n) if(headers[n]) {
        size_t off=25+n*CACHE_RECORD;
        memcpy(state+off,headers[n],34);
        unsigned char mask[32];
        cache_mask(mask,state+9,state+off);
        for(size_t i=0;i<32;++i) state[off+34+i]=keys[n][i]^mask[i];
        sodium_memzero(mask,sizeof(mask));
    }
    try {atomic_private_write(cache_path.c_str(),state,sizeof(state));}
    catch(...) {sodium_memzero(state,sizeof(state));throw;}
    sodium_memzero(state,sizeof(state));
}

// Shared encrypted-session saver (config and userlist): the plaintext string
// becomes ciphertext in-place, the stored KDF header is reused with a fresh
// random nonce, and a detached AEAD tag avoids any full-size extra buffer.
void session_save_encrypted(std::string& plaintext,const char *path,
                            const unsigned char *key,const unsigned char *stored) {
    unsigned char header[HDR];
    unsigned char mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    memcpy(header,stored,HDR);
    randombytes_buf(header+18+crypto_pwhash_SALTBYTES,
                    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    unsigned char *data=reinterpret_cast<unsigned char*>(&plaintext[0]);
    unsigned long long maclen=0;
    const int rc=crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        data,mac,&maclen,data,plaintext.size(),
        header,HDR,NULL,header+18+crypto_pwhash_SALTBYTES,key);
    if(rc!=0 || maclen!=sizeof(mac)) {
        sodium_memzero(mac,sizeof(mac));
        sodium_memzero(header,sizeof(header));
        throw std::runtime_error("session encryption failed");
    }
    try {
        atomic_private_write(path,header,sizeof(header),data,plaintext.size(),mac,sizeof(mac));
    } catch(...) {
        sodium_memzero(mac,sizeof(mac));
        sodium_memzero(header,sizeof(header));
        throw;
    }
    sodium_memzero(mac,sizeof(mac));
    sodium_memzero(header,sizeof(header));
}
// Prepare an encrypted replica without creating an empty userlist on disk.
void prepare_missing_userlist(const char *path) {
    if(!has_nxt_extension(path)) return;
    if(ul_active) throw std::runtime_error("userlist session already active");
    ready();
    unsigned char header[HDR]={0};
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]={0};
    std::string pass;
    try {
        if(!cached_key(path,NULL,true,key,header)) {
            memcpy(header,MAGIC,8);
            header[8]=1;header[9]=1;
            be32(header+10,OPS);be32(header+14,RAM);
            randombytes_buf(header+18,crypto_pwhash_SALTBYTES);
            pass=bootstrap_password.empty()?password(false):bootstrap_password;
            if(crypto_pwhash(key,sizeof(key),pass.data(),pass.size(),header+18,
                OPS,RAM,crypto_pwhash_ALG_ARGON2ID13)!=0)
                throw std::runtime_error("Argon2id failed");
        }
        ul_header.assign(header,header+HDR);
        ul_path=path;
        memcpy(ul_key,key,sizeof(key));
        ul_active=true;
    } catch(...) {
        wipe(pass);
        sodium_memzero(key,sizeof(key));
        sodium_memzero(header,sizeof(header));
        throw;
    }
    wipe(pass);
    sodium_memzero(key,sizeof(key));
    sodium_memzero(header,sizeof(header));
}

void save_userlist_data(std::string& plaintext,const char *path) {
    // Plaintext saves do not need libsodium initialization.
    if(ul_active || wizard_active) ready();
    if(plaintext.empty() || plaintext.size()>MAXDATA)
        throw std::runtime_error("invalid userlist size");
    if(ul_active) {
        if(ul_path!=path) throw std::runtime_error("userlist path changed during encrypted session");
        session_save_encrypted(plaintext,path,ul_key,ul_header.data());
    } else if(wizard_active) {
        wizard_write_encrypted(plaintext,path);
    } else {
        plaintext_guard(path,"userlist");
        atomic_private_write(path,reinterpret_cast<const unsigned char*>(plaintext.data()),plaintext.size());
    }
}
bool config_encrypted_session() { return cfg_active || wizard_active; }

void save_config_data(std::string& plaintext,const char *path) {
    if(cfg_active || wizard_active) ready();
    if(plaintext.empty() || plaintext.size()>MAXDATA)
        throw std::runtime_error("invalid config size");
    if(cfg_active) {
        if(cfg_path!=path) throw std::runtime_error("config path changed during encrypted session");
        session_save_encrypted(plaintext,path,cfg_key,cfg_header.data());
    } else if(wizard_active) {
        wizard_write_encrypted(plaintext,path);
    } else {
        plaintext_guard(path,"config");
        atomic_private_write(path,reinterpret_cast<const unsigned char*>(plaintext.data()),plaintext.size());
    }
}
int userlist_command(int argc,char **argv) {
    return config_command(argc,argv);
}

void encrypt_plaintext_to_file(const std::string& content, const char *path) {
    if(content.empty()) throw std::runtime_error("cannot encrypt empty configuration");
    std::string pass=password(true);
    try {
        std::vector<unsigned char> bytes(content.begin(), content.end());
        std::vector<unsigned char> crypt=seal(bytes,pass);
        wipe(bytes);
        wipe(pass);
        try { save_new(path,crypt.data(),crypt.size()); wipe(crypt); }
        catch(...) {wipe(crypt);throw;}
    } catch(...) {wipe(pass);throw;}
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
            std::string target(output);
            if(!has_nxt_extension(target.c_str())) target+=".nxt";
            std::string pass=password(true);
            try {
                std::vector<unsigned char> cipher=seal(clear,pass);
                wipe(pass);wipe(clear);
                save_new(target.c_str(),cipher.data(),cipher.size());wipe(cipher);
            } catch(...) {wipe(pass);wipe(clear);throw;}
            printf("[+] Encrypted %s saved: %s\n",strcmp(argv[1],"userlist")?"config":"userlist",target.c_str());
        } else if(action=="decrypt" || action=="preview") {
            if(action=="decrypt" && !output) throw std::runtime_error("decrypt requires --output");
            if(action=="decrypt" && has_nxt_extension(output))
                throw std::runtime_error(".nxt is reserved for encrypted files");
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
