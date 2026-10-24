// Legacy gay-psotnic configuration importer (version 3).
// Decodes old per-line Blowfish blocks. Never executes supplied binaries.
#include "prots.h"
#include "nxt-crypto.h"
#include "nxt-legacy.h"
#include <sodium.h>
#include <elf.h>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

namespace nxtlegacy {
namespace {
const size_t MAX_CFG = 8U*1024U*1024U;
const size_t MAX_BIN = 32U*1024U*1024U;
std::vector<unsigned char> read_bytes(const char *path, size_t maximum) {
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    if(!f) throw std::runtime_error(std::string("cannot read ")+path);
    std::streampos end=f.tellg();
    if(end<0 || end>static_cast<std::streampos>(maximum))
        throw std::runtime_error("input file exceeds limit");
    f.seekg(0);
    std::vector<unsigned char> data(static_cast<size_t>(end));
    if(!data.empty() && !f.read(reinterpret_cast<char*>(data.data()),data.size()))
        throw std::runtime_error("input read failed");
    return data;
}
void erase(std::vector<unsigned char>& x) {
    if(!x.empty()) sodium_memzero(x.data(),x.size());
    x.clear();
}
void erase(std::string &x) {
    if(!x.empty()) sodium_memzero(&x[0],x.size());
    x.clear();
}
typedef std::vector<unsigned char> Bytes;

bool is_legacy_v3(const Bytes &in,bool userlist) {
    if(in.size()<20 || ((in.size()-12)%8)!=0 || memcmp(in.data(),"psotnic\0",8)!=0)
        return false;
    const unsigned char *v=in.data()+8;
    if(userlist)
        return (v[0]==3 && v[1]==0 && v[2]==0 && v[3]==128) ||
               (v[0]==128 && v[1]==0 && v[2]==0 && v[3]==3);
    return (v[0]==3 && !v[1] && !v[2] && !v[3]) ||
           (!v[0] && !v[1] && !v[2] && v[3]==3);
}
unsigned int nibble(char c) {
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    throw std::runtime_error("invalid cfg_seed hex escape");
}
Bytes seed_from_header(const char *path,bool userlist) {
    Bytes bytes=read_bytes(path,1024U*1024U);
    std::string s(bytes.begin(),bytes.end());
    const std::string token=userlist?"ul_seed":"cfg_seed";
    size_t p=s.find(token);
    if(p==std::string::npos) throw std::runtime_error("cfg_seed not found in seed.h");
    p+=token.size();
    p=s.find('=',p);
    if(p==std::string::npos) throw std::runtime_error("invalid seed.h");
    p=s.find('"',p);
    if(p==std::string::npos) throw std::runtime_error("invalid cfg_seed in seed.h");
    ++p;
    Bytes seed;
    for(int i=0;i<16;++i) {
        if(p+3>=s.size() || s[p]!='\\' || s[p+1]!='x')
            throw std::runtime_error("cfg_seed must contain 16 \\xNN bytes");
        unsigned int value=(nibble(s[p+2])<<4)|nibble(s[p+3]);
        seed.push_back((unsigned char)value);
        p+=4;
    }
    if(p>=s.size() || s[p]!='"')
        throw std::runtime_error("cfg_seed must be exactly 16 bytes");
    erase(bytes);erase(s);
    return seed;
}
bool plausible(const std::string& data,bool userlist) {
    if(data.empty() || data.size()>MAX_CFG || data[data.size()-1]!='\n') return false;
    size_t lines=0, options=0;
    bool nick=false, seq=false, timestamp=false;
    size_t start=0;
    while(start<data.size()) {
        size_t end=data.find('\n',start);
        if(end==std::string::npos || end-start>4096) return false;
        for(size_t i=start;i<end;++i) {
            unsigned char c=(unsigned char)data[i];
            if((c<32 && c!='\t' && c!='\r') || c==127) return false;
        }
        size_t p=start;
        while(p<end && (data[p]==' '||data[p]=='\t')) ++p;
        if(p<end && data[p]!='#') {
            size_t q=p;
            while(q<end && (std::isalnum((unsigned char)data[q]) || data[q]=='-' || data[q]=='_')) ++q;
            if(q==p || q-p>80 || (q<end && data[q]!=' ' && data[q]!='\t')) return false;
            const std::string directive=data.substr(p,q-p);
            if(directive=="nick" && q<end) nick=true;
            if(directive=="21" && q<end && data[q+1]>='1' && data[q+1]<='9') seq=true;
            if(directive=="82" && q<end && data[q+1]>='0' && data[q+1]<='9') timestamp=true;
            ++options;
        }
        ++lines;
        if(lines>100000) return false;
        start=end+1;
    }
    return userlist?(seq && timestamp && options>=2):(nick && options>=1);
}
bool decrypt_with_seed(const Bytes &encrypted, const Bytes &seed, std::string& output,bool userlist) {
    if(seed.size()!=16 || !is_legacy_v3(encrypted,userlist)) return false;
    CBlowFish cipher;
    unsigned char key[16];memcpy(key,seed.data(),16);
    cipher.Initialize(key,16);
    sodium_memzero(key,sizeof key);
    Bytes plain(encrypted.size()-12);
    cipher.Decode(const_cast<unsigned char*>(encrypted.data()+12),plain.data(),(DWORD)plain.size());
    std::string text;
    bool in_padding=false;
    bool valid=true;
    // Each original line is separately padded to an 8-byte Blowfish block.
    for(size_t i=0;i<plain.size();++i) {
        if(i%8==0) in_padding=false;
        unsigned char c=plain[i];
        if(in_padding) {
            if(c!=0) {valid=false;break;}
        } else if(c=='\n') {
            text.push_back('\n');
            in_padding=true;
        } else if(c=='\0') {valid=false;break;}
        else text.push_back((char)c);
    }
    if(valid) valid=plausible(text,userlist);
    erase(plain);
    if(valid) output.swap(text);
    erase(text);
    return valid;
}
// ELF64 x86-64 virtual memory mapping, for RIP-relative optimized seed loads.
bool resolve_rip(const Bytes &file,size_t insn,size_t next,int32_t disp,size_t& offset) {
    if(file.size()<sizeof(Elf64_Ehdr)) return false;
    Elf64_Ehdr hdr;memcpy(&hdr,file.data(),sizeof hdr);
    if(memcmp(hdr.e_ident,ELFMAG,SELFMAG)!=0 ||
       hdr.e_ident[EI_CLASS]!=ELFCLASS64 || hdr.e_ident[EI_DATA]!=ELFDATA2LSB ||
       hdr.e_machine!=EM_X86_64 || hdr.e_phentsize!=sizeof(Elf64_Phdr) ||
       hdr.e_phnum>256 || hdr.e_phoff>file.size() ||
       (size_t)hdr.e_phnum*sizeof(Elf64_Phdr)>file.size()-hdr.e_phoff) return false;
    uint64_t insn_va=0; bool found=false;
    for(unsigned int i=0;i<hdr.e_phnum;++i) {
        Elf64_Phdr ph;memcpy(&ph,file.data()+hdr.e_phoff+i*sizeof ph,sizeof ph);
        if(ph.p_type==PT_LOAD && insn>=ph.p_offset && insn-ph.p_offset<ph.p_filesz) {
            insn_va=ph.p_vaddr+(insn-ph.p_offset);
            found=true;break;
        }
    }
    if(!found) return false;
    int64_t target=(int64_t)insn_va+(int64_t)(next-insn)+(int64_t)disp;
    if(target<0) return false;
    for(unsigned int i=0;i<hdr.e_phnum;++i) {
        Elf64_Phdr ph;memcpy(&ph,file.data()+hdr.e_phoff+i*sizeof ph,sizeof ph);
        if(ph.p_type==PT_LOAD && (uint64_t)target>=ph.p_vaddr &&
          (uint64_t)target-ph.p_vaddr<ph.p_filesz &&
          ph.p_offset+((uint64_t)target-ph.p_vaddr)<=file.size() &&
          file.size()-ph.p_offset-((uint64_t)target-ph.p_vaddr)>=16) {
            offset=(size_t)(ph.p_offset+((uint64_t)target-ph.p_vaddr));
            return true;
        }
    }
    return false;
}
std::vector<Bytes> binary_candidates(const Bytes& file) {
    std::vector<Bytes> candidates;
    // GCC -O2/-O3 often materializes the final 16-byte seed as a
    // RIP-relative constant loaded with MOVDQA and stored to *out.
    for(size_t p=0;p+12<file.size() && candidates.size()<64;++p) {
        if(file[p]==0x66 && file[p+1]==0x0f && file[p+2]==0x6f && file[p+3]==0x05) {
            if(file[p+8]==0x0f && file[p+9]==0x11 && file[p+10]==0x07) {
                int32_t delta;memcpy(&delta,file.data()+p+4,4);
                size_t off;
                if(resolve_rip(file,p,p+8,delta,off))
                    candidates.push_back(Bytes(file.begin()+off,file.begin()+off+16));
            }
        }
    }
    // GCC -O1: C6 07 imm then 15 C6 47 index imm stores.
    for(size_t p=0;p+64<file.size() && candidates.size()<64;++p) {
        if(file[p]!=0xc6 || file[p+1]!=0x07) continue;
        Bytes candidate(16); candidate[0]=file[p+2];
        bool found=true;
        for(int j=1;j<16;++j) {
            size_t a=p+3+4*(j-1);
            if(file[a]!=0xc6 || file[a+1]!=0x47 || file[a+2]!=j) {found=false;break;}
            candidate[j]=file[a+3];
        }
        if(found) candidates.push_back(candidate);
    }
    // GCC -O0: every byte is assigned after loading pointer from stack;
    // indexed byte stores follow ADD RAX, index / MOV [RAX], imm.
    for(size_t p=0;p+300<file.size() && candidates.size()<64;++p) {
        if(file[p]!=0xc6 || file[p+1]!=0x00) continue;
        Bytes candidate(16);candidate[0]=file[p+2];
        size_t cursor=p+3;bool found=true;
        for(int j=1;j<16;++j) {
            size_t stop=cursor+32;
            if(stop>file.size()) {found=false;break;}
            bool matched=false;
            for(size_t q=cursor;q+6<=stop;++q) {
                if(file[q]==0x48 && file[q+1]==0x83 && file[q+2]==0xc0 &&
                   file[q+3]==j && file[q+4]==0xc6 && file[q+5]==0x00 && q+6<file.size()) {
                    candidate[j]=file[q+6];cursor=q+7;matched=true;break;
                }
            }
            if(!matched) {found=false;break;}
        }
        if(found) candidates.push_back(candidate);
    }
    return candidates;
}
std::string decrypt_binary(const Bytes& encrypted,const char *binary,bool userlist) {
    Bytes file=read_bytes(binary,MAX_BIN);
    std::vector<Bytes> candidates=binary_candidates(file);
    erase(file);
    std::string plaintext;
    // Unoptimized generated function stores seed[i] XOR one constant byte.
    // Brute-forcing the XOR byte is cheap and does NOT brute-force Blowfish.
    for(size_t i=0;i<candidates.size();++i) {
        for(unsigned int mask=0;mask<256;++mask) {
            Bytes seed=candidates[i];
            for(int j=0;j<16;++j) seed[j]^=(unsigned char)mask;
            if(decrypt_with_seed(encrypted,seed,plaintext,userlist)) {
                erase(seed);
                for(size_t j=0;j<candidates.size();++j) erase(candidates[j]);
                return plaintext;
            }
            erase(seed);
            // Constants extracted from GCC -O2 already contain final seeds:
            // only need the unmasked candidate.
            if(i<candidates.size() && mask==0 && candidates.size()>64) break;
        }
    }
    for(size_t i=0;i<candidates.size();++i) erase(candidates[i]);
    throw std::runtime_error("no matching cfg seed found in ELF x86-64 binary (supported GCC -O0/-O1/-O2 layouts only)");
}
void save_plain(const char *path,const std::string &text) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) throw std::runtime_error(std::string("cannot create output (file exists?): ")+path);
    try {
        size_t pos=0;
        while(pos<text.size()) {
            ssize_t n=write(fd,text.data()+pos,text.size()-pos);
            if(n<0&&errno==EINTR) continue;
            if(n<=0) throw std::runtime_error("output write failed");
            pos+=(size_t)n;
        }
        if(fsync(fd)!=0) throw std::runtime_error("output sync failed");
        if(close(fd)!=0) {fd=-1;throw std::runtime_error("output close failed");}
    } catch(...) {
        if(fd>=0) close(fd);
        unlink(path);throw;
    }
}
} // namespace

std::string legacy_decrypt_as(const char *file,const char *seed_file,const char *binary,bool userlist) {
    Bytes cipher=read_bytes(file,MAX_CFG);
    if(!is_legacy_v3(cipher,userlist)) throw std::runtime_error("unsupported legacy Blowfish header/version");
    if(seed_file && binary) throw std::runtime_error("choose --seed-file or --binary, not both");
    if(!seed_file && !binary) throw std::runtime_error("supply --seed-file seed.h or --binary old-psotnic");
    std::string out;
    if(seed_file) {
        Bytes seed=seed_from_header(seed_file,userlist);
        bool success=decrypt_with_seed(cipher,seed,out,userlist);
        erase(seed);
        if(!success) throw std::runtime_error("legacy seed did not decode a valid config");
    } else out=decrypt_binary(cipher,binary,userlist);
    erase(cipher);
    return out;
}
std::string legacy_decrypt(const char *file,const char *seed_file,const char *binary) {
    return legacy_decrypt_as(file,seed_file,binary,false);
}
int import_common(int argc,char **argv,bool userlist) {
    if(argc<4) {fprintf(stderr,"Usage: psotnic config|userlist import OLD.cfg (--seed-file seed.h | --binary old-psotnic) [--preview | --output NEW.cfg --to plain|nxt]\n");return 1;}
    const char *seed_file=NULL, *binary=NULL, *output=NULL;
    std::string mode="plain";bool preview=false,to_specified=false;
    try {
        for(int i=4;i<argc;++i) {
            if(!strcmp(argv[i],"--seed-file") && i+1<argc) seed_file=argv[++i];
            else if(!strcmp(argv[i],"--binary") && i+1<argc) binary=argv[++i];
            else if(!strcmp(argv[i],"--output") && i+1<argc) output=argv[++i];
            else if(!strcmp(argv[i],"--to") && i+1<argc) {mode=argv[++i];to_specified=true;}
            else if(!strcmp(argv[i],"--preview")) preview=true;
            else if(!strcmp(argv[i],"--password") && i+1<argc) {
                ++i;nxtcrypto::set_password_argument(argv[i]);sodium_memzero(argv[i],strlen(argv[i]));
            } else if(!strcmp(argv[i],"--password-file") && i+1<argc) nxtcrypto::set_password_file(argv[++i]);
            else if(!strcmp(argv[i],"--password-stdin")) nxtcrypto::set_password_stdin();
            else throw std::runtime_error(std::string("unknown import option: ")+argv[i]);
        }
        if(mode!="plain" && mode!="nxt") throw std::runtime_error("--to must be plain or nxt");
        if(preview && output) throw std::runtime_error("--preview cannot be combined with --output");
        if(preview && to_specified) throw std::runtime_error("--to cannot be used with --preview");
        if(!preview && !output) throw std::runtime_error("--output is required unless --preview");
        if(!seed_file && !binary) throw std::runtime_error("missing --seed-file or --binary");
        std::string target=output ? output : "";
        const bool nxt_extension=nxtcrypto::has_nxt_extension(target.c_str());
        if(!preview && !to_specified && nxt_extension) mode="nxt";
        if(!preview && mode=="plain" && nxt_extension)
            throw std::runtime_error(".nxt is reserved for encrypted files");
        if(!preview && mode=="nxt" && !nxt_extension) target+=".nxt";
        std::string plain=legacy_decrypt_as(argv[3],seed_file,binary,userlist);
        try {
            if(preview) {
                if(fwrite(plain.data(),1,plain.size(),stdout)!=plain.size())
                    throw std::runtime_error("failed to write preview");
            } else if(mode=="plain") {
                save_plain(target.c_str(),plain);
                printf("[+] Legacy %s imported as plaintext: %s\n",userlist?"userlist":"config",target.c_str());
            } else {
                nxtcrypto::encrypt_plaintext_to_file(plain,target.c_str());
                printf("[+] Legacy %s imported to NXTCRYPT: %s\n",userlist?"userlist":"config",target.c_str());
            }
            erase(plain);
        } catch(...) {erase(plain);throw;}
        return 0;
    } catch(const std::exception &e) {
        fprintf(stderr,"[-] Legacy import: %s\n",e.what());
        return 1;
    }
}
int import_command(int argc,char **argv) {return import_common(argc,argv,false);}
int import_userlist_command(int argc,char **argv) {return import_common(argc,argv,true);}
} // namespace nxtlegacy
