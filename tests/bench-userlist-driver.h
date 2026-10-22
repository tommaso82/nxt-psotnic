// Test-only live userlist benchmark compiled into upstream and NXT main.cpp.
// Never shipped in the release binary. Run with NXT_BENCH=plain|blowfish|nxt.
#ifndef NXT_USERLIST_BENCH_DRIVER_H
#define NXT_USERLIST_BENCH_DRIVER_H
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iterator>
#include <time.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#ifdef NXT_BENCH_NEW
#include "../nxt-crypto.h"
#include <sodium.h>
#endif

static unsigned long long nxt_bench_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    return (unsigned long long)ts.tv_sec*1000000ULL+ts.tv_nsec/1000;
}
static long nxt_bench_rss_kib() {
    FILE *fp=fopen("/proc/self/status","r");
    if(!fp) return -1;
    char buf[256];
    long value=-1;
    while(fgets(buf,sizeof buf,fp)) {
        if(sscanf(buf,"VmRSS: %ld kB",&value)==1) break;
    }
    fclose(fp);return value;
}
static unsigned long long nxt_bench_cpu_us() {
    struct rusage r;
    getrusage(RUSAGE_SELF,&r);
    return (unsigned long long)(r.ru_utime.tv_sec+r.ru_stime.tv_sec)*1000000ULL +
      r.ru_utime.tv_usec+r.ru_stime.tv_usec;
}
static unsigned long long nxt_bench_file_bytes(const char *path) {
    struct stat st;
    return stat(path,&st)==0?(unsigned long long)st.st_size:0;
}
static int nxt_userlist_benchmark(void) {
    const char *m=getenv("NXT_BENCH");
    const char *s=getenv("NXT_BENCH_COUNT");
    const char *dest=getenv("NXT_BENCH_DEST");
    if(!m||!s||!dest) return 44;
    const std::string mode=m;
    const int n=atoi(s);
    if(n<1||n>10000) return 43;
#ifndef NXT_BENCH_NEW
    if(mode=="nxt") return 42;
#else
    if(mode=="blowfish") return 42;
#endif
    NOW=time(NULL);
    config.save_userlist=1;
    config.bottype=BOT_SLAVE;
    for(int i=0;i<n;++i) {
        char name[32];
        snprintf(name,sizeof name,"u%06d",i);
        if(!userlist.addHandle(name,0,0,0,0,"benchmark")) {
            fprintf(stderr,"addHandle failed: %d\n",i);return 41;
        }
    }
    userlist.SN=42;
    userlist.timestamp=NOW;
#ifdef NXT_BENCH_NEW
    if(mode=="nxt") {
        std::string initial=std::string(dest)+".plain";
        if(!userlist.save(initial.c_str(),0)) return 40;
        std::ifstream in(initial.c_str(),std::ios::binary);
        std::string plaintext((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());
        if(plaintext.empty()) return 39;
        nxtcrypto::set_password_argument("synthetic benchmark passphrase");
        nxtcrypto::encrypt_plaintext_to_file(plaintext,dest);
        nxtcrypto::set_password_argument("synthetic benchmark passphrase");
        const std::string restored=nxtcrypto::load_userlist_data(dest);
        if(restored!=plaintext) return 38;
        if(!plaintext.empty()) sodium_memzero(&plaintext[0],plaintext.size());
        unlink(initial.c_str());
    }
#endif
    // Warm up serialization and filesystem paths outside measurement.
    if(!userlist.save(dest,
#ifdef NXT_BENCH_NEW
    0
#else
    mode=="blowfish"?1:0
#endif
    )) return 37;

    const long before=nxt_bench_rss_kib();
    std::vector<unsigned long long> latency,cpu;
    const int reps=11;
    for(int i=0;i<reps;++i) {
        const unsigned long long start=nxt_bench_us();
        const unsigned long long pcpu=nxt_bench_cpu_us();
        const bool ok=userlist.save(dest,
#ifdef NXT_BENCH_NEW
        0
#else
        mode=="blowfish"?1:0
#endif
        );
        const unsigned long long endcpu=nxt_bench_cpu_us();
        const unsigned long long end=nxt_bench_us();
        if(!ok) {fprintf(stderr,"bench save failed mode=%s n=%d i=%d\n",mode.c_str(),n,i);return 36;}
        latency.push_back(end-start);
        cpu.push_back(endcpu-pcpu);
    }
    std::sort(latency.begin(),latency.end());
    std::sort(cpu.begin(),cpu.end());
    struct rusage use;
    getrusage(RUSAGE_SELF,&use);
    fprintf(stdout,"BENCH_RESULT mode=%s users=%d repeats=%d median_us=%llu p95_us=%llu min_us=%llu max_us=%llu cpu_median_us=%llu bytes=%llu rss_before_kib=%ld rss_after_kib=%ld rss_peak_kib=%ld\n",
       mode.c_str(),n,reps,
       latency[reps/2],latency[(reps*95+99)/100-1],latency.front(),latency.back(),
       cpu[reps/2],nxt_bench_file_bytes(dest),
       before,nxt_bench_rss_kib(),use.ru_maxrss);
    return 0;
}
#endif
