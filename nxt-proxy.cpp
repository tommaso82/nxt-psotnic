#include "nxt-proxy.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

namespace nxtproxy {
Session irc;
Session hub;
Type parse_type(const char *value) {
    if(value && !strcmp(value,"socks5"))return SOCKS5;
    if(value && !strcmp(value,"http"))return HTTP_CONNECT;
    return NONE;
}
const char *strip_host_prefix(const char *s) {
    if(!s) return "";
    for(int i=0;i<3;++i) {
        if(!strncmp(s,"ssl:",4)) s+=4;
        else if(!strncmp(s,"ipv4:",5)||!strncmp(s,"ipv6:",5)) s+=5;
        else break;
    }
    return s;
}
Session::Session():fd(-1),type(NONE),phase(IDLE),stage(0),
    txlen(0),txpos(0),rxlen(0),expected(0),port(0) {
    target[0]=user[0]=pass[0]=0;
}
void Session::reset() {
    // Avoid keeping password or authentication data after negotiation.
    volatile unsigned char *p=tx;
    for(size_t i=0;i<sizeof tx;++i) p[i]=0;
    p=rx;
    for(size_t i=0;i<sizeof rx;++i) p[i]=0;
    volatile char *q=pass;
    for(size_t i=0;i<sizeof pass;++i) q[i]=0;
    q=user;
    for(size_t i=0;i<sizeof user;++i) q[i]=0;
    fd=-1;type=NONE;phase=IDLE;stage=0;
    txlen=txpos=rxlen=expected=0;port=0;target[0]=0;
}
int Session::fail() {reset();phase=FAILED;return -1;}
bool Session::begin(int socket_fd,Type proto,const char *host,unsigned short dst_port,
                    const char *username,const char *password) {
    reset();
    if(socket_fd<0 || (proto!=SOCKS5 && proto!=HTTP_CONNECT) ||
       !host || !*host || !dst_port || strlen(host)>=sizeof(target) ||
       !username || !password || strlen(username)>255 || strlen(password)>255)
        return false;
    for(const char *s=host;*s;++s)
        if((unsigned char)*s<=32 || (unsigned char)*s>=127 || *s=='[' || *s==']')
            return false;
    for(const char *s=username;*s;++s) if(*s=='\r'||*s=='\n') return false;
    for(const char *s=password;*s;++s) if(*s=='\r'||*s=='\n') return false;
    if(!*username && *password) return false;
    fd=socket_fd;type=proto;phase=TCP;port=dst_port;
    strcpy(target,host);strcpy(user,username);strcpy(pass,password);
    return true;
}
bool Session::active(int socket_fd) const {
    return fd==socket_fd && (phase==TCP||phase==SENDING||phase==READING);
}
bool Session::want_write() const {return phase==TCP||phase==SENDING;}
bool Session::want_read() const {return phase==READING;}
static bool append_ascii(unsigned char *dst,size_t capacity,size_t &n,const char *v) {
    const size_t z=strlen(v);
    if(n+z>capacity)return false;
    memcpy(dst+n,v,z);n+=z;return true;
}
static bool append_number(unsigned char *dst,size_t capacity,size_t &n,unsigned short port) {
    char number[8];snprintf(number,sizeof number,"%u",(unsigned)port);
    return append_ascii(dst,capacity,n,number);
}
static bool base64(unsigned char *dst,size_t capacity,size_t &n,const char *value) {
    const char *alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const size_t len=strlen(value);
    for(size_t i=0;i<len;i+=3) {
        const unsigned a=(unsigned char)value[i];
        const bool b=i+1<len,c=i+2<len;
        const unsigned v=(a<<16)|((b?(unsigned char)value[i+1]:0)<<8)|(c?(unsigned char)value[i+2]:0);
        if(n+4>capacity)return false;
        dst[n++]=alphabet[(v>>18)&63];dst[n++]=alphabet[(v>>12)&63];
        dst[n++]=b?alphabet[(v>>6)&63]:'=';
        dst[n++]=c?alphabet[v&63]:'=';
    }
    return true;
}
bool Session::compose() {
    txlen=txpos=rxlen=expected=0;
    if(type==SOCKS5) {
        if(stage==0) {tx[0]=5;tx[1]=1;tx[2]=*user?2:0;txlen=3;expected=2;}
        else if(stage==1) {
            const size_t a=strlen(user),b=strlen(pass);
            if(a==0||a>255||b>255)return false;
            tx[0]=1;tx[1]=(unsigned char)a;
            memcpy(tx+2,user,a);tx[2+a]=(unsigned char)b;
            memcpy(tx+3+a,pass,b);txlen=3+a+b;expected=2;
        }
        else if(stage==2) {
            unsigned char addr[16];int family=0;
            if(inet_pton(AF_INET,target,addr)==1)family=4;
            else if(inet_pton(AF_INET6,target,addr)==1)family=6;
            tx[0]=5;tx[1]=1;tx[2]=0;
            if(family==4||family==6) {
                tx[3]=family==4?1:4;
                const size_t length=family==4?4:16;
                memcpy(tx+4,addr,length);txlen=4+length;
            } else {
                const size_t length=strlen(target);
                if(length>255)return false;
                tx[3]=3;tx[4]=(unsigned char)length;
                memcpy(tx+5,target,length);txlen=5+length;
            }
            tx[txlen++]=(unsigned char)(port>>8);
            tx[txlen++]=(unsigned char)port;
            expected=4;
        } else return false;
    } else if(type==HTTP_CONNECT) {
        size_t n=0;
        unsigned char addr[16];
        const bool ipv6=inet_pton(AF_INET6,target,addr)==1;
        if(!append_ascii(tx,sizeof tx,n,"CONNECT ")) return false;
        if(ipv6&&!append_ascii(tx,sizeof tx,n,"["))return false;
        if(!append_ascii(tx,sizeof tx,n,target))return false;
        if(ipv6&&!append_ascii(tx,sizeof tx,n,"]"))return false;
        if(!append_ascii(tx,sizeof tx,n,":")||!append_number(tx,sizeof tx,n,port))return false;
        if(!append_ascii(tx,sizeof tx,n," HTTP/1.1\r\nHost: "))return false;
        if(ipv6&&!append_ascii(tx,sizeof tx,n,"["))return false;
        if(!append_ascii(tx,sizeof tx,n,target))return false;
        if(ipv6&&!append_ascii(tx,sizeof tx,n,"]"))return false;
        if(!append_ascii(tx,sizeof tx,n,":")||!append_number(tx,sizeof tx,n,port))return false;
        if(!append_ascii(tx,sizeof tx,n,"\r\n"))return false;
        if(*user) {
            if(!append_ascii(tx,sizeof tx,n,"Proxy-Authorization: Basic "))return false;
            char cred[512];
            snprintf(cred,sizeof cred,"%s:%s",user,pass);
            const bool ok=base64(tx,sizeof tx,n,cred);
            volatile char *v=cred;for(size_t i=0;i<sizeof cred;++i)v[i]=0;
            if(!ok||!append_ascii(tx,sizeof tx,n,"\r\n"))return false;
        }
        if(!append_ascii(tx,sizeof tx,n,"Proxy-Connection: Keep-Alive\r\n\r\n"))return false;
        txlen=n;
    } else return false;
    phase=SENDING;
    return true;
}
int Session::consume() {
    if(type==HTTP_CONNECT) {
        if(rxlen<4) return 0;
        if(rxlen>=12 && (memcmp(rx,"HTTP/1.1 200",12)==0 ||
                         memcmp(rx,"HTTP/1.0 200",12)==0)) {
            if(rxlen>=4 && !memcmp(rx+rxlen-4,"\r\n\r\n",4)) {
                reset();phase=ESTABLISHED;return 1;
            }
        } else if(rxlen>=12) return fail();
        if(rxlen==sizeof rx)return fail();
        return 0;
    }
    if(stage==0) {
        if(rxlen<2)return 0;
        if(rx[0]!=5 || rx[1]!=(*user?2:0))return fail();
        stage=(*user?1:2);
        if(!compose())return fail();
        return 0;
    }
    if(stage==1) {
        if(rxlen<2)return 0;
        if(rx[0]!=1 || rx[1]!=0)return fail();
        stage=2;
        if(!compose())return fail();
        return 0;
    }
    if(stage==2) {
        if(rxlen<4)return 0;
        if(rx[0]!=5 || rx[1]!=0 || rx[2]!=0)return fail();
        size_t total=0;
        if(rx[3]==1)total=10;
        else if(rx[3]==4)total=22;
        else if(rx[3]==3) {
            if(rxlen<5){expected=5;return 0;}
            total=7+rx[4];
        } else return fail();
        expected=total;
        if(rxlen>=total) {reset();phase=ESTABLISHED;return 1;}
    }
    return 0;
}
int Session::step(bool readable,bool writable) {
    if(phase==ESTABLISHED)return 1;
    if(phase==FAILED)return -1;
    if(phase==TCP && writable) {
        int e=0;socklen_t len=sizeof e;
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&e,&len)!=0||e!=0)return fail();
        if(!compose())return fail();
    }
    if(phase==SENDING && writable) {
        while(txpos<txlen) {
            ssize_t n=send(fd,tx+txpos,txlen-txpos,MSG_NOSIGNAL);
            if(n>0)txpos+=(size_t)n;
            else if(n<0&&errno==EINTR)continue;
            else if(n<0&&(errno==EWOULDBLOCK||errno==EAGAIN))return 0;
            else return fail();
        }
        phase=READING;
        rxlen=0;
    }
    if(phase==READING && readable) {
        // Receive just the handshake, never consume IRC data after tunnel opens.
        while(true) {
            if(rxlen>=sizeof rx)return fail();
            const size_t needed=type==SOCKS5?expected-rxlen:1;
            if(needed==0)return fail();
            ssize_t n=recv(fd,rx+rxlen,needed,0);
            if(n>0) {
                rxlen+=(size_t)n;
                const int state=consume();
                if(state!=0||phase==SENDING)return state;
                if(type==HTTP_CONNECT)continue;
                if(rxlen<expected)continue;
                return 0;
            }
            if(n<0&&errno==EINTR)continue;
            if(n<0&&(errno==EWOULDBLOCK||errno==EAGAIN))return 0;
            return fail();
        }
    }
    return 0;
}
}
