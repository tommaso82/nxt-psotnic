#include "../nxt-proxy.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <string>
#include <cerrno>
static void nb(int fd) {int v=fcntl(fd,F_GETFL);assert(v>=0&&fcntl(fd,F_SETFL,v|O_NONBLOCK)==0);}
static std::string readpkt(int fd) {
    char buf[4096];std::string s;
    while(true) {ssize_t n=recv(fd,buf,sizeof(buf),0);
        if(n>0)s.append(buf,n);
        else if(n<0&&errno==EINTR)continue;
        else break;
    }return s;
}
static void reply(int fd,const std::string& s) {
    size_t p=0;while(p<s.size()) {ssize_t n=send(fd,s.data()+p,s.size()-p,0);assert(n>0);p+=n;}
}
static std::string raw(const unsigned char *data,size_t size) {return std::string(reinterpret_cast<const char *>(data),size);}
static void socks(bool auth,bool bad=false,bool ipv6=false) {
    int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);nb(pair[0]);nb(pair[1]);
    nxtproxy::Session s;
    assert(s.begin(pair[0],nxtproxy::SOCKS5,ipv6?"2001:db8::1":"irc.example.test",6697,auth?"user":"",auth?"password":""));
    assert(s.step(false,true)==0);
    assert(readpkt(pair[1])==raw(reinterpret_cast<const unsigned char*>(auth?"\x05\x01\x02":"\x05\x01\x00"),3));
    reply(pair[1],raw(reinterpret_cast<const unsigned char*>(auth?"\x05\x02":"\x05\x00"),2));
    assert(s.step(true,false)==0);
    if(auth) {
        assert(s.step(false,true)==0);
        std::string got=readpkt(pair[1]);
        assert(got==std::string("\x01\x04",2)+"user"+std::string("\x08",1)+"password");
        reply(pair[1],std::string("\x01",1)+std::string(bad?"\x01":"\x00",1));
        int v=s.step(true,false);
        if(bad){assert(v==-1);assert(!s.active(pair[0]));close(pair[0]);close(pair[1]);return;}
        assert(v==0);
    }
    assert(s.step(false,true)==0);
    std::string request=readpkt(pair[1]);
    assert(request.size()>9 && request[0]==5 && request[1]==1 && request[2]==0);
    if(ipv6)assert((unsigned char)request[3]==4);
    else {assert((unsigned char)request[3]==3);assert(request.find("irc.example.test")!=std::string::npos);}
    // Send the reply in fragments: header, address, port.
    reply(pair[1],std::string("\x05\x00\x00\x01",4));
    assert(s.step(true,false)==0);
    reply(pair[1],std::string("\x7f\x00\x00\x01\x1a\x29",6));
    assert(s.step(true,false)==1);
    assert(!s.active(pair[0]));
    close(pair[0]);close(pair[1]);
}
static void http(bool auth,bool bad=false,bool ipv6=false) {
    int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);nb(pair[0]);nb(pair[1]);
    nxtproxy::Session s;
    assert(s.begin(pair[0],nxtproxy::HTTP_CONNECT,ipv6?"2001:db8::1":"irc.example.test",6667,auth?"user":"",auth?"password":""));
    assert(s.step(false,true)==0);
    auto request=readpkt(pair[1]);
    assert(request.find(ipv6?"CONNECT [2001:db8::1]:6667 HTTP/1.1":"CONNECT irc.example.test:6667 HTTP/1.1")==0);
    assert(request.find("Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==")!=std::string::npos == auth);
    assert(request.find("\r\n\r\n")==request.size()-4);
    reply(pair[1],"HTTP/1.1 ");
    assert(s.step(true,false)==0);
    reply(pair[1],bad?"407 Proxy Authentication Required\r\n\r\n":"200 Connection Established\r\n");
    int v=s.step(true,false);
    if(bad){assert(v==-1);close(pair[0]);close(pair[1]);return;}
    assert(v==0);
    reply(pair[1],"\r\n");
    assert(s.step(true,false)==1);
    close(pair[0]);close(pair[1]);
}
int main() {
    socks(false);socks(true);socks(true,true);socks(false,false,true);
    http(false);http(true);http(true,true);http(false,false,true);
    nxtproxy::Session invalid;
    assert(!invalid.begin(3,nxtproxy::HTTP_CONNECT,"irc.example.test\r\nInjected: yes",6697,"",""));
    assert(!invalid.begin(3,nxtproxy::SOCKS5,"irc.example.test",6697,"","wrong"));
    assert(std::string(nxtproxy::strip_host_prefix("ssl:ipv6:2001:db8::1"))=="2001:db8::1");
    printf("PASS: SOCKS5 + RFC1929 auth, HTTP CONNECT + Basic, IPv6, fragmented replies, rejection and validation\n");
}
