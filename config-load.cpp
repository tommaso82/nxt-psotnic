/***************************************************************************
 *   Copyright (C) 2003-2005 by Grzegorz Rusin                             *
 *   grusin@gmail.com                                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "prots.h"
#include "global-var.h"
#include "nxt-crypto.h"
#include "nxt-proxy.h"
#include <string>
#include <stdexcept>
#include <sodium.h>

void CONFIG::load(const char *file, bool decrypted)
{
	char arg[10][MAX_LEN], buf[MAX_LEN], cwd[MAX_LEN];
	int line = 0, n;
	int errors = 0;
	int alts = 0;
	int i;
	bool can_link_bots=false;
//	bool listening=false;
	bool listening_ssl=false;
	options::event *e;
	inetconn f;

	config.file = file;
#ifndef HAVE_ADNS
    nxtproxy::defer_dns=true;
#endif

	getcwd(cwd, MAX_LEN);

	(void)decrypted; // Historical debug flag; the format determines how we read.
	bool encrypted = nxtcrypto::is_nxt_file(file);
	std::string plaintext;
	size_t pos = 0;
	if(nxtcrypto::is_legacy_file(file)) {
		printf("[-] Legacy Blowfish config detected. Import it before startup.\n");
		exit(1);
	}
	if(encrypted) {
		try {
			plaintext = nxtcrypto::decrypt_file(file);
			if(plaintext.find('\0') != std::string::npos)
				throw std::runtime_error("NUL in config");
		} catch(const std::exception &e) {
			printf("[-] Cannot read NXT config: %s\n", e.what());
			exit(1);
		}
		printf("[*] Loading NXT encrypted config from '%s/%s'\n", cwd, file);
	} else {
		printf("[*] Loading plaintext config from '%s/%s'\n", cwd, file);
		if(f.open(file, O_RDONLY) < 0) {
			printf("[-] Cannot open config file '%s/%s': %s\n", cwd, file, strerror(errno));
			exit(1);
		}
	}

	while(1)
	{
		if(encrypted) {
			if(pos >= plaintext.size()) break;
			size_t end = plaintext.find('\n', pos);
			if(end == std::string::npos) end = plaintext.size();
			size_t count = end - pos;
			if(count >= MAX_LEN) {
				printf("[-] Encrypted configuration line exceeds MAX_LEN\n");
				exit(1);
			}
			memcpy(buf, plaintext.data() + pos, count);
			buf[count] = '\0';
			n = static_cast<int>(count);
			if(n && buf[n-1]=='\r') buf[--n]='\0';
			pos = (end == plaintext.size()) ? end : end + 1;
		} else n = f.readln(buf, MAX_LEN);
		if(n == -1) break;
		if(!n) continue;

		++line;

		str2words(arg[0], buf, 10, MAX_LEN);
		if(arg[0][0] == '#' || !*arg[0]) continue;

		e = setVariable(arg[0], rtrim(srewind(buf, 1)));
		if(!e->ok)
		{
			printf("[-] %s/%s:%d: %s\n", cwd, file, line, (const char *) e->reason);
			++errors;
		}
	}

#ifndef HAVE_ADNS
    nxtproxy::defer_dns=false;
    // Do the classic local lookup only for truly direct connections.
    const bool proxied=strcmp(proxy_type,"none")!=0;
    const bool proxy_hub=proxied && !strcmp(proxy_scope,"irc,hub");
    const auto resolve_direct=[&](entHost &host) {
        if(host.isDefault() || !(host.getConnectionStringType(host.getValue()) & entHost::domain))return;
        const std::string original=host.getValue();
        options::event *event=host.setValue("host",original.c_str());
        if(!event || !event->ok) {
            printf("[-] Cannot resolve direct connection host: %s\n",original.c_str());
            ++errors;
        }
    };
    if(!proxied)
        for(int i=0;i<MAX_SERVERS;++i)
            if(!server[i].isDefault()) resolve_direct(server[i].getHost());
    if(!proxy_hub) {
        if(!hub.isDefault())resolve_direct(hub.getHost());
        for(int i=0;i<MAX_ALTS;++i)
            if(!alt[i].isDefault())resolve_direct(alt[i].getHost());
    }
#endif
	if(encrypted && !plaintext.empty()) sodium_memzero(&plaintext[0], plaintext.size());

	/* Basic checks */
	if(!nick.getLen())
	{
		printf("[-] Nick is not set\n");
		++errors;
	}

	if(errors)
	{
		plonk:
		printf("[-] Failed to load config\n");
		exit(1);
	}

        for(i=0; i<MAX_LISTENPORTS; i++)
        {
                if(config.listenport[i].isDefault())
                        continue;

                if(config.listenport[i].getHost().isSSL())
                        listening_ssl=true;

//                listening=true;

		if(!strcmp(config.listenport[i].getHandle(), "all") || !strcmp(config.listenport[i].getHandle(), "bots"))
			can_link_bots=true;
        }

	if(!config.hub.getPort())
	{
		printf("[*] Acting as MAIN\n");
		config.bottype = BOT_MAIN;
	}

	else if(can_link_bots)
	{
		printf("[*] Acting as SLAVE\n");
		config.bottype = BOT_SLAVE;
	}

	else
	{
		printf("[*] Acting as LEAF\n");
		config.bottype = BOT_LEAF;
	}

        if(config.bottype != BOT_LEAF)
        {
                if(alts)
                {
                        printf("[-] Alternating slaves can only be used for leafes\n");
                        goto plonk;
                }
        }
        else
        {
                if(!*config.hub.getHandle() && alts)
                {
                        printf("[-] Invalid hub's handle\n");
                        goto plonk;
                }
        }

    if(strcmp(proxy_type,"none") && strcmp(proxy_type,"socks5") && strcmp(proxy_type,"http")) {
        printf("[-] proxy-type must be none, socks5 or http\n");
        exit(1);
    }
    if(strcmp(proxy_scope,"irc") && strcmp(proxy_scope,"irc,hub")) {
        printf("[-] proxy-scope must be irc or irc,hub\n");
        exit(1);
    }
    if(strcmp(proxy_type,"none")) {
        if(proxy_host.isDefault() || proxy_port.value==0) {
            printf("[-] proxy-host and proxy-port are required\n");
            exit(1);
        }
        if(!proxy_user.getLen() && proxy_pass.getLen()) {
            printf("[-] proxy-pass requires proxy-user\n");
            exit(1);
        }
    }
	polish();

	if(imUp())
	{
		printf("[-] Signs on the sky tell me that i am already up\n");
		printf("[*] Terminating\n");
		exit(1337);
	}

	printf("[+] Config loaded\n");

#ifdef HAVE_SSL
	if(listening_ssl)
	{
		char tmp[MAX_LEN];
		char cwd[MAX_LEN];

		getcwd(cwd, MAX_LEN);

		printf("[*] Creating SSL context\n");
		
		if(!(inet::server_ctx = SSL_CTX_new(SSLv23_method())) || !SSL_CTX_set_mode(inet::server_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE))
		{
			printf("[-] Creation of SSL conext failed\n");
			exit(1);
		}

		snprintf(tmp, MAX_LEN, "server.key");
		printf("[*] Loading RSA private key from `%s/%s'\n", cwd, tmp);
		if(!SSL_CTX_use_RSAPrivateKey_file(inet::server_ctx, tmp, SSL_FILETYPE_PEM))
		{
			printf("[-] Error while loading key\n");
			exit(1);
		}
		
		snprintf(tmp, MAX_LEN, "server.crt");
		printf("[*] Loading server certificate from `%s/%s'\n", cwd, tmp);
		if(!SSL_CTX_use_certificate_file(inet::server_ctx, tmp, SSL_FILETYPE_PEM))
		{
			printf("[-] Error while loading cert\n");
			exit(1);
		}
	}
#endif

        for(i=0; i<MAX_LISTENPORTS; i++)
        {
                if(!config.listenport[i].isDefault())
                {
                        inet::listen_entry *e=new inet::listen_entry();

			e->access=0;

			if(!strcmp(config.listenport[i].getHandle(), "all"))
				e->access=LISTEN_ALL;
			else if(!strcmp(config.listenport[i].getHandle(), "users"))
				e->access=LISTEN_USERS;
			else if(!strcmp(config.listenport[i].getHandle(), "bots"))
				e->access=LISTEN_BOTS;

                        printf("[*] Opening listening socket at %s:%d\n", config.listenport[i].getHost().isIpv6() ? (const char *)config.listenport[i].getHost().ip6 : (const char *)config.listenport[i].getHost().ip4, (int) config.listenport[i].getPort());

                        if(config.listenport[i].isSSL())
                                e->use_ssl=true;

                        e->fd=startListening(config.listenport[i].getHost().isIpv6() ? (const char*)config.listenport[i].getHost().ip6 : (const char*)config.listenport[i].getHost().ip4, config.listenport[i].getPort());
                        net.listeners.add(e);

                        if(e->fd < 1)
                        {
                                printf("[-] Cannot open socket (%s)\n", strerror(errno));
                                exit(1);
                        }

                        printf("[+] Socket awaits incomming connections\n");
                }
        }
}
