#include <Utils.h>
#include <Packet.h>
#include <CLI.h>

struct RootHint{
    const char* hostname;
    uint32_t in_addr;
    uint8_t in6_addr[IPV6_ADDRESS_LENGTH];
};

RootHint root_hint[13];

#define HOSTNAME(i,s) root_hint[i].hostname = s
#define INADDR(i,s) inet_pton(AF_INET,s,&root_hint[i].in_addr)
#define IN6ADDR(i,s) inet_pton(AF_INET6,s,root_hint[i].in6_addr)

void init_root_hints(){
    HOSTNAME(0,"a.root-servers.net");  INADDR(0,"198.41.0.4");     IN6ADDR(0,"2001:503:ba3e::2:30");
    HOSTNAME(1,"b.root-servers.net");  INADDR(1,"170.247.170.2");  IN6ADDR(1,"2801:1b8:10::b");
    HOSTNAME(2,"c.root-servers.net");  INADDR(2,"192.33.4.12");    IN6ADDR(2,"2001:500:2::c");
    HOSTNAME(3,"d.root-servers.net");  INADDR(3,"199.7.91.13");    IN6ADDR(3,"2001:500:2d::d");
    HOSTNAME(4,"e.root-servers.net");  INADDR(4,"192.203.230.10"); IN6ADDR(4,"2001:500:a8::e");
    HOSTNAME(5,"f.root-servers.net");  INADDR(5,"192.5.5.241");    IN6ADDR(5,"2001:500:2f::f");
    HOSTNAME(6,"g.root-servers.net");  INADDR(6,"192.112.36.4");   IN6ADDR(6,"2001:500:12::d0d");
    HOSTNAME(7,"h.root-servers.net");  INADDR(7,"198.97.190.53");  IN6ADDR(7,"2001:500:1::53");
    HOSTNAME(8,"i.root-servers.net");  INADDR(8,"192.36.148.17");  IN6ADDR(8,"2001:7fe::53");
    HOSTNAME(9,"j.root-servers.net");  INADDR(9,"192.58.128.30");  IN6ADDR(9,"2001:503:c27::2:30");
    HOSTNAME(10,"k.root-servers.net"); INADDR(10,"193.0.14.129");  IN6ADDR(10,"2001:7fd::1");
    HOSTNAME(11,"l.root-servers.net"); INADDR(11,"199.7.83.42");   IN6ADDR(11,"2001:500:9f::42");
    HOSTNAME(12,"m.root-servers.net"); INADDR(12,"202.12.27.33");  IN6ADDR(12,"2001:dc3::35");
}

int main(int n_args,char **args){
    init_root_hints();

    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")) return 1;

    int sock = socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
    if(sock == -1){
        printf("socket: %s\n",strerror(errno));
        return 1;
    }

    timeval tv;
    tv.tv_sec = 2e-0;
    tv.tv_usec = 0e-0;
    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
        printf("setsockopt: %s\n",strerror(errno));
        return 1;
    }

    sockaddr_in6 daddr = {0};
    daddr.sin6_family = AF_INET6;
    daddr.sin6_port = htons(DNS_SERVER_PORT);
    memcpy(&daddr.sin6_addr,root_hint[0].in6_addr,sizeof(daddr.sin6_addr));

    if(connect(sock,(sockaddr*)&daddr,sizeof(daddr)) == -1){
        printf("connect: %s\n",strerror(errno));
    }

    DNS dns;
    DNS::FLAGS flags;
    flags.qr = false;
    flags.opcode = DNS::OPCODE::QUERY;
    flags.aa = false;
    flags.tc = false;
    flags.rd = false;
    flags.rcode = 0;

    dns.write_hdr<true>(777,flags,1,0,0,0);
    dns.write_question("www.gov.br",DNS::TYPE::A,DNS::CLASS::INTERNET);
    dns.set_prefix_length();

    //dns.print<true>();

    if(send(sock,dns.data(),dns.length(),0) == -1){
        printf("sendto: %s\n",strerror(errno));
    }
    else{
        int result = 0;
        
        uint16_t length = 0;
        
        result = recv(sock,&length,sizeof(length),MSG_PEEK | MSG_WAITALL);

        if(result == -1){
            printf("recv: %s (%d)\n",strerror(errno),errno);
        }
        else if(result == sizeof(length)){
            
            length = ntohs(length) + 2;

            if(length > dns.capacity()){
                length = dns.capacity();
            }

            result = recv(sock,dns.data(),length,MSG_WAITALL);

            if(result == -1){
                printf("recv: %s (%d)\n",strerror(errno),errno);
            }
            else if(result <= length){
                dns.set_length(length);
                dns.print<true>();
            }
        }
    }
    
    close(sock);

    return 0;
}
