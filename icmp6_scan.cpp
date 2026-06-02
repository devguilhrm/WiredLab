#include <Utils.h>
#include <Packet.h>
#include <Filter.h>
#include <CLI.h>

#include <vector>
#include <string>
#include <chrono>

#include <curl/curl.h>

#define CURL_BUFFER_LENGTH 260

#define MAC_FIND_URL "https://api.macvendors.com"

#define MAX_ATTEMPTS 15

struct HOST {
    uint8_t iaddr[IPV6_ADDRESS_LENGTH];
    uint8_t haddr[MAC_ADDRESS_LENGTH];
    std::string vendor;
};

size_t cb(char *data,size_t size,size_t n,void *userdata){
    char* curl_buffer = (char*)userdata;
    
    size_t bytes = size * n;

    size_t length = (bytes >= CURL_BUFFER_LENGTH) ? CURL_BUFFER_LENGTH - 1 : bytes;
    
    memcpy(curl_buffer,data,bytes);

    curl_buffer[length] = '\0';

    return bytes;
}

int main(int n_args,char **args){

    char curl_buffer[CURL_BUFFER_LENGTH] = {0};

    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")){
        return 1;
    }

    if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK){
        printf("curl_global_init: failed\n");
        return 1;
    }

    CURL* handle = curl_easy_init();
    if(!handle){
        printf("curl_easy_init: failed\n");
        return 1;
    }

    curl_easy_setopt(handle,CURLOPT_WRITEFUNCTION,cb);
    curl_easy_setopt(handle,CURLOPT_WRITEDATA,curl_buffer);


    int sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sock == -1){
        printf("socket: %s\n",strerror(errno));
        return 1;
    }

    sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = interface.index;
    if(bind(sock,(sockaddr*)&saddr,sizeof(saddr)) == -1){
        printf("bind: %s\n",strerror(errno));
        return 1;
    }

    timeval tv;
    tv.tv_sec = 1e+0;
    tv.tv_usec = 0e+0;
    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
        printf("setsockopt: %s\n",strerror(errno));
        return 1;
    }

    sock_filter filter[] = {
        //ethernet dst addr == interface.haddr
        {BPF_LD  | BPF_H   | BPF_ABS,0,0,ETHERNET_DST_OFFSET + 0},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,19,READH(interface.haddr + 0)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,ETHERNET_DST_OFFSET + 2},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,17,READW(interface.haddr + 2)},
        //ethernet type == ipv6
        {BPF_LD  | BPF_H   | BPF_ABS,0,0,ETHERNET_TYPE_OFFSET},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,15,ETHERNET_IPV6},

        {BPF_LDX | BPF_W   | BPF_IMM,0,0,ETHERNET_HDR_LENGTH},

        //ipv6 next hdr == icmpv6
        {BPF_LD  | BPF_B   | BPF_IND,0,0,IPV6_NEXT_HDR_OFFSET},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,12,IPPROTOCOL_ICMPV6},
        //ipv6 dst addr == interface.in6_addr
        {BPF_LD  | BPF_W   | BPF_IND,0,0,IPV6_DST_ADDR_OFFSET + 0},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,10,READW(interface.in6_addr + 0)},
        {BPF_LD  | BPF_W   | BPF_IND,0,0,IPV6_DST_ADDR_OFFSET + 4},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,8,READW(interface.in6_addr + 4)},
        {BPF_LD  | BPF_W   | BPF_IND,0,0,IPV6_DST_ADDR_OFFSET + 8},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,6,READW(interface.in6_addr + 8)},
        {BPF_LD  | BPF_W   | BPF_IND,0,0,IPV6_DST_ADDR_OFFSET + 12},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,4,READW(interface.in6_addr + 12)},

        {BPF_LDX | BPF_W   | BPF_IMM,0,0,ETHERNET_HDR_LENGTH + IPV6_HDR_LENGTH},

        //icmpv6 type == echo reply
        {BPF_LD  | BPF_B   | BPF_IND,0,0,ICMPV6_TYPE_OFFSET},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,1,ICMPV6::ECHO_REPLY},

        {BPF_RET | BPF_K,0,0,(uint32_t)-1},
        {BPF_RET | BPF_K,0,0,0}
    };

    sock_fprog fprog = {sizeof(filter) / sizeof(filter[0]),filter};

    if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
        printf("setsockopt: %s\n",strerror(errno));
        return 1;
    }

    uint8_t dhaddr[6] = {0x33,0x33,0x00,0x00,0x00,0x01};
    uint8_t diaddr[16] = {0};
    inet_pton(AF_INET6,"ff02::1",diaddr);

    sockaddr_ll daddr = {0};
    daddr.sll_family = AF_PACKET;
    daddr.sll_ifindex = interface.index;
    daddr.sll_hatype = HARDWARE_ETHERNET;
    daddr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(daddr.sll_addr,dhaddr,daddr.sll_halen);

    PACKET spacket;
    PACKET rpacket;
    ETHERNET ethernet;
    IPV6 ipv6;
    ICMPV6 icmpv6;

    icmpv6.echo_request(interface.in6_addr,diaddr,777,0);
    
    ipv6.write_hdr(icmpv6.length(),IPPROTOCOL_ICMPV6,64,interface.in6_addr,diaddr);

    ethernet.write_hdr(interface.haddr,dhaddr,ETHERNET_IPV6);

    spacket = ethernet;
    spacket += ipv6;
    spacket += icmpv6;

    std::vector<HOST> hosts;

    auto start = std::chrono::steady_clock::now();

    print_percent_bar(0,MAX_ATTEMPTS);

    for(int i = 0; i < MAX_ATTEMPTS; ++i){

        if(sendto(sock,spacket.data(),spacket.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
            printf("sendto: %s\n",strerror(errno));
            continue;
        }

        while(true){
            int l = recv(sock,rpacket.data(),rpacket.capacity(),0);
            
            if(l == -1) break;

            rpacket.set_length(l);

            ethernet = rpacket.unpack_ethernet();
            ipv6 = rpacket.unpack_ipv6();
            icmpv6 = rpacket.unpack<ICMPV6>();

            IPV6::HDR ipv6_hdr = ipv6.read_hdr();
            ETHERNET::HDR ether_hdr = ethernet.read_hdr();

            bool find_host = false;

            for(auto& host : hosts){
                if(!memcmp(host.iaddr,ipv6_hdr.saddr,sizeof(host.iaddr))){
                    find_host = true;
                    break;
                }
            }

            if(find_host) continue;

            HOST& host = hosts.emplace_back();

            memcpy(host.iaddr,ipv6_hdr.saddr,sizeof(host.iaddr));
            memcpy(host.haddr,ether_hdr.shaddr,sizeof(host.haddr));

            snprintf(curl_buffer,sizeof(curl_buffer),"%s/%s",MAC_FIND_URL,sprint_mac(host.haddr));

            curl_easy_setopt(handle,CURLOPT_URL,curl_buffer);

            auto current = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(current - start).count();
            if(elapsed < 1e+6){
                usleep(1e+6 - elapsed);
            }

            if(curl_easy_perform(handle) == CURLE_OK && strcmp(curl_buffer,"{\"errors\":{\"detail\":\"Not Found\"}}")){
                host.vendor = curl_buffer;
            }

            start = std::chrono::steady_clock::now();
        }

        print_percent_bar(i+1,MAX_ATTEMPTS);
    }

    for(auto& host : hosts){
        printf("IP: %s ",sprint_ipv6(host.iaddr));
        printf("MAC: %s ",sprint_mac(host.haddr));
        if(host.vendor.length()){
            printf("Vendor: %s",host.vendor.c_str());
        }
        printf("\n");
    }

    close(sock);

    curl_easy_cleanup(handle);
    curl_global_cleanup();

    return 0;
}
