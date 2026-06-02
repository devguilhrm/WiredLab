#include <Utils.h>
#include <Packet.h>
#include <Filter.h>
#include <CLI.h>

int main(int n_args,char **args){

    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")){
        return 1;
    }

    uint8_t haddr[MAC_ADDRESS_LENGTH] = {0};
    if(!cli_read_mac(haddr,n_args,args,"--mac","MAC Address: ")){
        return 1;
    }

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
    tv.tv_sec = 1e-0;
    tv.tv_usec = 0e-0;
    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
        printf("setsockopt: %s\n",strerror(errno));
        return 1;
    }

    sock_filter filter[] = {
        //ethernet src == interface.haddr
        {BPF_LD   | BPF_H   | BPF_ABS,0,0,ETHERNET_SRC_OFFSET + 0},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,0,20,READH(haddr + 0)},
        {BPF_LD   | BPF_W   | BPF_ABS,0,0,ETHERNET_SRC_OFFSET + 2},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,0,18,READW(haddr + 2)},
        //ethernet type == ipv4
        {BPF_LD   | BPF_H   | BPF_ABS,0,0,ETHERNET_TYPE_OFFSET},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,1,0,ETHERNET_IPV4},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,8,15,ETHERNET_IPV6},
        
        //ipv4 protocol == (udp or tcp)
        {BPF_LD   | BPF_B   | BPF_ABS,0,0,ETHERNET_HDR_LENGTH + IPV4_PROTOCOL_OFFSET},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,1,0,IPPROTOCOL_UDP},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,0,12,IPPROTOCOL_TCP},
        //x = src port offset
        {BPF_LDX  | BPF_B   | BPF_MSH,0,0,ETHERNET_HDR_LENGTH + IPV4_IHL_OFFSET},
        {BPF_MISC | BPF_TXA,          0,0,0},
        {BPF_ALU  | BPF_ADD | BPF_IMM,0,0,ETHERNET_HDR_LENGTH},
        {BPF_MISC | BPF_TAX,          0,0,0},
        {BPF_JMP  | BPF_IMM,          0,0,4},

        //ipv6 next header == (udp or tcp)
        {BPF_LD   | BPF_B   | BPF_ABS,0,0,ETHERNET_HDR_LENGTH + IPV6_NEXT_HDR_OFFSET},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,1,0,IPPROTOCOL_UDP},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,0,4,IPPROTOCOL_TCP},
        //x = src port offset
        {BPF_LDX  | BPF_W   | BPF_IMM,0,0,ETHERNET_HDR_LENGTH + IPV6_HDR_LENGTH},

        //src port == dns server port
        {BPF_LD   | BPF_H   | BPF_IND,0,0,DST_PORT_OFFSET},
        {BPF_JMP  | BPF_JEQ | BPF_IMM,0,1,DNS_SERVER_PORT},

        {BPF_RET  | BPF_K,0,0,(uint32_t)-1},
        {BPF_RET  | BPF_K,0,0,0}
    };

    sock_fprog fprog = {
        sizeof(filter) / sizeof(filter[0]),
        filter
    };

    if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
        printf("setsockopt: %s\n",strerror(errno));
        return -1;
    }

    PACKET packet;
    
    ETHERNET ethernet;
    ETHERNET::HDR ethernet_hdr;

    IPV4 ipv4;
    IPV4::HDR ipv4_hdr;

    IPV6 ipv6;
    IPV6::HDR ipv6_hdr;

    DNS dns;
    DNS::MESSAGE dns_msg;

    while(true){
        int l = recv(sock,packet.data(),packet.capacity(),0);
        
        if(l <= 0) continue;
        
        packet.set_length(l);
        
        ethernet = packet.unpack_ethernet();

        ethernet_hdr = ethernet.read_hdr();

        uint8_t ip_protocol = 0;

        if(ethernet_hdr.type == ETHERNET_IPV4){
            ipv4 = packet.unpack_ipv4();
            ipv4_hdr = ipv4.read_hdr();
            ip_protocol = ipv4_hdr.protocol;
        }
        else if(ethernet_hdr.type == ETHERNET_IPV6){
            ipv6 = packet.unpack_ipv6();
            ipv6_hdr = ipv6.read_hdr();
            ip_protocol = ipv6_hdr.next_header;
        }
        else{
            continue;
        }

        if(ip_protocol == IPPROTOCOL_TCP){
            packet.unpack_tcp_void();

            if(packet.length()){
                dns = packet.unpack<DNS>();
                dns_msg = dns.read_message<true>();
                for(uint16_t i = 0; i < dns_msg.qdcount; ++i){
                    printf("%s\n",dns_msg.question[i].qname);
                }
            }
        }
        else if(ip_protocol == IPPROTOCOL_UDP){
            packet.unpack_udp_void();
            
            if(packet.length()){
                dns = packet.unpack<DNS>();
                dns_msg = dns.read_message<false>();
                for(uint16_t i = 0; i < dns_msg.qdcount; ++i){
                    printf("%s\n",dns_msg.question[i].qname);
                }
            }
        }
    }

    close(sock);

    return 0;
}
