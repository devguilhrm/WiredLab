#include <Packet.h>
#include <Utils.h>
#include <CLI.h>

int main(int n_args,char **args){

    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")) return 1;

    int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IPV6));
    if(sock == -1) return 1;

    uint8_t dhaddr[6] = {0x33,0x33,0x00,0x01,0x00,0x02};

    sockaddr_ll daddr = {0};
    daddr.sll_family = AF_PACKET;
    daddr.sll_protocol = htons(ETH_P_IPV6);
    daddr.sll_ifindex = interface.index;
    daddr.sll_hatype = HARDWARE_ETHERNET;
    daddr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(daddr.sll_addr,dhaddr,daddr.sll_halen);

    uint8_t siaddr[IPV6_ADDRESS_LENGTH];
    inet_pton(AF_INET6,"fe80::3a49:78da:9d07:80bf",siaddr);

    uint8_t diaddr[IPV6_ADDRESS_LENGTH];
    inet_pton(AF_INET6,"ff02::1:2",diaddr);

    uint32_t id = 777;
    uint8_t uuid[16] = {0x97,0x56,0x75,0x42,0xbd,0x07,0x86,0x3a,0x72,0x7c,0xaf,0x80,0x5a,0x49,0x74,0xc5};
    uint16_t ro[] = {
        htons(DHCPV6_OPT_DNS_SERVERS),
        htons(DHCPV6_OPT_DOMAIN_LIST),
        htons(DHCPV6_OPT_SNTP_SERVERS),
        htons(DHCPV6_OPT_INFORMATION_REFRESH_TIME),
        htons(DHCPV6_OPT_NTP_SERVER),
        htons(DHCPV6_OPT_INF_MAX_RT)
    };


    DHCPV6 dhcpv6;
    dhcpv6.write_information_request(id);
    dhcpv6.write_option_request(ro,sizeof(ro));
    dhcpv6.write_option_client_id_uuid(uuid);
    dhcpv6.write_option_elapsed_time(0);

    UDP udp;
    udp.write_hdr_ipv6(siaddr,diaddr,DHCPV6_CLIENT_PORT,DHCPV6_SERVER_PORT,dhcpv6);

    IPV6 ipv6;
    ipv6.write_hdr(udp.length() + dhcpv6.length(),IPPROTOCOL_UDP,64,siaddr,diaddr);

    ipv6.print();
    udp.print();
    dhcpv6.print();

    PACKET packet;
    packet = ipv6;
    packet += udp;
    packet += dhcpv6;

    if(sendto(sock,packet.data(),packet.length(),0,(sockaddr*)&daddr,sizeof(sockaddr_ll)) == -1){
        printf("sendto: %s\n",strerror(errno));
    }

    close(sock);

    return 0;
}
