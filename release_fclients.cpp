#include <DHCP_Starvation.h>
#include <CLI.h>

int main(int n_args,char **args){

    DHCPCLIENTS fclients("./Clients/fclients.cli");

    if(!fclients.size()){
        printf("DHCP context not found\n");
        return 1;
    }

    printf("Server: %s\n",sprint_ipv4(&fclients.siaddr));
    printf("Clients: %d\n",fclients.size());

    int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(sock == -1){
        printf("socket: %s\n",strerror(errno));
        return 1;
    }

    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")) return 1;

    sockaddr_ll saddr = {0};
    socklen_t saddr_len = sizeof(sockaddr_ll);

    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_IP);
    saddr.sll_ifindex = interface.index;

    if(bind(sock,(sockaddr*)&saddr,sizeof(sockaddr_ll)) == -1){
        printf("bind failed -> %s\n",strerror(errno));
        return 1;
    }

    if(getsockname(sock,(sockaddr*)&saddr,&saddr_len) == -1){
        printf("getsockname failed -> %s\n",strerror(errno));
        return 1;
    }

    if(saddr.sll_hatype != HARDWARE_ETHERNET || saddr.sll_halen != MAC_ADDRESS_LENGTH){
        printf("hardware address invalid\n");
        return 1;
    }

    uint8_t dhaddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    sockaddr_ll daddr = {0};
    daddr.sll_family = AF_PACKET;
    daddr.sll_protocol = htons(ETH_P_IP);
    daddr.sll_ifindex = interface.index;
    daddr.sll_hatype = HARDWARE_ETHERNET;
    daddr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(daddr.sll_addr,dhaddr,daddr.sll_halen);

    DHCP dhcp;
    UDP udp;
    IPV4 ipv4;
    PACKET spacket;

    for(auto &fclient : fclients){

        dhcp.write_release(DHCP_ID,fclient.iaddr,fclient.haddr,fclients.siaddr);
        udp.write_hdr_ipv4(interface.in_addr,INADDR_BROADCAST,DHCP_CLIENT_PORT,DHCP_SERVER_PORT,dhcp);
        ipv4.write_hdr(IPV4_ID,false,IPV4_TTL,IPPROTOCOL_UDP,interface.in_addr,INADDR_BROADCAST,udp.length() + dhcp.length());
        
        spacket = ipv4;
        spacket += udp;
        spacket += dhcp;

        for(int i = 0; i < 2; ++i){
            if(sendto(sock,spacket.data(),spacket.length(),0,(sockaddr*)&daddr,sizeof(sockaddr_ll)) == -1){
                printf("\nRELEASE sendto failed -> %s\n",strerror(errno));
            }
            usleep(300000);
        }

        printf("IP: %s ",sprint_ipv4(&fclient.iaddr));
        printf("MAC: %s\n",sprint_mac(fclient.haddr));
    }

    close(sock);

    return 0;
}
