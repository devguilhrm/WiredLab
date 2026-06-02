#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/icmpv6.h>

#include <unistd.h>

#include <Packet.h>

char buff[256] = {0};

#define PRINT(s) snprintf(buff,sizeof(buff),s)

const char* sprint_address_family(uint8_t family);
const char* sprint_route_scope(uint8_t scope);
const char* sprint_route_table(uint8_t table);
const char* sprint_route_protocol(uint8_t protocol);
const char* sprint_route_type(uint8_t type);

void print_nlmsghdr(nlmsghdr *nlh);
void print_rtmsg(rtmsg* msg);
void print_ifinfomsg(ifinfomsg* msg);

void get_all_link(int sock,int pid,sockaddr_nl &daddr);
void get_all_address(int sock,int pid,sockaddr_nl &daddr);
void get_all_router(int sock,int pid,sockaddr_nl &daddr);

int main(int n_args,char **args){

    int sock = socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE);
    if(sock == -1){
        printf("socket: %s\n",strerror(errno));
        return 1;
    }

    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

    int pid = getpid();
    printf("PID: %d\n",pid);

    sockaddr_nl saddr = {0};
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = pid;

    sockaddr_nl daddr = {0};
    daddr.nl_family = AF_NETLINK;

    if(bind(sock,(sockaddr*)&saddr,sizeof(sockaddr_nl)) == -1){
        printf("bind: %s\n",strerror(errno));
    }

    //get_all_link(sock,pid,daddr);
    //get_all_address(sock,pid,daddr);
    get_all_router(sock,pid,daddr);

    close(sock);
}

const char* sprint_address_family(uint8_t family){
    switch(family){
        case AF_UNSPEC:     PRINT("unspec"); break;
        case AF_LOCAL:      PRINT("local"); break;
        case AF_INET:       PRINT("inet"); break;
        case AF_AX25:       PRINT("ax25"); break;
        case AF_IPX:        PRINT("ipx"); break;
        case AF_APPLETALK:  PRINT("appletalk"); break;
        case AF_NETROM:     PRINT("netrom"); break;
        case AF_BRIDGE:     PRINT("bridge"); break;
        case AF_ATMPVC:     PRINT("atmpvc"); break;
        case AF_X25:        PRINT("x25"); break;
        case AF_INET6:      PRINT("inet6"); break;
        case AF_ROSE:       PRINT("rose"); break;
        case AF_DECnet:     PRINT("decnet"); break;
        case AF_NETBEUI:    PRINT("netbeui"); break;
        case AF_SECURITY:   PRINT("security"); break;
        case AF_KEY:        PRINT("key"); break;
        case AF_NETLINK:    PRINT("netlink"); break;
        case AF_PACKET:     PRINT("packet"); break;
        case AF_ASH:        PRINT("ash"); break;
        case AF_ECONET:     PRINT("econet"); break;
        case AF_ATMSVC:     PRINT("atmsvc"); break;
        case AF_RDS:        PRINT("rds"); break;
        case AF_SNA:        PRINT("sna"); break;
        case AF_IRDA:       PRINT("irda"); break;
        case AF_PPPOX:      PRINT("pppox"); break;
        case AF_WANPIPE:    PRINT("wanpipe"); break;
        case AF_LLC:        PRINT("llc"); break;
        case AF_IB:         PRINT("ib"); break;
        case AF_MPLS:       PRINT("mpls"); break;
        case AF_CAN:        PRINT("can"); break;
        case AF_TIPC:       PRINT("tipc"); break;
        case AF_BLUETOOTH:  PRINT("bluetooth"); break;
        case AF_IUCV:       PRINT("iucv"); break;
        case AF_RXRPC:      PRINT("rxrpc"); break;
        case AF_ISDN:       PRINT("isdn"); break;
        case AF_PHONET:     PRINT("phonet"); break;
        case AF_IEEE802154: PRINT("ieee802154"); break;
        case AF_CAIF:       PRINT("caif"); break;  
        case AF_ALG:        PRINT("alg"); break;
        case AF_NFC:        PRINT("nfc"); break;
        case AF_VSOCK:      PRINT("vsock"); break;
        case AF_KCM:        PRINT("kcm"); break;
        case AF_QIPCRTR:    PRINT("qipcrtr"); break;
        case AF_SMC:        PRINT("smc"); break;
        case AF_XDP:        PRINT("xdp"); break;
        case AF_MCTP:       PRINT("mctp"); break;
        default:            PRINT("invalid"); break;
    }
    return buff;
}

const char* sprint_route_scope(uint8_t scope){
    switch(scope){
        case RT_SCOPE_UNIVERSE: PRINT("universe"); break;
        case RT_SCOPE_SITE:     PRINT("site");     break;
        case RT_SCOPE_LINK:     PRINT("link");     break;
        case RT_SCOPE_HOST:     PRINT("host");     break;
        case RT_SCOPE_NOWHERE:  PRINT("nowhere");  break;
        default:                PRINT("unknown");  break;
    }
    return buff;
}

const char* sprint_route_table(uint8_t table){
    switch(table){
        case RT_TABLE_UNSPEC:  PRINT("unspec");  break;
        case RT_TABLE_COMPAT:  PRINT("compat");  break;
        case RT_TABLE_DEFAULT: PRINT("default"); break;
        case RT_TABLE_MAIN:    PRINT("main");    break;
        case RT_TABLE_LOCAL:   PRINT("local");   break;
        default:               PRINT("unknown"); break;
    }
    return buff;
}

const char* sprint_route_protocol(uint8_t protocol){
    switch(protocol){
        case RTPROT_UNSPEC:     PRINT("unspec");     break;
        case RTPROT_REDIRECT:   PRINT("redirect");   break;
		case RTPROT_KERNEL:     PRINT("kernel");     break;
        case RTPROT_BOOT:       PRINT("boot");       break;
        case RTPROT_STATIC:     PRINT("static");     break;
        case RTPROT_GATED:      PRINT("gated");      break;
        case RTPROT_RA:         PRINT("ra");         break;
        case RTPROT_MRT:        PRINT("mrt");        break;
        case RTPROT_ZEBRA:      PRINT("zebra");      break;
        case RTPROT_BIRD:       PRINT("bird");       break;
        case RTPROT_DNROUTED:   PRINT("dnrouted");   break;
        case RTPROT_XORP:       PRINT("xorp");       break;
        case RTPROT_NTK:        PRINT("ntk");        break;
        case RTPROT_DHCP:       PRINT("dhcp");       break;
        case RTPROT_MROUTED:    PRINT("mrouted");    break;
        case RTPROT_KEEPALIVED: PRINT("keepalived"); break;
        case RTPROT_BABEL:      PRINT("babel");      break;
        case RTPROT_OPENR:      PRINT("openr");      break;
        case RTPROT_BGP:        PRINT("bgp");        break;
        case RTPROT_ISIS:       PRINT("isis");       break;
        case RTPROT_OSPF:       PRINT("ospf");       break;
        case RTPROT_RIP:        PRINT("rip");        break;
        case RTPROT_EIGRP:      PRINT("eigrp");      break;
        default:                PRINT("unknown");    break;
    }
    return buff;
}

const char* sprint_route_type(uint8_t type){
    switch(type){
        case RTN_UNSPEC:      PRINT("unspec");      break;
        case RTN_UNICAST:     PRINT("unicast");     break;
        case RTN_LOCAL:       PRINT("local");       break;
        case RTN_BROADCAST:   PRINT("broadcast");   break;
        case RTN_ANYCAST:     PRINT("anycast");     break;
        case RTN_MULTICAST:   PRINT("multicast");   break;
        case RTN_BLACKHOLE:   PRINT("blackhole");   break;
        case RTN_UNREACHABLE: PRINT("unreachable"); break;
        case RTN_PROHIBIT:    PRINT("prohibit");    break;
        case RTN_THROW:       PRINT("throw");       break;
        case RTN_NAT:         PRINT("nat");         break;
        case RTN_XRESOLVE:    PRINT("xresolve");    break;
    }
    return buff;
}


void print_nlmsghdr(nlmsghdr* nlh){
    printf("nlmsghdr: {\n");
    printf("    nlmsg_len: %d\n",nlh->nlmsg_len);
    printf("    nlmsg_type: %d\n",nlh->nlmsg_type);
    printf("    nlmsg_flags: %d\n",nlh->nlmsg_flags);
    printf("    nlmsg_seq: %d\n",nlh->nlmsg_seq);
    printf("    nlmsg_pid: %d\n",nlh->nlmsg_pid);
    printf("}\n");
}

void print_rtmsg(rtmsg* msg){
    printf("rtmsg: {\n");
    printf("    rtm_family: %s (%d)\n",sprint_address_family(msg->rtm_family),msg->rtm_family);
    printf("    rtm_dst_len: %d\n",msg->rtm_dst_len);
    printf("    rtm_src_len: %d\n",msg->rtm_src_len);
    printf("    rtm_tos: %d\n",msg->rtm_tos);
    printf("    rtm_table: %s (%d)\n",sprint_route_table(msg->rtm_table),msg->rtm_table);
    printf("    rtm_protocol: %s (%d)\n",sprint_route_protocol(msg->rtm_protocol),msg->rtm_protocol);
    printf("    rtm_scope: %s (%d)\n",sprint_route_scope(msg->rtm_scope),msg->rtm_scope);
    printf("    rtm_type: %s (%d)\n",sprint_route_type(msg->rtm_type),msg->rtm_type);
    printf("    rtm_flags: %d\n",msg->rtm_flags);
    printf("}\n");
}

void print_ifinfomsg(ifinfomsg* msg){
    printf("ifinfomsg: {\n");
    printf("    ifi_family: %s (%d)\n",sprint_address_family(msg->ifi_family),msg->ifi_family);
    printf("    ifi_type: %d\n",msg->ifi_type);
    printf("    ifi_index: %d\n",msg->ifi_index);
    printf("    ifi_flags: {\n");
    if(msg->ifi_flags & IFF_UP)          printf("        up\n");
    if(msg->ifi_flags & IFF_BROADCAST)   printf("        broadcast\n");
    if(msg->ifi_flags & IFF_DEBUG)       printf("        debug\n");
    if(msg->ifi_flags & IFF_LOOPBACK)    printf("        loopback\n");
    if(msg->ifi_flags & IFF_POINTOPOINT) printf("        pointopoint\n");
    if(msg->ifi_flags & IFF_NOTRAILERS)  printf("        notrailers\n");
    if(msg->ifi_flags & IFF_RUNNING)     printf("        running\n");
    if(msg->ifi_flags & IFF_NOARP)       printf("        noarp\n");
    if(msg->ifi_flags & IFF_PROMISC)     printf("        promisc\n");
    if(msg->ifi_flags & IFF_ALLMULTI)    printf("        allmulti\n");
    if(msg->ifi_flags & IFF_MASTER)      printf("        master\n");
    if(msg->ifi_flags & IFF_SLAVE)       printf("        slave\n");
    if(msg->ifi_flags & IFF_MULTICAST)   printf("        multicast\n");
    if(msg->ifi_flags & IFF_PORTSEL)     printf("        portsel\n");
    if(msg->ifi_flags & IFF_AUTOMEDIA)   printf("        automedia\n");
    if(msg->ifi_flags & IFF_DYNAMIC)     printf("        dynamic\n");
    if(msg->ifi_flags & IFF_LOWER_UP)    printf("        lower up\n");
    if(msg->ifi_flags & IFF_DORMANT)     printf("        dormant\n");
    if(msg->ifi_flags & IFF_ECHO)        printf("        echo\n");
    printf("    }\n");
    printf("    ifi_change: %lu\n",msg->ifi_change);
    printf("}\n");
}

void print_ifaddrmsg(ifaddrmsg* msg){
    printf("ifaddrmsg: {\n");
    printf("    ifa_family: %s (%d)\n",sprint_address_family(msg->ifa_family),msg->ifa_family);
    printf("    ifa_prefixlen: %d\n",msg->ifa_prefixlen);
    printf("    ifa_flags: {\n");
    if(msg->ifa_flags & IFA_F_TEMPORARY)      printf("        temporary\n");
    if(msg->ifa_flags & IFA_F_NODAD)          printf("        no dad\n");
    if(msg->ifa_flags & IFA_F_OPTIMISTIC)     printf("        optimistic\n");
    if(msg->ifa_flags & IFA_F_DADFAILED)      printf("        dad failed\n");
    if(msg->ifa_flags & IFA_F_HOMEADDRESS)    printf("        home address\n");
    if(msg->ifa_flags & IFA_F_DEPRECATED)     printf("        deprecated\n");
    if(msg->ifa_flags & IFA_F_TENTATIVE)      printf("        tentative\n");
    if(msg->ifa_flags & IFA_F_PERMANENT)      printf("        permanent\n");
    if(msg->ifa_flags & IFA_F_MANAGETEMPADDR) printf("        manage temp addr\n");
    if(msg->ifa_flags & IFA_F_NOPREFIXROUTE)  printf("        no prefix route\n"); 	
    if(msg->ifa_flags & IFA_F_MCAUTOJOIN)     printf("        mc auto join\n");
    if(msg->ifa_flags & IFA_F_STABLE_PRIVACY) printf("        stable privacy\n");
    printf("    }\n");
    printf("    ifa_scope: %s (%d)\n",sprint_route_scope(msg->ifa_scope),msg->ifa_scope);
    printf("    ifa_index: %lu\n",msg->ifa_index);
    printf("}\n");
}


void get_all_link(int sock,int pid,sockaddr_nl &daddr){
    char buffer[8092] = {0};
    
    nlmsghdr* nlh = nullptr;
    nlmsgerr* nle = nullptr;
    ifinfomsg* msg = nullptr;
    rtattr* rta = nullptr;

    nlh = (nlmsghdr*)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = pid;

    msg = (ifinfomsg*)NLMSG_DATA(nlh);
    msg->ifi_family = AF_UNSPEC;

    if(sendto(sock,buffer,NLMSG_SPACE(sizeof(ifinfomsg)),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
        fprintf(stderr,"sendto: %s\n",strerror(errno));
    }
    else{
        bool runner = true;

        while(runner){
            ssize_t l = recv(sock,buffer,sizeof(buffer),0);

            if(l == -1){
                fprintf(stderr,"recv: %s\n",strerror(errno));
                runner = false;
            }
            else{
                for(nlh = (nlmsghdr*)buffer; NLMSG_OK(nlh,l); nlh = NLMSG_NEXT(nlh,l)){
                    
                    printf("\n");
                    print_nlmsghdr(nlh);

                    if(!(nlh->nlmsg_flags & NLM_F_MULTI) || (nlh->nlmsg_type == NLMSG_DONE)){
                        runner = false;
                    }

                    if(nlh->nlmsg_type == NLMSG_ERROR){
                        nle = (nlmsgerr*)NLMSG_DATA(nlh);
                        fprintf(stderr,"error: %s\n",strerror(-nle->error));
                    }
                    else if(nlh->nlmsg_type == RTM_NEWLINK){
                        msg = (ifinfomsg*)NLMSG_DATA(nlh);
                        print_ifinfomsg(msg);

                        int attrlen = IFLA_PAYLOAD(nlh);

                        for(rta = IFLA_RTA(msg); RTA_OK(rta,attrlen); rta = RTA_NEXT(rta,attrlen)){

                            //printf("\n");
                            //printf("type: %d length: %d\n",rta->rta_type,rta->rta_len);

                            void* data = RTA_DATA(rta);

                            switch(rta->rta_type & NLA_TYPE_MASK){
                                case IFLA_ADDRESS:   printf("ADDRESS: %s\n",sprint_mac(data)); break;
                                case IFLA_BROADCAST: printf("BROADCAST: %s\n",sprint_mac(data)); break;
                                case IFLA_IFNAME:    printf("IFNAME: %s\n",(char*)data); break;
                                case IFLA_MTU:       printf("MTU: %lu\n",*(uint32_t*)data); break;
                                case IFLA_LINK:      printf("LINK: %d\n",*(int*)data); break;
                                case IFLA_QDISC:     printf("QDISC: %s\n",(char*)data); break;
                                case IFLA_COST:      printf("COST: %s\n",(char*)data); break;
                                case IFLA_PRIORITY:  printf("PRIORITY: %s\n",(char*)data); break;
                                case IFLA_MASTER:    printf("MASTER: %lu\n",*(uint32_t*)data); break;
                                case IFLA_WIRELESS:  printf("WIRELESS: %s\n",(char*)data); break;
                                case IFLA_PROTINFO:  printf("PROTINFO: %s\n",(char*)data); break;
                                case IFLA_TXQLEN:    printf("TXQLEN: %lu\n",*(uint32_t*)data); break;
                                case IFLA_OPERSTATE:{
                                    printf("OPERSTATE: ");
                                    switch(*(uint8_t*)data){
                                        case IF_OPER_UNKNOWN:        printf("Unknown ");          break;
                                        case IF_OPER_NOTPRESENT:     printf("Not present ");      break;
                                        case IF_OPER_DOWN:           printf("Down ");             break;
                                        case IF_OPER_LOWERLAYERDOWN: printf("Lower layer down "); break;
                                        case IF_OPER_TESTING:        printf("Testing ");          break;
                                        case IF_OPER_DORMANT:        printf("Dormant ");          break;
                                        case IF_OPER_UP:             printf("Up ");               break;
                                    }
                                    printf("(%d)\n",*(uint8_t*)data);
                                    break;
                                }
                                case IFLA_LINKMODE:{
                                    printf("LINKMODE: ");
                                    switch(*(uint8_t*)data){
                                        case IF_LINK_MODE_DEFAULT: printf("Default "); break;
                                        case IF_LINK_MODE_DORMANT: printf("Dormant "); break;
                                        case IF_LINK_MODE_TESTING: printf("Testing "); break;
                                    }
                                    printf("(%d)\n",*(uint8_t*)data);
                                    break;
                                }
                                case IFLA_GROUP:               printf("GROUP: %lu\n",*(uint32_t*)data); break;
                                case IFLA_PROMISCUITY:         printf("PROMISCUITY: %lu\n",*(uint32_t*)data); break;
                                case IFLA_NUM_TX_QUEUES:       printf("NUM TX QUEUES: %lu\n",*(uint32_t*)data); break;
                                case IFLA_NUM_RX_QUEUES:       printf("NUM RX QUEUES: %lu\n",*(uint32_t*)data); break;
                                case IFLA_CARRIER:             printf("CARRIER: %d\n",*(uint8_t*)data); break;
                                case IFLA_CARRIER_CHANGES:     printf("CARRIER CHANGES: %lu\n",*(uint8_t*)data); break;
                                case IFLA_PROTO_DOWN:          printf("PROTO DOWN: %d\n",*(uint8_t*)data); break;
                                case IFLA_GSO_MAX_SEGS:        printf("GSO MAX SEGS: %lu\n",*(uint32_t*)data); break;
                                case IFLA_GSO_MAX_SIZE:        printf("GSO MAX SIZE: %lu\n",*(uint32_t*)data); break;
                                case IFLA_CARRIER_UP_COUNT:    printf("CARRIER UP COUNT: %lu\n",*(uint32_t*)data); break;
                                case IFLA_CARRIER_DOWN_COUNT:  printf("CARRIER DOWN COUNT: %lu\n",*(uint32_t*)data); break;
                                case IFLA_MIN_MTU:             printf("MIN MTU: %lu\n",*(uint32_t*)data); break;
                                case IFLA_MAX_MTU:             printf("MAX MTU: %lu\n",*(uint32_t*)data); break;
                                case IFLA_PERM_ADDRESS:        printf("PERM ADDRESS: %s\n",sprint_mac(data)); break;
                                case IFLA_PROTO_DOWN_REASON:   printf("PROTO DOWN REASON: %s\n",(char*)data); break;
                                case IFLA_PARENT_DEV_NAME:     printf("PARENT DEV NAME: %s\n",(char*)data); break;
                                case IFLA_PARENT_DEV_BUS_NAME: printf("PARENT DEV BUS NAME: %s\n",(char*)data); break;
                                case IFLA_GRO_MAX_SIZE:        printf("GRO MAX SIZE: %lu\n",*(uint32_t*)data); break;
                                case IFLA_TSO_MAX_SIZE:        printf("TSO MAX SIZE: %lu\n",*(uint32_t*)data); break;
                                case IFLA_TSO_MAX_SEGS:        printf("TSO MAX SEGS: %lu\n",*(uint32_t*)data); break;
                                case IFLA_ALLMULTI:            printf("ALLMULTI: %lu\n",*(uint32_t*)data); break;
                            }
                        }
                    }                
                }
            }
        }
    }
}

void get_all_address(int sock,int pid,sockaddr_nl &daddr){
    char buffer[8092] = {0};

    nlmsghdr* nlh = nullptr;
    nlmsgerr* nle = nullptr;
    ifaddrmsg* msg = nullptr;
    rtattr* rta = nullptr;

    nlh = (nlmsghdr*)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = pid;

    msg = (ifaddrmsg*)NLMSG_DATA(nlh);
    msg->ifa_family = AF_UNSPEC;

    if(sendto(sock,buffer,NLMSG_SPACE(sizeof(ifaddrmsg)),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
        fprintf(stderr,"sendto: %s\n",strerror(errno));
    }
    else{
        bool runner = true;
        
        while(runner){
            
            ssize_t l = recv(sock,buffer,sizeof(buffer),0);

            if(l == -1){
                fprintf(stderr,"recv: %s\n",strerror(errno));
                runner = false;
            }
            else{
                for(nlh = (nlmsghdr*)buffer; NLMSG_OK(nlh,l); nlh = NLMSG_NEXT(nlh,l)){

                    printf("\n");
                    print_nlmsghdr(nlh);

                    if(!(nlh->nlmsg_flags & NLM_F_MULTI) || (nlh->nlmsg_type == NLMSG_DONE)){
                        runner = false;
                    }
                    
                    if(nlh->nlmsg_type == NLMSG_ERROR){
                        nle = (nlmsgerr*)NLMSG_DATA(nlh);
                        printf("error: %s\n",strerror(-nle->error));
                    }
                    else if(nlh->nlmsg_type == RTM_NEWADDR){
                        msg = (ifaddrmsg*)NLMSG_DATA(nlh);
                        print_ifaddrmsg(msg);

                        int attrlen = IFA_PAYLOAD(nlh);

                        for(rta = IFA_RTA(msg); RTA_OK(rta,attrlen); rta = RTA_NEXT(rta,attrlen)){

                            printf("\n");
                            printf("type: %d length: %d\n",rta->rta_type,rta->rta_len);
                            
                            void* data = RTA_DATA(rta);

                            switch(rta->rta_type & NLA_TYPE_MASK){
                                case IFA_ADDRESS:{
                                    if(msg->ifa_family == AF_INET){
                                        printf("address: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->ifa_family == AF_INET6){
                                        printf("address: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case IFA_LOCAL:{
                                    if(msg->ifa_family == AF_INET){
                                        printf("local: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->ifa_family == AF_INET6){
                                        printf("local: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case IFA_LABEL:{
                                    printf("label: %s\n",(char*)data);
                                    break;
                                }
                                case IFA_BROADCAST:{
                                    if(msg->ifa_family == AF_INET){
                                        printf("broadcast: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->ifa_family == AF_INET6){
                                        printf("broadcast: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case IFA_CACHEINFO:{
                                    ifa_cacheinfo* cache = (ifa_cacheinfo*)data;
                                    printf("ifa_cacheinfo: {\n");
                                    if(cache->ifa_prefered == UINT32_MAX){
                                        printf("    prefered: infinite\n");
                                    }
                                    else{
                                        printf("    prefered: %lus\n",cache->ifa_prefered);
                                    }
                                    if(cache->ifa_valid == UINT32_MAX){
                                        printf("    valid: infinite\n");
                                    }
                                    else{
                                        printf("    valid: %lus\n",cache->ifa_valid);
                                    }
                                    printf("    cstamp: %lus\n",cache->cstamp);
                                    printf("    tstamp: %lus\n",cache->tstamp);
                                    printf("}\n");
                                    break;
                                }
                                case IFA_FLAGS:{
                                    uint32_t flags = *(uint32_t*)data;
                                    printf("flags: {\n");
                                    if(flags & IFA_F_TEMPORARY)      printf("    temporary\n");
                                    if(flags & IFA_F_NODAD)          printf("    no dad\n");
                                    if(flags & IFA_F_OPTIMISTIC)     printf("    optimistic\n");
                                    if(flags & IFA_F_DADFAILED)      printf("    dad failed\n");
                                    if(flags & IFA_F_HOMEADDRESS)    printf("    home address\n");
                                    if(flags & IFA_F_DEPRECATED)     printf("    deprecated\n");
                                    if(flags & IFA_F_TENTATIVE)      printf("    tentative\n");
                                    if(flags & IFA_F_PERMANENT)      printf("    permanent\n");
                                    if(flags & IFA_F_MANAGETEMPADDR) printf("    manage temp addr\n");
                                    if(flags & IFA_F_NOPREFIXROUTE)  printf("    no prefix route\n"); 	
                                    if(flags & IFA_F_MCAUTOJOIN)     printf("    mc auto join\n");
                                    if(flags & IFA_F_STABLE_PRIVACY) printf("    stable privacy\n");
                                    printf("}\n");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void get_all_router(int sock,int pid,sockaddr_nl &daddr){
    char buffer[8092] = {0};

    nlmsghdr* nlh = nullptr;
    nlmsgerr* nle = nullptr;
    rtmsg* msg = nullptr;
    rtattr* rta = nullptr;

    nlh = (nlmsghdr*)buffer;
    msg = (rtmsg*)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = pid;

    msg->rtm_family = AF_INET;

    if(sendto(sock,buffer,NLMSG_SPACE(sizeof(rtmsg)),0,(sockaddr*)&daddr,sizeof(sockaddr_nl)) == -1){
        fprintf(stderr,"sendto: %s\n",strerror(errno));
    }
    else{
        bool runner = true;
        while(runner){
            ssize_t l = recv(sock,buffer,sizeof(buffer),0);
            if(l == -1){
                fprintf(stderr,"recv: %s\n",strerror(errno));
                runner = false;
            }
            else{
                for(nlh = (nlmsghdr*)buffer; NLMSG_OK(nlh,l); nlh = NLMSG_NEXT(nlh,l)){
                    
                    printf("\n");
                    print_nlmsghdr(nlh);

                    if(!(nlh->nlmsg_flags & NLM_F_MULTI) || (nlh->nlmsg_type == NLMSG_DONE)){
                        runner = false;
                    }
                    
                    if(nlh->nlmsg_type == NLMSG_ERROR){
                        nle = (nlmsgerr*)NLMSG_DATA(nlh);
                        fprintf(stderr,"error: %s\n",strerror(-nle->error));
                    }
                    else if(nlh->nlmsg_type == RTM_NEWROUTE){
                        msg = (rtmsg*)NLMSG_DATA(nlh);
                        print_rtmsg(msg);

                        int attrlen = RTM_PAYLOAD(nlh);

                        for(rta = RTM_RTA(msg); RTA_OK(rta,attrlen); rta = RTA_NEXT(rta,attrlen)){
                            
                            printf("\n");
                            printf("type: %d length: %d\n",rta->rta_type,rta->rta_len);

                            void* data = RTA_DATA(rta);

                            switch(rta->rta_type & NLA_TYPE_MASK){
                                case RTA_DST:{
                                    if(msg->rtm_family == AF_INET){
                                        printf("dst: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->rtm_family == AF_INET6){
                                        printf("dst: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case RTA_SRC:{
                                    if(msg->rtm_family == AF_INET){
                                        printf("src: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->rtm_family == AF_INET6){
                                        printf("src: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case RTA_IIF:{
                                    printf("input interface: %lu\n",*(uint32_t*)data);
                                    break;
                                }
                                case RTA_OIF:{
                                    printf("output interface: %lu\n",*(uint32_t*)data);
                                    break;
                                }
                                case RTA_GATEWAY:{
                                    if(msg->rtm_family == AF_INET){
                                        printf("gateway: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->rtm_family == AF_INET6){
                                        printf("gateway: %s\n",sprint_ipv6(data));
                                    }
                                    break;
                                }
                                case RTA_PRIORITY:{
                                    printf("priority: %lu\n",*(uint32_t*)data);
                                    break;
                                }
                                case RTA_PREFSRC:{
                                    if(msg->rtm_family == AF_INET){
                                        printf("prefsrc: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->rtm_family == AF_INET6){
                                        printf("prefsrc: %s\n",sprint_ipv6(data));
                                    }
                                    break;                                 
                                }
                                case RTA_METRICS: break;
                                case RTA_MULTIPATH: break;
                                case RTA_PROTOINFO: break;
                                case RTA_FLOW: break;
                                case RTA_CACHEINFO: break;
                                case RTA_SESSION: break;
                                case RTA_MP_ALGO: break;
                                case RTA_TABLE:{
                                    uint32_t table_id = *(uint32_t*)data;
                                    printf("table: %s (%d)\n",sprint_route_table(table_id),table_id);
                                    break;
                                }
                                case RTA_MARK: break;
                                case RTA_MFC_STATS: break;
                                case RTA_VIA: break;
                                case RTA_NEWDST:{
                                    if(msg->rtm_family == AF_INET){
                                        printf("newdst: %s\n",sprint_ipv4(data));
                                    }
                                    else if(msg->rtm_family == AF_INET6){
                                        printf("newdst: %s\n",sprint_ipv6(data));
                                    }
                                    break;                                   
                                }
                                case RTA_PREF:{
                                    uint8_t pref = *(uint8_t*)data;
                                    printf("preference: ");
                                    switch(pref){
                                        case ICMPV6_ROUTER_PREF_MEDIUM:  printf("medium "); break;
                                        case ICMPV6_ROUTER_PREF_HIGH:    printf("high "); break;
                                        case ICMPV6_ROUTER_PREF_LOW:     printf("low "); break;
                                        default:                         printf("invalid "); break;
                                    }
                                    printf("(%d)\n",pref);
                                    break;
                                }
                                case RTA_ENCAP_TYPE: break;
                                case RTA_ENCAP: break;
                                case RTA_EXPIRES: break;
                                case RTA_PAD: break;
                                case RTA_UID: break;
                                case RTA_TTL_PROPAGATE: break;
                                case RTA_IP_PROTO: break;
                                case RTA_SPORT: break;
                                case RTA_DPORT: break;
                                case RTA_NH_ID: break;
                            }
                        }
                    }
                }
            }
        }
    }
}