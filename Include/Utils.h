#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>

#include <string>

struct Interface{
	int index;

	std::string name;

	uint8_t haddr[6];
	
	uint32_t in_addr;
	uint8_t in_prefix_length;

	uint8_t in6_addr[16];
	uint8_t in6_prefix_length;

	Interface():
	index(0),
	haddr{0},
	in_addr(0),
	in_prefix_length(0),
	in6_addr{0},
	in6_prefix_length(0)
	{}

	bool init(const char* ifname){
		
		name = ifname;

		int sock = socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE);
		if(sock == -1){
			fprintf(stderr,"function: %s line: %d socket: failed\n",__func__,__LINE__);
			return false;
		}
		
		timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
			fprintf(stderr,"function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
			close(sock);
			return false;
		}

		sockaddr_nl saddr = {0};
		saddr.nl_family = AF_NETLINK;
		saddr.nl_pid = getpid();
		if(bind(sock,(sockaddr*)&saddr,sizeof(saddr)) == -1){
			fprintf(stderr,"function: %s line: %d bind: %s\n",__func__,__LINE__,strerror(errno));
			close(sock);
			return false;
		}

		sockaddr_nl daddr = {0};
		daddr.nl_family = AF_NETLINK;

		if(!get_link(sock,daddr)){
			close(sock);
			return false;
		}

		get_address(sock,daddr);

		close(sock);

		return true;
	}


	rtattr* get_rtattr(rtattr* rta,int attrlen,uint16_t type){
		while(RTA_OK(rta,attrlen)){	
			if((rta->rta_type & NLA_TYPE_MASK) == (type & NLA_TYPE_MASK)){
				return rta;
			}
			rta = RTA_NEXT(rta,attrlen);
		}
		return nullptr;
	}

	bool get_link(int sock,sockaddr_nl& daddr){

		bool result = false;

		char buffer[8092] = {0};

		nlmsghdr* nlh = nullptr;
		nlmsgerr *nle = nullptr;
		ifinfomsg* ifm = nullptr;
		rtattr* rta = nullptr;

		nlh = (nlmsghdr*)buffer;
		nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
		nlh->nlmsg_type = RTM_GETLINK;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
		nlh->nlmsg_seq = 0;
		nlh->nlmsg_pid = getpid();

		ifm = (ifinfomsg*)NLMSG_DATA(nlh);
		ifm->ifi_family = AF_UNSPEC;

		if(sendto(sock,buffer,NLMSG_SPACE(sizeof(ifinfomsg)),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
			fprintf(stderr,"function: %s line: %d sendto: %s\n",__func__,__LINE__,strerror(errno));
			return result;
		}

		bool runner = true;
		
		while(runner){

			int l = recv(sock,buffer,sizeof(buffer),0);
			
			if(l == -1){
				fprintf(stderr,"function: %s line: %d recv: %s\n",__func__,__LINE__,strerror(errno));
				return result;
			}

			for(nlh = (nlmsghdr*)buffer; NLMSG_OK(nlh,l); nlh = NLMSG_NEXT(nlh,l)){

				if(!(nlh->nlmsg_flags & NLM_F_MULTI) || (nlh->nlmsg_type == NLMSG_DONE)){
					runner = false;
				}

				if(nlh->nlmsg_type == NLMSG_ERROR){
					nle = (nlmsgerr*)NLMSG_DATA(nlh);
					fprintf(stderr,"function: %s line: %d error: %s\n",__func__,__LINE__,strerror(-nle->error));
					continue;
				}

				if(nlh->nlmsg_type == RTM_NEWLINK){
					ifm = (ifinfomsg*)NLMSG_DATA(nlh);
					rta = IFLA_RTA(ifm);
					int attrlen = IFLA_PAYLOAD(nlh);

					rtattr* rta_ifname = get_rtattr(rta,attrlen,IFLA_IFNAME);
					rtattr* rta_address = get_rtattr(rta,attrlen,IFLA_ADDRESS);

					if(rta_ifname && rta_ifname->rta_len && !strcmp(name.c_str(),(char*)RTA_DATA(rta_ifname))){
						
						index = ifm->ifi_index;
						
						if(ifm->ifi_type == ARPHRD_ETHER && rta_address && rta_address->rta_len >= sizeof(haddr)){
							memcpy(haddr,RTA_DATA(rta_address),sizeof(haddr));
						}

						result = true;
					}
				}

			}
		}

		return result;
	}

	void get_address(int sock,sockaddr_nl& daddr){
		char buffer[8092] = {0};

		nlmsghdr* nlh = nullptr;
		nlmsgerr* nle = nullptr;
		ifaddrmsg* ifm = nullptr;
		rtattr* rta = nullptr;
		
		nlh = (nlmsghdr*)buffer;
		nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
		nlh->nlmsg_type = RTM_GETADDR;
		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
		nlh->nlmsg_seq = 0;
		nlh->nlmsg_pid = getpid();

		ifm = (ifaddrmsg*)NLMSG_DATA(nlh);
		ifm->ifa_family = AF_UNSPEC;


		if(sendto(sock,buffer,NLMSG_SPACE(sizeof(ifaddrmsg)),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
			fprintf(stderr,"function: %s line: %d sendto: %s\n",__func__,__LINE__,strerror(errno));
			return;
		}

		bool runner = true;

		while(runner){
			int l = recv(sock,buffer,sizeof(buffer),0);

			if(l == -1){
				fprintf(stderr,"function: %s line: %d recv: %s\n",__func__,__LINE__,strerror(errno));
				return;
			}

			for(nlh = (nlmsghdr*)buffer; NLMSG_OK(nlh,l); nlh = NLMSG_NEXT(nlh,l)){

				if(!(nlh->nlmsg_flags & NLM_F_MULTI) || (nlh->nlmsg_type == NLMSG_DONE)){
					runner = false;
				}

				if(nlh->nlmsg_type == NLMSG_ERROR){
					nle = (nlmsgerr*)NLMSG_DATA(nlh);
					fprintf(stderr,"function: %s line: %d error: %s\n",__func__,__LINE__,strerror(-nle->error));
					continue;
				}
				
				if(nlh->nlmsg_type == RTM_NEWADDR){
					ifm = (ifaddrmsg*)NLMSG_DATA(nlh);

					if(ifm->ifa_index != index) continue;

					rtattr* rta_address = get_rtattr(IFA_RTA(ifm),IFA_PAYLOAD(nlh),IFA_ADDRESS);
					
					if(!rta_address) continue;

					if(ifm->ifa_family == AF_INET && rta_address->rta_len >= sizeof(in_addr)){
						memcpy(&in_addr,RTA_DATA(rta_address),sizeof(in_addr));
						in_prefix_length = ifm->ifa_prefixlen;
					}
					else if(ifm->ifa_family == AF_INET6 && rta_address->rta_len >= sizeof(in6_addr)){
						memcpy(&in6_addr,RTA_DATA(rta_address),sizeof(in6_addr));
						in6_prefix_length = ifm->ifa_prefixlen;
					}
				}

			}
		}
	}
};

#define PERCENT_BAR_WIDTH 50

void print_percent_bar(int current,int final);

void clear_stdin();