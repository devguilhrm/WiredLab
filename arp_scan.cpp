#include <Utils.h>
#include <Packet.h>
#include <Filter.h>
#include <CLI.h>

#include <stdarg.h>

#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>

#include <curl/curl.h>
#include <netdb.h>

#define CURL_BUFFER_LENGTH 260

#define MAC_FIND_URL "https://api.macvendors.com"

#define MAX_ATTEMPTS 6
#define THREADS 20

struct HOST{
	uint32_t iaddr;
	uint8_t haddr[MAC_ADDRESS_LENGTH];
};

struct ERROR{
	char s[260];
};

bool resolve_hostname(uint32_t iaddr,char* hostname,size_t hostname_len){
	if(!hostname || !hostname_len) return false;

	sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = iaddr;

	int result = getnameinfo(
		(sockaddr*)&addr,
		sizeof(addr),
		hostname,
		hostname_len,
		nullptr,
		0,
		NI_NAMEREQD
	);

	return result == 0;
}

struct Ctx{
	Interface interface;

	sockaddr_ll daddr;

	uint32_t mask;
	uint32_t subnetwork;
	uint32_t max_hosts;

	std::vector<std::thread> threads;
	std::atomic<int> thread_count;

	std::queue<ERROR> errors;
	std::mutex errors_mutex;

	std::vector<HOST> hosts;
	std::mutex hosts_mutex;

	std::atomic<uint32_t> host_count;
	std::mutex host_count_mutex;

	uint32_t read_host_count(){
		host_count_mutex.lock();
		uint32_t count = host_count.load(std::memory_order_relaxed);
		if(count < max_hosts) host_count.fetch_add(1,std::memory_order_relaxed);
		host_count_mutex.unlock();
		return count;
	}

	void push_error(const char* format,...){
		ERROR error;

		va_list arg;
		va_start(arg,format);
		vsnprintf(error.s,sizeof(error.s),format,arg);

		errors_mutex.lock();
		errors.push(error);
		errors_mutex.unlock();
	}

	void pop_error(){
		errors_mutex.lock();
		
		fprintf(stdout,"\r\033[2k");
		
		while(errors.size() > 0){
			ERROR& error = errors.front();
			
			fprintf(stdout,"%s\n",error.s);

			errors.pop();
		}

		errors_mutex.unlock();
	}

	int load_sock(int id){

		int sock = socket(AF_PACKET,SOCK_DGRAM,htons(ETHERNET_ARP));
		if(sock == -1){
			push_error("thread: %d function: %s line: %d socket: %s",id,__func__,__LINE__,strerror(errno));
			return -1;
		}

		sockaddr_ll saddr = {0};
		saddr.sll_family = AF_PACKET;
		saddr.sll_ifindex = interface.index;
		if(bind(sock,(sockaddr*)&saddr,sizeof(saddr)) == -1){
			push_error("thread: %d function: %s line: %d bind: %s",id,__func__,__LINE__,strerror(errno));
			close(sock);
			return -1;
		}

		timeval tv;
		tv.tv_sec = 1e+0;
		tv.tv_usec = 5e+5;
		if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv)) == -1){
			push_error("thread: %d function: %s line: %d setsockopt: %s",id,__func__,__LINE__,strerror(errno));
			close(sock);
			return -1;
		}

		sock_filter filter[] = {
			//hardware type == ethernet
			{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_HARDWARE_TYPE_OFFSET},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,15,HARDWARE_ETHERNET},
			
			//protocol type == ipv4
			{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_PROTOCOL_TYPE_OFFSET},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,13,ETHERNET_IPV4},
			
			//hardware length == mac address length
			{BPF_LD  | BPF_B   | BPF_ABS,0,0,ARP_HARDWARE_LENGTH_OFFSET},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,11,MAC_ADDRESS_LENGTH},
			
			//protocol length == ipv4 address length
			{BPF_LD  | BPF_B   | BPF_ABS,0,0,ARP_PROTOCOL_LENGTH_OFFSET},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,9,IPV4_ADDRESS_LENGTH},

			//operation == arp reply
			{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_OPERATION_OFFSET},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,7,ARP_REPLY},

			//target hardware address == interface.haddr
			{BPF_LD  | BPF_H   | BPF_ABS,0,0,ARP_TARGET_HADDR_OFFSET + 0},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,5,READH(interface.haddr + 0)},
			{BPF_LD  | BPF_W   | BPF_ABS,0,0,ARP_TARGET_HADDR_OFFSET + 2},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,3,READW(interface.haddr + 2)},

			//target ip address == interface.in_addr
			{BPF_LD  | BPF_W   | BPF_ABS,0,0,ARP_TARGET_IP_ADDRESS},
			{BPF_JMP | BPF_JEQ | BPF_IMM,0,1,ntohl(interface.in_addr)},

			{BPF_RET | BPF_IMM,0,0,(uint32_t)-1},
			{BPF_RET | BPF_IMM,0,0,0}
		};

		sock_fprog fprog = {sizeof(filter) / sizeof(filter[0]),filter};

		if(setsockopt(sock,SOL_SOCKET,SO_ATTACH_FILTER,&fprog,sizeof(fprog)) == -1){
			printf("thread: %d function: %s line: %d setsockopt: %s",id,__func__,__LINE__,strerror(errno));
			close(sock);
			return -1;
		}

		return sock;
	}

	void thread(int id){
		ARP s_arp;
		ARP r_arp;

		int sock = load_sock(id);
		if(sock == -1){
			thread_count.fetch_sub(1,std::memory_order_relaxed);
			return;
		}

		while(true){
			uint32_t index = read_host_count();

			if(index >= max_hosts) break;

			uint32_t tiaddr = htonl(subnetwork | index);

			s_arp.write_hdr(ARP_REQUEST,interface.haddr,interface.in_addr,nullptr,tiaddr);

			for(int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt){

				if(sendto(sock,s_arp.data(),s_arp.length(),0,(sockaddr*)&daddr,sizeof(daddr)) == -1){
					push_error("thread: %d function: %s line: %d sendto: %s",id,__func__,__LINE__,strerror(errno));
					continue;
				}

				while(true){

					int l = recv(sock,r_arp.data(),r_arp.capacity(),0);
					
					if(l == -1) break;

					r_arp.set_length(l);
					
					ARP::HDR arp_hdr = r_arp.read_hdr();

					if(arp_hdr.siaddr == tiaddr){
						hosts_mutex.lock();

						HOST& host = hosts.emplace_back();

						host.iaddr = tiaddr;
						memcpy(host.haddr,arp_hdr.shaddr,sizeof(host.haddr));

						hosts_mutex.unlock();

						attempt = MAX_ATTEMPTS;
						break;
					}
				}
			}	
		}

		close(sock);

		thread_count.fetch_sub(1,std::memory_order_relaxed);
	}
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

	Ctx ctx;
	bool resolve_hostnames = !cli_has_arg(n_args,args,"--no-hostnames");

	if(!cli_read_interface(ctx.interface,n_args,args,"--interface","Interface Name: ")){
		return 1;
	}

	printf("\nInterface: %s ",ctx.interface.name.c_str());
	printf("IP: %s/%d ",sprint_ipv4(&ctx.interface.in_addr),ctx.interface.in_prefix_length);
	printf("MAC: %s\n\n",sprint_mac(&ctx.interface.haddr));

	ctx.daddr.sll_family = AF_PACKET;
	ctx.daddr.sll_protocol = htons(ETHERNET_ARP);
	ctx.daddr.sll_ifindex = ctx.interface.index;
	ctx.daddr.sll_hatype = 0;
	ctx.daddr.sll_pkttype = 0;
	ctx.daddr.sll_halen = MAC_ADDRESS_LENGTH;
	memset(ctx.daddr.sll_addr,0xff,ctx.daddr.sll_halen);

	ctx.mask = ctx.interface.in_prefix_length ? ((0x01 << ctx.interface.in_prefix_length) - 0x01) : 0;
	ctx.subnetwork = ntohl(ctx.interface.in_addr & ctx.mask);
	ctx.max_hosts = ctx.mask ? ntohl(~ctx.mask) + 0x01 : 0;

	ctx.host_count = 0;
	ctx.thread_count = 0;

	for(int i = 0; i < THREADS; ++i){
		ctx.thread_count.fetch_add(1,std::memory_order_relaxed);
		ctx.threads.emplace_back(&Ctx::thread,&ctx,i);
	}

	while(true){
		ctx.pop_error();

		uint32_t host_count = ctx.host_count.load(std::memory_order_relaxed);
		int thread_count = ctx.thread_count.load(std::memory_order_relaxed);

		fprintf(stdout,"\r\033[2KHosts %lu/%lu Threads %d/%d",host_count,ctx.max_hosts,thread_count,THREADS);
		fflush(stdout);

		if(host_count >= ctx.max_hosts || thread_count <= 0){
			fprintf(stdout,"\r\033[2k");
			break;
		}

		usleep(2e+5);
	}

	for(auto& thread : ctx.threads){
		if(thread.joinable()){
			thread.join();
		}
	}

	if(ctx.hosts.size()){

		char curl_buffer[CURL_BUFFER_LENGTH] = {0};

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

		for(HOST& host : ctx.hosts){
			printf("IP: %s ",sprint_ipv4(&host.iaddr));
			printf("MAC: %s ",sprint_mac(&host.haddr));

			char hostname[NI_MAXHOST] = {0};
			if(resolve_hostnames && resolve_hostname(host.iaddr,hostname,sizeof(hostname))){
				printf("Hostname: %s ",hostname);
			}

			snprintf(curl_buffer,sizeof(curl_buffer),"%s/%s",MAC_FIND_URL,sprint_mac(&host.haddr));

			curl_easy_setopt(handle,CURLOPT_URL,curl_buffer);

			if(curl_easy_perform(handle) == CURLE_OK && strcmp(curl_buffer,"{\"errors\":{\"detail\":\"Not Found\"}}")){
				printf("Vendor: %s",curl_buffer);
			}

			printf("\n");

			sleep(1);
		}

		curl_easy_cleanup(handle);
		curl_global_cleanup();
	}

	return 0;
}
