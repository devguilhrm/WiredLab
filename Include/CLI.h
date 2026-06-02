#pragma once

#include <Utils.h>
#include <Packet.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

inline const char* cli_get_arg(int n_args,char** args,const char* name){
	if(!args || !name) return nullptr;

	size_t name_len = strlen(name);
	for(int i = 1; i < n_args; ++i){
		if(!strcmp(args[i],name) && i + 1 < n_args){
			return args[i + 1];
		}
		if(!strncmp(args[i],name,name_len) && args[i][name_len] == '='){
			return args[i] + name_len + 1;
		}
	}

	return nullptr;
}

inline bool cli_has_arg(int n_args,char** args,const char* name){
	if(!args || !name) return false;

	for(int i = 1; i < n_args; ++i){
		if(!strcmp(args[i],name)) return true;
	}

	return false;
}

inline bool cli_parse_mac(const char* value,uint8_t* haddr){
	if(!value || !haddr) return false;

	unsigned int b[MAC_ADDRESS_LENGTH] = {0};
	int n = sscanf(
		value,
		"%02x-%02x-%02x-%02x-%02x-%02x",
		&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]
	);

	if(n != MAC_ADDRESS_LENGTH){
		n = sscanf(
			value,
			"%02x:%02x:%02x:%02x:%02x:%02x",
			&b[0],&b[1],&b[2],&b[3],&b[4],&b[5]
		);
	}

	if(n != MAC_ADDRESS_LENGTH) return false;

	for(int i = 0; i < MAC_ADDRESS_LENGTH; ++i){
		if(b[i] > 0xff) return false;
		haddr[i] = (uint8_t)b[i];
	}

	return true;
}

inline bool cli_read_interface(Interface& interface,int n_args,char** args,const char* option,const char* prompt){
	char buffer[260] = {0};
	const char* value = cli_get_arg(n_args,args,option);

	if(value){
		if(interface.init(value)) return true;
		printf("Invalid Interface Name: %s\n",value);
		return false;
	}

	while(true){
		printf("%s",prompt);
		scanf("%259s",buffer);
		clear_stdin();

		if(!interface.init(buffer)){
			printf("Invalid Interface Name\n");
			continue;
		}

		return true;
	}
}

inline bool cli_read_ipv4(uint32_t* iaddr,int n_args,char** args,const char* option,const char* prompt){
	char buffer[260] = {0};
	const char* value = cli_get_arg(n_args,args,option);

	if(value){
		if(inet_pton(AF_INET,value,iaddr) == 1) return true;
		printf("Invalid IPv4 Address: %s\n",value);
		return false;
	}

	while(true){
		printf("%s",prompt);
		scanf("%259s",buffer);
		clear_stdin();

		if(inet_pton(AF_INET,buffer,iaddr) != 1){
			printf("Invalid Address\n");
			continue;
		}

		return true;
	}
}

inline bool cli_read_ipv6(uint8_t* iaddr,int n_args,char** args,const char* option,const char* prompt){
	char buffer[260] = {0};
	const char* value = cli_get_arg(n_args,args,option);

	if(value){
		if(inet_pton(AF_INET6,value,iaddr) == 1) return true;
		printf("Invalid IPv6 Address: %s\n",value);
		return false;
	}

	while(true){
		printf("%s",prompt);
		scanf("%259s",buffer);
		clear_stdin();

		if(inet_pton(AF_INET6,buffer,iaddr) != 1){
			printf("Invalid Address\n");
			continue;
		}

		return true;
	}
}

inline bool cli_read_mac(uint8_t* haddr,int n_args,char** args,const char* option,const char* prompt){
	char buffer[260] = {0};
	const char* value = cli_get_arg(n_args,args,option);

	if(value){
		if(cli_parse_mac(value,haddr)) return true;
		printf("Invalid MAC Address: %s\n",value);
		return false;
	}

	while(true){
		printf("%s",prompt);
		scanf("%259s",buffer);
		clear_stdin();

		if(!cli_parse_mac(buffer,haddr)){
			printf("Address Invalid\n");
			continue;
		}

		return true;
	}
}
