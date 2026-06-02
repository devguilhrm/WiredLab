#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>

#define BUFFER_MAX_LENGTH 2048

struct PACKET;
struct ETHERNET;
struct IPV4;
struct IPV6;
struct TCP;
struct UDP;

const char* sprint_mac(const void* data);

const char* sprint_ipv4(const void* data);

const char* sprint_ipv6(const void* data);

const char* sprint_string(const uint8_t* data,size_t len);

const char* sprint_ip_protocol(uint8_t protocol);

const char* sprint_hardware_type(uint16_t htype);

const char* sprint_uuid(const void* data);

uint16_t network_checksum(PACKET *pheader,PACKET *packet);


#define ETHERNET_HDR_LENGTH 14
#define UDP_HDR_LENGTH 8
#define IPV6_HDR_LENGTH 40

#define UUID_LENGTH 16

#define MAC_ADDRESS_LENGTH 6
#define IPV4_ADDRESS_LENGTH 4
#define IPV6_ADDRESS_LENGTH 16

#define DNS_LABEL_MASK_LENGTH 0x3F
#define DNS_MAX_NAME_LENGTH 0xFF
#define DNS_MAX_PTR_DEPTH 0x7F

struct PACKET {
private:
	uint8_t _data[BUFFER_MAX_LENGTH];
	size_t _rpos;
	size_t _len;
public:
	PACKET():_data{0},_rpos(0),_len(0){}

	void update_rpos(){
		_rpos = (_rpos > _len) ? _len : _rpos;
	}

	void set_rpos(size_t rpos) {
		if (rpos >= _len) return;
		_rpos = rpos;
	}

	void advance_rpos(size_t len) {
		if (_rpos + len > _len) return;
		_rpos += len;
	}

	size_t rpos() const {
		return _rpos;
	}


	uint8_t* data() {
		return _data;
	}

	void set_length(size_t len) {
		if (len > sizeof(_data)) return;
		_len = len;
		update_rpos();
	}

	size_t length() const {
		return _len;
	}

	size_t capacity() const{
		return sizeof(_data);
	}


	PACKET& operator+=(const PACKET& src){
		write(src._data, src._len);
		return *this;
	}


	void set(uint8_t value,size_t len) {
		if (_len + len > sizeof(_data)) return;
		memset(_data + _len, value, len);
		_len += len;
	}

	void write(const void* value,size_t len,size_t pos = (size_t)-1) {
		if (pos < (size_t)-1){
			if (pos + len > _len) return;
			memcpy(_data + pos,value,len);
		}
		else {
			if (_len + len > sizeof(_data)) return;
			memcpy(_data + _len,value,len);
			_len += len;
		}
	}

	void read(void* value,size_t len,size_t pos = (size_t)-1){
		if(pos < (size_t)-1){
			if(pos + len > _len) return;
			memcpy(value,_data + pos,len);
		}
		else{
			if (_rpos + len > _len) return;
			memcpy(value,_data + _rpos,len);
			_rpos += len;
		}
	}

	void peek(void* value,size_t len,int pos) {
		if (pos + len > _len) return;
		memcpy(value, _data + pos, len);
	}


	void write_32(uint32_t value,int pos = -1) {
		write(&value,sizeof(value),pos);
	}

	uint32_t read_32() {
		uint32_t value = 0;
		read(&value,sizeof(value));
		return value;
	}

	uint32_t peek_32(size_t pos) {
		uint32_t value = 0;
		peek(&value,sizeof(value),pos);
		return value;
	}


	void write_16(uint16_t value, int pos = -1) {
		write(&value,sizeof(value),pos);
	}

	uint16_t read_16() {
		uint16_t value = 0;
		read(&value,sizeof(value));
		return value;
	}

	uint16_t peek_16(size_t pos) {
		uint16_t value = 0;
		peek(&value,sizeof(value),pos);
		return value;
	}


	void write_8(uint8_t value,size_t pos = (size_t)-1) {
		if (pos < (size_t)-1) {
			if (pos >= _len) return;
			_data[pos] = value;
		}
		else {
			if (_len >= sizeof(_data)) return;
			_data[_len++] = value;
		}
	}

	uint8_t read_8(size_t *pos = nullptr) {
		if(pos){
			if(*pos >= _len) return 0x00;
			return _data[*pos++];
		}
		else{
			if (_rpos >= _len) return 0x00;
			return _data[_rpos++];
		}
	}

	uint8_t peek_8(size_t pos) {
		if (pos >= _len) return 0x00;
		return _data[pos];
	};


	void write_domain_name(const char* s,uint16_t ptr_offset = (uint16_t)-1);

	const char* read_domain_name(uint16_t offset = 0,size_t pos = (size_t)-1);

	const char* read_string_ipv4(size_t pos = (size_t)-1){
		if(pos < (size_t)-1){
			if(pos + IPV4_ADDRESS_LENGTH > _len) return "\0";
			return sprint_ipv4(_data + pos);
		}
		else{
			if (_rpos + IPV4_ADDRESS_LENGTH > _len) return "\0";
			const char* r = sprint_ipv4(_data + _rpos);
			_rpos += IPV4_ADDRESS_LENGTH;
			return r;
		}
	}

	const char* read_string_ipv6(size_t pos = (size_t)-1){
		if(pos < (size_t)-1){
			if(pos + IPV6_ADDRESS_LENGTH > _len) return "\0";
			return sprint_ipv6(_data + pos);
		}
		else{
			if(_rpos + IPV6_ADDRESS_LENGTH > _len) return "\0";
			const char* r = sprint_ipv6(_data + _rpos);
			_rpos += IPV6_ADDRESS_LENGTH;
			return r;
		}
	}

	const char* read_string_mac(size_t pos = (size_t)-1) {
		if(pos < (size_t)-1){
			if(pos + MAC_ADDRESS_LENGTH > _len) return "\0";
			return sprint_mac(_data + pos);
		}
		else{
			if (_rpos + MAC_ADDRESS_LENGTH > _len) return "\0";
			const char* r = sprint_mac(_data + _rpos);
			_rpos += MAC_ADDRESS_LENGTH;
			return r;
		}
	}

	const char* read_string_uuid(size_t pos = (size_t)-1){
		if(pos < (size_t)-1){
			if(pos + UUID_LENGTH > _len) return "\0";
			return sprint_uuid(_data + pos);
		}
		else{
			if(_rpos + UUID_LENGTH > _len) return "\0";
			const char* r = sprint_uuid(_data + _rpos);
			_rpos += UUID_LENGTH;
			return r;
		}
	}

	const char* read_string(size_t len,size_t pos = (size_t)-1){
		if(pos < (size_t)-1){
			if(pos + len > _len) return "\0";
			return sprint_string(_data + pos,len);
		}
		else{
			if(_rpos + len > _len) return "\0";
			const char *r = sprint_string(_data + _rpos,len);
			_rpos += len;
			return r;
		}
	}


	ETHERNET unpack_ethernet();
	void unpack_ethernet_void();

	IPV4 unpack_ipv4();
	void unpack_ipv4_void();

	IPV6 unpack_ipv6();
	void unpack_ipv6_void();

	TCP unpack_tcp();
	void unpack_tcp_void();

	UDP unpack_udp();
	void unpack_udp_void();

	template<typename T> T unpack(){
		T packet;
		packet.write(_data,_len);
		_len = 0;
		_rpos = 0;
		return packet;
	}
};


#define HARDWARE_MAX_ADDRESS_LENGTH 16

#define HARDWARE_ETHERNET 1
#define HARDWARE_EXPERIMENTAL_ETHERNET 2
#define HARDWARE_AMATEUR_RADIO_AX25 3
#define HARDWARE_PROTEON_PRONET_TOKEN_RING 4
#define HARDWARE_CHAOS 5
#define HARDWARE_IEEE_802_NETWORKS 6
#define HARDWARE_ARCNET 7
#define HARDWARE_HYPERCHANNEL 8
#define HARDWARE_LANSTAR 9
#define HARDWARE_AUTONET_SHORT_ADDRESS 10
#define HARDWARE_LOCALTALK 11
#define HARDWARE_LOCALNET 12
#define HARDWARE_ULTRA_LINK 13
#define HARDWARE_SMDS 14
#define HARDWARE_FRAME_RELAY 15
#define HARDWARE_ATM1 16
#define HARDWARE_HDLC 17
#define HARDWARE_FIBRE_CHANNEL 18
#define HARDWARE_ATM2 19
#define HARDWARE_SERIAL_LINE 20
#define HARDWARE_ATM3 21
#define HARDWARE_MIL_STD_188_220 22
#define HARDWARE_METRICOM 23
#define HARDWARE_IEEE_1394_1995 24
#define HARDWARE_MAPOS 25
#define HARDWARE_TWINAXIAL 26
#define HARDWARE_EUI64 27
#define HARDWARE_HIPARP 28
#define HARDWARE_IP_AND_ARP 29
#define HARDWARE_ARPSEC 30
#define HARDWARE_IPSEC_TUNNEL 31
#define HARDWARE_INFINIBAND 32
#define HARDWARE_CAI 33
#define HARDWARE_WIEGAND_INTERFACE 34
#define HARDWARE_PURE_IP 35
#define HARDWARE_HW_EXP1 36
#define HARDWARE_HFI 37
#define HARDWARE_UNIFIED_BUS 38
#define HARDWARE_HW_EXP2 256
#define HARDWARE_AETHERNET 257


#define ETHERNET_IPV4 0x0800
#define ETHERNET_ARP 0x0806
#define ETHERNET_IPV6 0x86DD

struct ETHERNET : PACKET {

	struct HDR {
		uint8_t dhaddr[MAC_ADDRESS_LENGTH];
		uint8_t shaddr[MAC_ADDRESS_LENGTH];
		uint16_t type;
	};

	void write_hdr(uint8_t* shaddr, uint8_t* dhaddr, uint16_t type){
		set_length(0);
		write(dhaddr,MAC_ADDRESS_LENGTH);
		write(shaddr,MAC_ADDRESS_LENGTH);
		write_16(htons(type));
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		read(hdr.dhaddr,sizeof(hdr.dhaddr));
		read(hdr.shaddr,sizeof(hdr.shaddr));
		hdr.type = ntohs(read_16());
		return hdr;
	}

	void print(){
		HDR hdr = read_hdr();
		printf("\n-------- Ethernet --------\n");
		printf("Destination: %s\n",sprint_mac(hdr.dhaddr));
		printf("Source: %s\n",sprint_mac(hdr.shaddr));
		printf("Type: ");
		switch(hdr.type){
			case ETHERNET_IPV4: printf("IPv4 "); break;
			case ETHERNET_ARP: printf("ARP "); break;
			case ETHERNET_IPV6: printf("IPv6 "); break;
			default: printf("Unknown "); break;
		}
		printf("(0x%.4X)\n",hdr.type);
	}
};


#define ARP_REQUEST 1
#define ARP_REPLY 2

struct ARP : PACKET {

	struct HDR {
		uint16_t htype;
		uint16_t ptype;
		uint8_t hlen;
		uint8_t plen;
		uint16_t op;
		uint8_t shaddr[6];
		uint32_t siaddr;
		uint8_t thaddr[6];
		uint32_t tiaddr;
	};

	void write_hdr(uint16_t type,uint8_t* shaddr,uint32_t siaddr,uint8_t* thaddr,uint32_t tiaddr){
		set_length(0);
		write_16(htons(HARDWARE_ETHERNET)); //hardware type
		write_16(htons(ETHERNET_IPV4)); //protocol type
		write_8(MAC_ADDRESS_LENGTH); //hardware length
		write_8(IPV4_ADDRESS_LENGTH); //protocol length
		write_16(htons(type)); //operation type
		write(shaddr,MAC_ADDRESS_LENGTH); //sender hardware address
		write_32(siaddr); //sender ip address
		if(thaddr) write(thaddr,MAC_ADDRESS_LENGTH); //target hardware address
		else       set(0,MAC_ADDRESS_LENGTH);
		write_32(tiaddr); //target ip address
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		hdr.htype = ntohs(read_16());
		hdr.ptype = ntohs(read_16());
		hdr.hlen = read_8();
		hdr.plen = read_8();
		hdr.op = ntohs(read_16());
		read(hdr.shaddr,MAC_ADDRESS_LENGTH);
		hdr.siaddr = read_32();
		read(hdr.thaddr,MAC_ADDRESS_LENGTH);
		hdr.tiaddr = read_32();
		return hdr;
	}

	void print(){
		HDR hdr = read_hdr();
		printf("\n-------- ARP --------\n");
		printf("Hardware Type: %s (%d)\n",sprint_hardware_type(hdr.htype),hdr.htype);

		printf("Protocol Type: ");
		switch(hdr.ptype){
			case ETHERNET_IPV4: printf("IPv4 "); break;
			default: printf("Unknown "); break;
		}
		printf("(0x%.4X)\n",hdr.ptype);
		
		printf("Hardware Length: %d\n",hdr.hlen);

		printf("Protocol Length: %d\n",hdr.plen);

		printf("Operation Type: ");
		switch(hdr.op){
			case ARP_REQUEST: printf("Request "); break;
			case ARP_REPLY: printf("Reply "); break;
			default: printf("Unknown "); break;
		}
		printf("(%d)\n",hdr.op);

		printf("Sender Hardware Address: %s\n",sprint_mac(hdr.shaddr));
		printf("Sender IP Address: %s\n",sprint_ipv4(&hdr.siaddr));

		printf("Target Hardware Address: %s\n",sprint_mac(hdr.thaddr));
		printf("Target IP Address: %s\n",sprint_ipv4(&hdr.tiaddr));
	}
};


#define IPPROTOCOL_ICMP 1
#define IPPROTOCOL_TCP 6
#define IPPROTOCOL_UDP 17
#define IPPROTOCOL_ICMPV6 58

#define DONT_FRAGMENT_FLAG 0x02
#define MORE_FRAGMENTS_FLAG 0x04

struct IPV4 : PACKET {
	
	struct HDR {
		uint8_t version : 4;
		uint8_t hdr_len : 4;
		uint8_t tos;
		uint16_t total_len;
		uint16_t identifier;
		uint8_t flags : 3;
		uint16_t foffset : 13;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t hdr_checksum;
		uint32_t saddr;
		uint32_t daddr;
	};


	void write_hdr(uint16_t id,bool dont_fragment,uint8_t ttl,uint8_t protocol,uint32_t saddr,uint32_t daddr,int plen){
		set_length(0);

		uint8_t flags = dont_fragment ? DONT_FRAGMENT_FLAG : 0;

		write_8(0); //version + header length
		write_8(0); //type of service
		write_16(0); //total length
		write_16(htons(id)); //identifier
		write_16(htons(((flags & 0x07) << 0x0D) | 0x00)); //flags + fragment offset
		write_8(ttl); //time to live
		write_8(protocol); //protocol
		write_16(0); //checksum
		write_32(saddr);
		write_32(daddr);

		write_8(0x40 | ((length() >> 0x02) & 0x0F),0);
		write_16(htons(length() + plen),2);
		write_16(htons(network_checksum(nullptr,this)),10);
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		uint8_t byte = read_8();
		hdr.version = byte >> 0x04;
		hdr.hdr_len = byte & 0x0F;
		hdr.tos = read_8();
		hdr.total_len = ntohs(read_16());
		hdr.identifier = ntohs(read_16());
		uint16_t word = ntohs(read_16());
		hdr.flags = word >> 0x0D;
		hdr.foffset = word & 0x1FFF;
		hdr.ttl = read_8();
		hdr.protocol = read_8();
		hdr.hdr_checksum = ntohs(read_16());
		hdr.saddr = read_32();
		hdr.daddr = read_32();
		set_rpos(0);
		return hdr;
	}


	void print(){
		printf("\n-------- IPv4 --------\n");
		HDR hdr = read_hdr();
		printf("Version: %d\n",hdr.version);
		printf("Headr Length: %d bytes (%d)\n",hdr.hdr_len << 0x02,hdr.hdr_len);
		printf("Type of Service: 0x%.2X\n",hdr.tos);
		printf("Total Length: %d\n",hdr.total_len);
		printf("Identifier: 0x%.2X (%d)\n",hdr.identifier,hdr.identifier);
		printf("Flags: Don't Fragment(%d) More Fragments(%d)\n",(hdr.flags & DONT_FRAGMENT_FLAG) ? 1 : 0,(hdr.flags & MORE_FRAGMENTS_FLAG) ? 1 : 0);
		printf("Fragment Offset: %d\n",hdr.foffset);
		printf("Time To Live: %d\n",hdr.ttl);
		printf("Protocol: %s (%d)\n",sprint_ip_protocol(hdr.protocol),hdr.protocol);
		printf("Header Checksum: 0x%.2X\n",hdr.hdr_checksum);
		printf("Source Address: %s\n",sprint_ipv4(&hdr.saddr));
		printf("Destination Address: %s\n",sprint_ipv4(&hdr.daddr));
	}
};


struct IPV6 : PACKET {
	
	struct HDR {
		uint8_t version : 4;
		uint8_t traffic_class;
		uint32_t flow_label : 20;
		uint16_t payload_length;
		uint8_t next_header;
		uint8_t hop_limit;
		uint8_t saddr[IPV6_ADDRESS_LENGTH];
		uint8_t daddr[IPV6_ADDRESS_LENGTH];
	};

	void write_hdr(uint16_t payload_length,uint8_t next_header, uint8_t hop_limit, uint8_t* saddr, uint8_t* daddr){
		set_length(0);

		uint8_t version = 6;
		uint8_t traffic_class = 0;
		uint32_t flow_label = 0;
		uint32_t word = ((version & 0xF) << 0x1C) | ((traffic_class & 0xFF) << 0x14) | ((flow_label & 0xFFFFF) << 0x00);

		write_32(htonl(word)); //version + traffic_class + flow_label
		write_16(htons(payload_length)); //payload length
		write_8(next_header); //next header
		write_8(hop_limit); //hop_limit
		write(saddr,IPV6_ADDRESS_LENGTH);
		write(daddr,IPV6_ADDRESS_LENGTH);
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		uint32_t word = ntohl(read_32());
		hdr.version = (word & 0xF0000000) >> 0x1C;
		hdr.traffic_class = (word & 0x0FF00000) >> 0x14;
		hdr.flow_label = (word & 0x000FFFFF) >> 0x00;
		hdr.payload_length = htons(read_16());
		hdr.next_header = read_8();
		hdr.hop_limit = read_8();
		read(hdr.saddr,sizeof(hdr.saddr));
		read(hdr.daddr,sizeof(hdr.daddr));
		return hdr;
	}

	void print(){
		HDR hdr = read_hdr();
		printf("\n-------- IPv6 --------\n");
		printf("Version: %d\n",hdr.version);
		printf("Traffic Class: 0x%02x\n",hdr.traffic_class);
		printf("Flow Label: 0x%05x\n",hdr.flow_label);
		printf("Payload Length: %d\n",hdr.payload_length);
		printf("Next Header: %s (%d)\n",sprint_ip_protocol(hdr.next_header),hdr.next_header);
		printf("Hop Limit: %d\n",hdr.hop_limit);
		printf("Source Address: %s\n",sprint_ipv6(hdr.saddr));
		printf("Destination Address: %s\n",sprint_ipv6(hdr.daddr));
	}
};


#define MANAGED_ADDRESS_CONFIGURATION_FLAG 0x80
#define OTHER_CONFIGURATION_FLAG 0x40
#define HOME_AGENT_FLAG 0x20
#define PREFERENCE_LOW_FLAG 0x18
#define PREFERENCE_HIGH_FLAG 0x08
#define PREFERENCE_MEDIUM_FLAG 0x00
#define PROXY_FLAG 0x04

#define ONLINK_FLAG 0x80
#define AUTONOMOS_ADDRESS_CONFIGURATION_FLAG 0x40



struct ICMPV6 : PACKET {
private:
	void echo(uint8_t type,uint16_t id,uint16_t seq_number,const void *data,int len){
		write_8(type); //type
		write_8(0); //code
		write_16(0); //checksum
		write_16(htons(id)); //identifier
		write_16(htons(seq_number)); //sequence number
		if(data != nullptr && len > 0){
			write(data,len); //data
		}
	}

public:
    enum TYPE {
		ECHO_REQUEST = 128,
		ECHO_REPLY = 129,
		ROUTER_SOLICITATION = 133,
		ROUTER_ADVERTISEMENT = 134,
		NEIGHBOR_SOLICITATION = 135,
		NEIGHBOR_ADVERTISEMENT = 136
	};

	enum NDP_OPTION_TYPE {
		SOURCE_LINKLAYER_ADDRESS = 1,
		TARGET_LINKLAYER_ADDRESS = 2,
		PREFIX_INFORMATION = 3,
		REDIRECT_HEADER = 4,
		MTU = 5,
	};

	struct NDP_OPTION {
		uint8_t type;
		uint8_t length;
	};

	NDP_OPTION* peek_ndp_option(){
		return (NDP_OPTION*)(data() + rpos());
	}

	size_t ndp_option_data_offset(){
		return rpos() + 2;
	}

	bool ndp_option_ok(const NDP_OPTION* option) const {
		if(!option->type || option->type > 5){
			return false;
		}

		int len = option->length << 0x03;
		int remaining_len = length() - rpos();

		if(!option->length || len > remaining_len){
			return false;
		}

		return true;
	}
	
	NDP_OPTION* advance_ndp_option(NDP_OPTION* option){
		advance_rpos(option->length << 0x03);
		return peek_ndp_option();
	}


	struct ECHO_HDR {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint16_t id;
		uint16_t seq_number;
		const uint8_t* data;
		uint16_t data_len;
	};

	ECHO_HDR read_echo_hdr(){
		set_rpos(0);
		ECHO_HDR hdr = {0};
		hdr.type = read_8();
		hdr.code = read_8();
		hdr.checksum = ntohs(read_16());
		hdr.id = ntohs(read_16());
		hdr.seq_number = ntohs(read_16());
		hdr.data = data() + rpos();
		hdr.data_len = length() - rpos();
		return hdr;
	}

	struct NS_HDR {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint32_t reserved;
		uint8_t taddr[IPV6_ADDRESS_LENGTH];
	};

	NS_HDR read_ns_hdr(){
		set_rpos(0);
		NS_HDR hdr = {0};
		hdr.type = read_8();
		hdr.code = read_8();
		hdr.checksum = ntohs(read_16());
		hdr.reserved = ntohl(read_32());
		read(hdr.taddr,sizeof(hdr.taddr));
		return hdr;
	}

	enum NA_FLAG {
		OVERRIDE_FLAG = 0x01,
		SOLICITED_FLAG = 0x02,
		ROUTER_FLAG = 0x03
	};

	struct NA_HDR {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint8_t flags : 3;
		uint32_t reserved : 29;
		uint8_t taddr[IPV6_ADDRESS_LENGTH];
	};

	NA_HDR read_na_hdr(){
		set_rpos(0);
		NA_HDR hdr = {0};
		hdr.type = read_8();
		hdr.code = read_8();
		hdr.checksum = ntohs(read_16());
		uint32_t word = ntohl(read_32());
		hdr.flags = word & 0xE0000000;
		hdr.reserved = word & 0x1FFFFFFF;
		read(hdr.taddr,sizeof(hdr.taddr));
		return hdr;
	}


	uint8_t type(){
		return peek_8(0);
	}

	void checksum(const void* siaddr,const void* diaddr){
		PACKET ph;
		ph.write(siaddr,IPV6_ADDRESS_LENGTH); //source address
		ph.write(diaddr,IPV6_ADDRESS_LENGTH); //destination address
		ph.write_32(htonl(length())); //icmpv6 length
		ph.set(0,3); //reserved
		ph.write_8(IPPROTOCOL_ICMPV6); //next header

		write_16(htons(network_checksum(&ph, this)), 2);
	}


	void echo_request(const void* siaddr,const void* diaddr,uint16_t id,uint16_t seq_number,const void *data = nullptr,int len = 0){
		echo(ECHO_REQUEST,id,seq_number,data,len);
		checksum(siaddr,diaddr);
	}

	void echo_reply(const void* siaddr,const void* diaddr,uint16_t id,uint16_t seq_number,const void *data = nullptr,int len = 0){
		echo(ECHO_REPLY,id,seq_number,data,len);
		checksum(siaddr,diaddr);
	}


	void write_router_solicitation(const void* siaddr,const void* diaddr,const void* shaddr){
		write_8(ROUTER_SOLICITATION); //type
		write_8(0); //code
		write_16(0); //checksum
		write_32(0); //reserved

		write_8(SOURCE_LINKLAYER_ADDRESS); //type
		write_8(1); //length
		write(shaddr,MAC_ADDRESS_LENGTH); //source link-layer address
		
		checksum(siaddr,diaddr);
	}

	void write_router_advertisement(const void* siaddr,const void* diaddr,const void* prefix,const void* shaddr) {
		set_length(0);

		write_8(ROUTER_ADVERTISEMENT); //type
		write_8(0); //code
		write_16(0); //checksum
		write_8(64); //cur hop limit
		write_8(OTHER_CONFIGURATION_FLAG | PREFERENCE_LOW_FLAG); //flags
		write_16(htons(30)); //router lifetime
		write_32(0); //reachable time
		write_32(0); //retrans timer

		write_8(PREFIX_INFORMATION); //type
		write_8(4); //length
		write_8(64); //prefix length
		write_8(ONLINK_FLAG | AUTONOMOS_ADDRESS_CONFIGURATION_FLAG); //flags
		write_32(htonl(300)); //valid lifetime
		write_32(htonl(120)); //preferred lifetime
		write_32(0); //reserved
		write(prefix,IPV6_ADDRESS_LENGTH); //prefix

		write_8(SOURCE_LINKLAYER_ADDRESS); //type
		write_8(1); //length
		write(shaddr,MAC_ADDRESS_LENGTH); //source link-layer address

		checksum(siaddr,diaddr);
	}

	void write_neighbor_solicitation(const void* siaddr,const void* diaddr,const void* tiaddr,const void* shaddr) {
		set_length(0);

		write_8(NEIGHBOR_SOLICITATION); //type
		write_8(0); //code
		write_16(0); //checksum
		write_32(0); //reserved
		write(tiaddr,IPV6_ADDRESS_LENGTH); //target address

		write_8(SOURCE_LINKLAYER_ADDRESS); //type
		write_8(1); //length
		write(shaddr,MAC_ADDRESS_LENGTH); //source link-layer address

		checksum(siaddr,diaddr);
	}

	void write_neighbor_advertisement(const void* siaddr,const void* diaddr,uint8_t flags,const void* tiaddr,const void* thaddr) {
		set_length(0);

		write_8(NEIGHBOR_ADVERTISEMENT); //type
		write_8(0); //code
		write_16(0); //checksum
		write_32(htonl((flags & 0x07) << 0x1D)); //flags RSO
		write(tiaddr,IPV6_ADDRESS_LENGTH); //target address

		write_8(TARGET_LINKLAYER_ADDRESS); //type
		write_8(1); //length
		write(thaddr,MAC_ADDRESS_LENGTH); //target link-layer address

		checksum(siaddr,diaddr);
	}


	void print_ndp_options(){
		
		while(rpos() < length()){
			
			uint8_t type = read_8();
			
			if(type > 5) break;
			
			uint8_t length = read_8();

			printf("\n");

			switch(type){
				case SOURCE_LINKLAYER_ADDRESS:
				{
					printf("Option: Source Link-Layer Address (%d)\n", type);
					printf("        Length: %d\n", length);
					while(length--){
						printf("        Link-Layer Address: %s\n",read_string_mac());
					}
					break;
				}
				case TARGET_LINKLAYER_ADDRESS:
				{
					printf("Option: Target Link-Layer Address (%d)\n", type);
					printf("        Length: %d\n", length);
					while(length--){
						printf("        Link-Layer Address: %s\n",read_string_mac());
					}
					break;
				}
				case PREFIX_INFORMATION:
				{
					printf("Option: Prefix Information (%d)\n", type);
					printf("        Length: %d\n", length);
					printf("        Prefix Length: %d\n", read_8());
					printf("        Flags: 0x%.2X\n", read_8());
					printf("        Valid Lifetime: %ds\n", ntohl(read_32()));
					printf("        Preferred Lifetime: %ds\n", ntohl(read_32()));
					printf("        Reserved: 0x%.4X\n", ntohl(read_32()));
					printf("        Prefix: %s\n",read_string_ipv6());
					break;
				}
				case REDIRECT_HEADER:
				{
					printf("Option: Redirect Header (%d)\n", type);
					printf("        Length: %d\n", length);
					break;
				}
				case MTU:
				{
					printf("Option: MTU (%d)\n", type);
					printf("        Length: %d\n", length);
					break;
				}
			}
		}
	}


	void print_echo(uint8_t type){
		printf("Type: ");
		switch(type){
			case ECHO_REQUEST: printf("Echo Request "); break;
			case ECHO_REPLY: printf("Echo Reply "); break;
			default: printf("Unknown ");
		}
		printf("(%d)\n",type); 
		printf("Code: %d\n", read_8());
		printf("Checksum: 0x%.2X\n", ntohs(read_16()));
		printf("Identifier: %d\n", ntohs(read_16()));
		printf("Sequence Number: %d\n", ntohs(read_16()));
		printf("Data: { ");
		while(rpos() < length()){
			printf("%.2X ",read_8());
		}
		printf("}\n");
	}

	void print_router_solicitation(){
		printf("Type: Router Solicitation (%d)\n",ROUTER_SOLICITATION);
		printf("Code: %d\n", read_8());
		printf("Checksum: 0x%.2X\n", ntohs(read_16()));
		printf("Reserved: 0x%.4X\n", ntohl(read_32()));
		print_ndp_options();
	}

	void print_router_advertisement(){
		printf("Type: Router Advertisement (%d)\n",ROUTER_ADVERTISEMENT);
		printf("Code: %d\n", read_8());
		printf("Checksum: 0x%.2X\n", ntohs(read_16()));
		printf("Cur Hop Limit: %d\n", read_8());
		printf("Flags: 0x%.2X\n", read_8());
		printf("Router Lifetime: %ds\n", ntohs(read_16()));
		printf("Reachable Time: %lums\n", ntohl(read_32()));
		printf("Retrans Timer: %lums\n", ntohl(read_32()));
		print_ndp_options();
	}

	void print_neighbor_advertisement(){
		printf("Type: Neighbor Advertisement (%d)\n",NEIGHBOR_ADVERTISEMENT);
		printf("Code: %d\n",read_8());
		printf("Checksum: 0x%.2X\n",ntohs(read_16()));
		printf("Flags: 0x%.8X\n",ntohl(read_32()));
		printf("Target IP Address: %s\n",read_string_ipv6());
		print_ndp_options();
	}

	void print(){
		printf("\n-------- ICMPv6 --------\n");
		uint8_t type = read_8();
		switch(type){
			case ECHO_REQUEST:
			case ECHO_REPLY: print_echo(type); break;
			case ROUTER_SOLICITATION: print_router_solicitation(); break;
			case ROUTER_ADVERTISEMENT: print_router_advertisement(); break;
			case NEIGHBOR_ADVERTISEMENT: print_neighbor_advertisement(); break;
		}
	}
};


struct ICMP : PACKET {
public:
    enum TYPE : uint8_t {
		ECHO_REPLY = 0,
		DST_UNREACHABLE = 3,
		SRC_QUENCH = 4,
		REDIRECT = 5,
		ALTERNATE_HOST_ADDRESS = 6,
		ECHO_REQUEST = 8,
		ROUTER_ADVERTISEMENT = 9,
		ROUTER_SOLICITATION = 10,
		TIME_EXCEEDED = 11,
		PARAMETER_PROBLEM = 12,
		TIMESTAMP = 13,
		TIMESTAMP_REPLY = 14,
		INFORMATION_REQUEST = 15,
		INFORMATION_REPLY = 16,
	};

	enum DST_UNREACHABLE_CODE {
		NET_UNREACHABLE = 0,
		HOST_UNREACHABLE = 1,
		PROTOCOL_UNREACHABLE = 2,
		PORT_UNREACHABLE = 3,
		FRAG_NEEDED_AND_DF_SET = 4,
		SRC_ROUTER_FAILED = 5,
	};

	struct ECHO_HDR {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint16_t id;
		uint16_t seq_number;
		const uint8_t* data;
		int data_len;
	};

	void write_echo_request(uint16_t id,uint16_t seq_number,const void *data = nullptr,int len = 0){
		echo(ECHO_REQUEST,id,seq_number,data,len);
	}

	void write_echo_reply(uint16_t id,uint16_t seq_number,const void *data = nullptr,int len = 0){
		echo(ECHO_REPLY,id,seq_number,data,len);
	}

	ECHO_HDR read_echo_hdr(){
		set_rpos(0);
		ECHO_HDR hdr = {0};
		hdr.type = read_8();
		hdr.code = read_8();
		hdr.checksum = ntohs(read_16());
		hdr.id = ntohs(read_16());
		hdr.seq_number = ntohs(read_16());
		hdr.data = data() + rpos();
		hdr.data_len = length() - rpos();
		return hdr;
	}

	void print_echo(){
		uint8_t type = read_8();
		printf("Type: ");
		switch(type){
			case ECHO_REPLY: printf("Echo Reply "); break;
			case ECHO_REQUEST: printf("Echo Request "); break;
			default: printf("Unknown "); break;
		}
		printf("(%d)\n",type);
		printf("Code: %d\n",read_8());
		printf("Checksum: 0x%.2X\n",ntohs(read_16()));
		printf("Identifier: %d\n",ntohs(read_16()));
		printf("Sequence Number: %d\n",ntohs(read_16()));
		printf("Data: { ");
		while(rpos() < length()){
			printf("%.2X ",read_8());
		}
		printf("}\n");
	}

	void print(){
		printf("\n-------- ICMP --------\n");
		switch(peek_8(0)){
			case ECHO_REPLY:
			case ECHO_REQUEST: print_echo();
		}
	}

private:
	void echo(uint8_t type,uint16_t id,uint16_t seq_number,const void *data,int len){
		set_length(0);
		write_8(type); //type
		write_8(0); //code
		write_16(0); //checksum
		write_16(htons(id)); //identifier
		write_16(htons(seq_number)); //sequence number
		if(data != nullptr && len > 0){
			write(data,len); //data
		}
		write_16(htons(network_checksum(nullptr,this)),2);
	}
};



struct TCP : PACKET {
	
	enum FLAGS : uint8_t {
		FIN = 0x01,
		SYN = 0x02,
		RST = 0x04,
		PSH = 0x08,
		ACK = 0x10,
		URG = 0x20,
		ECE = 0x40,
		CWR = 0x80
	};

	struct HDR {
		uint16_t src_port;
		uint16_t dst_port;
		uint32_t seq_number;
		uint32_t ack_number;
		uint8_t data_offset : 4;
		uint8_t reserved : 4;
		uint8_t flags;
		uint16_t window;
		uint16_t checksum;
		uint16_t urgent_ptr;
	};

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		hdr.src_port = ntohs(read_16());
		hdr.dst_port = ntohs(read_16());
		hdr.seq_number = ntohl(read_32());
		hdr.ack_number = ntohl(read_32());
		uint8_t byte = read_8();
		hdr.data_offset = byte >> 0x04;
		hdr.reserved = byte & 0x0F;
		hdr.flags = read_8();
		hdr.window = ntohs(read_16());
		hdr.checksum = ntohs(read_16());
		hdr.urgent_ptr = ntohs(read_16());
		return hdr;
	}

	void print(){
		HDR hdr = read_hdr();
		printf("\n-------- TCP --------\n");
		printf("Source Port: %d\n",hdr.src_port);
		printf("Destination Port: %d\n",hdr.dst_port);
		printf("Sequence Number: %lu\n",hdr.seq_number);
		printf("Acknowledgment Number: %lu\n",hdr.ack_number);
		printf("Data Offset: %d bytes (%d)\n",hdr.data_offset << 0x02,hdr.data_offset);
		printf("Reserved: %d\n",hdr.reserved);
		printf("Flags: {\n");
		if(hdr.flags & CWR) printf("    CWR (Congestion Window Reduced)\n");
		if(hdr.flags & ECE) printf("    ECE (ECN-Echo)\n");
		if(hdr.flags & URG) printf("    URG (Urgent pointer field is significant)\n");
		if(hdr.flags & ACK) printf("    ACK (Acknowledgment field is significant)\n");
		if(hdr.flags & PSH) printf("    PSH (Push function)\n");
		if(hdr.flags & RST) printf("    RST (Reset the connection)\n");
		if(hdr.flags & SYN) printf("    SYN (Synchronize sequence numbers)\n");
		if(hdr.flags & FIN) printf("    FIN (No more data from sender)\n"); 
		printf("}\n");
		printf("Window: %d\n",hdr.window);
		printf("Checksum: 0x%04X\n",hdr.checksum);
		printf("Urgent Pointer: %d\n",hdr.urgent_ptr);
	}
};

struct UDP : PACKET {

	struct HDR {
		uint16_t src_port;
		uint16_t dst_port;
		uint16_t length;
		uint16_t checksum;
	};

	void write_hdr_ipv4(uint32_t siaddr,uint32_t diaddr,uint16_t src_port,uint16_t dst_port,PACKET &payload){
		set_length(0);

		uint16_t udp_length = htons(UDP_HDR_LENGTH + payload.length());

		PACKET phdr;
		phdr.write_32(siaddr);
		phdr.write_32(diaddr);
		phdr.write_8(0);
		phdr.write_8(IPPROTOCOL_UDP);
		phdr.write_16(udp_length);


		write_16(htons(src_port));
		write_16(htons(dst_port));
		write_16(udp_length);

		PACKET packet;
		packet = *this;
		packet += payload;

		write_16(htons(network_checksum(&phdr,&packet)));
	}

	void write_hdr_ipv6(const uint8_t* siaddr,const uint8_t* diaddr,uint16_t src_port,uint16_t dst_port,PACKET &payload){
		set_length(0);

		uint16_t udp_length = htons(UDP_HDR_LENGTH + payload.length());

		PACKET phdr;
		phdr.write(siaddr,IPV6_ADDRESS_LENGTH);
		phdr.write(diaddr,IPV6_ADDRESS_LENGTH);
		phdr.write_8(0);
		phdr.write_8(IPPROTOCOL_UDP);
		phdr.write_16(udp_length);


		write_16(htons(src_port));
		write_16(htons(dst_port));
		write_16(udp_length);

		PACKET packet;
		packet = *this;
		packet += payload;

		write_16(htons(network_checksum(&phdr,&packet)));
	}


	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		hdr.src_port = ntohs(read_16());
		hdr.dst_port = ntohs(read_16());
		hdr.length = ntohs(read_16());
		hdr.checksum = ntohs(read_16());
		return hdr;
	}

	void print(){
		HDR hdr = read_hdr();
		printf("\n-------- UDP --------\n");
		printf("Source Port: %d\n",hdr.src_port);
		printf("Destinantion Port: %d\n",hdr.dst_port);
		printf("Length: %d\n",hdr.length);
		printf("Checksum: 0x%04X\n",hdr.checksum);
	}
};


#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_START_OPTIONS_OFFSET 236

#define BOOT_MSG_REQUEST 1
#define BOOT_MSG_REPLY 2

#define DHCP_BROADCAST_FLAG 0x8000

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER 2
#define DHCP_MSG_REQUEST 3
#define DHCP_MSG_DECLINE 4
#define DHCP_MSG_ACK 5
#define DHCP_MSG_NAK 6
#define DHCP_MSG_RELEASE 7
#define DHCP_MSG_INFORM 8

#define DHCP_OPT_PADDING 0
#define DHCP_OPT_SUBNET_MASK 1
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_DNS 6
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_IP_ADDRESS_LEASE_TIME 51
#define DHCP_OPT_MESSAGE_TYPE 53
#define DHCP_OPT_SERVER_IDENTIFIER 54
#define DHCP_OPT_CLIENT_IDENTIFIER 61
#define DHCP_OPT_END 255

constexpr uint8_t dhcp_magic_cookie[4] = {99,130,83,99};

struct DHCP : PACKET {

	struct HDR{
		uint8_t op;
		uint8_t htype;
		uint8_t hlen;
		uint8_t hops;
		uint32_t xid;
		uint16_t secs;
		uint16_t flags;
		uint32_t ciaddr;
		uint32_t yiaddr;
		uint32_t siaddr;
		uint32_t giaddr;
		uint8_t chaddr[16];
		uint8_t sname[64];
		uint8_t file[128];
	};


	void write_hdr(HDR& hdr){
		set_length(0);
		write_8(hdr.op); //opcode
		write_8(hdr.htype); //htype
		write_8(hdr.hlen); //hlen
		write_8(hdr.hops); //hops
		write_32(htonl(hdr.xid)); //xid
		write_16(htons(hdr.secs)); //secs
		write_16(htons(hdr.flags)); //flags
		write_32(hdr.ciaddr); //ciaddr
		write_32(hdr.yiaddr); //yiaddr
		write_32(hdr.siaddr); //siaddr
		write_32(hdr.giaddr); //giaddr
		write(hdr.chaddr,hdr.hlen); //chaddr
		set(0, sizeof(hdr.chaddr) - hdr.hlen); //padding
		write(hdr.sname,sizeof(hdr.sname)); //sname
		write(hdr.file,sizeof(hdr.file)); //file
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		hdr.op = read_8();
		hdr.htype = read_8();
		hdr.hlen = read_8();
		hdr.hops = read_8();
		hdr.xid = ntohl(read_32());
		hdr.secs = ntohs(read_16());
		hdr.flags = ntohs(read_16());
		hdr.ciaddr = read_32();
		hdr.yiaddr = read_32();
		hdr.siaddr = read_32();
		hdr.giaddr = read_32();
		read(hdr.chaddr,hdr.hlen);
		read(hdr.sname,sizeof(hdr.sname));
		read(hdr.file,sizeof(hdr.file));
		return hdr;
	}


	void write_magic_cookie(){
		write(dhcp_magic_cookie, sizeof(dhcp_magic_cookie));
	}

	void write_message_type(uint8_t type){
		write_8(DHCP_OPT_MESSAGE_TYPE);
		write_8(1);
		write_8(type);
	}

	void write_client_identifier(const uint8_t* chaddr){
		write_8(DHCP_OPT_CLIENT_IDENTIFIER);
		write_8(1 + MAC_ADDRESS_LENGTH);
		write_8(HARDWARE_ETHERNET);
		write(chaddr,MAC_ADDRESS_LENGTH);
	}

	void write_server_identifier(uint32_t siaddr){
		write_8(DHCP_OPT_SERVER_IDENTIFIER);
		write_8(4);
		write_32(siaddr);
	}

	void write_requested_ip(uint32_t riaddr){
		write_8(DHCP_OPT_REQUESTED_IP);
		write_8(4);
		write_32(riaddr);
	}

	void write_end(){
		write_8(DHCP_OPT_END);
	}


	int get_option_value(uint8_t code,void* value,int len) {
		
		set_rpos(DHCP_START_OPTIONS_OFFSET + sizeof(dhcp_magic_cookie));

		uint8_t _len = 0;

		while (rpos() < length()) {

			uint8_t _code = read_8();
			
			if (_code == DHCP_OPT_PADDING) break;

			switch (_code) {
				case DHCP_OPT_SUBNET_MASK:
				case DHCP_OPT_ROUTER:
				case DHCP_OPT_DNS:
				case DHCP_OPT_REQUESTED_IP:
				case DHCP_OPT_IP_ADDRESS_LEASE_TIME:
				case DHCP_OPT_MESSAGE_TYPE:
				case DHCP_OPT_SERVER_IDENTIFIER:
					if (_code == code) {
						_len = read_8();
					}
					else {
						advance_rpos(read_8());
					}
					break;
			}

			if (_len > 0) {
				if (len >= _len) {
					read(value,_len);
				}
				else{
					_len = 0;
				}
				break;
			}
		}
		
		set_rpos(0);

		return _len;
	}


	void write_discover(uint32_t xid,uint16_t secs,uint16_t flags,const uint8_t* chaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.secs = secs;
		hdr.flags = flags;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_DISCOVER);
		write_client_identifier(chaddr);
		write_end();
	}

	void write_inform(uint32_t xid,uint16_t flags,uint32_t ciaddr,const uint8_t* chaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.flags = flags;
		hdr.ciaddr = ciaddr;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_INFORM);
		write_client_identifier(chaddr);
		write_end();
	}

	void write_request_select(uint32_t xid,uint16_t secs,uint16_t flags,const uint8_t* chaddr,uint32_t siaddr,uint32_t riaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.secs = secs;
		hdr.flags = flags;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_REQUEST);
		write_client_identifier(chaddr);
		write_server_identifier(siaddr);
		write_requested_ip(riaddr);
		write_end();
	}

	void write_request_init_boot(uint32_t xid,uint16_t secs,uint16_t flags,const uint8_t* chaddr,uint32_t riaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.secs = secs;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_REQUEST);
		write_client_identifier(chaddr);
		write_requested_ip(riaddr);
		write_end();
	}

	void write_request_renewing(uint32_t xid,uint16_t secs,uint16_t flags,uint32_t ciaddr,const uint8_t* chaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.secs = secs;
		hdr.flags = flags;
		hdr.ciaddr = ciaddr;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_REQUEST);
		write_client_identifier(chaddr);
		write_end();

	}

	void write_decline(uint32_t xid,const uint8_t* chaddr,uint32_t siaddr,uint32_t riaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_DECLINE);
		write_client_identifier(chaddr);
		write_server_identifier(siaddr);
		write_requested_ip(riaddr);
		write_end();
	}

	void write_release(uint32_t xid,uint32_t ciaddr,const uint8_t* chaddr,uint32_t siaddr){
		HDR hdr = {0};
		hdr.op = BOOT_MSG_REQUEST;
		hdr.htype = HARDWARE_ETHERNET;
		hdr.hlen = MAC_ADDRESS_LENGTH;
		hdr.xid = xid;
		hdr.ciaddr = ciaddr;
		memcpy(hdr.chaddr,chaddr,hdr.hlen);

		write_hdr(hdr);
		write_magic_cookie();
		write_message_type(DHCP_MSG_RELEASE);
		write_client_identifier(chaddr);
		write_server_identifier(siaddr);
		write_end();
	}


	void print_options(){
		set_rpos(DHCP_START_OPTIONS_OFFSET);

		uint8_t buffer[4] = {0};
		read(buffer,sizeof(dhcp_magic_cookie));

		if(memcmp(buffer,dhcp_magic_cookie,sizeof(dhcp_magic_cookie))){
			set_rpos(0);
			return;
		}

		printf("Magic Cookie: Ok\n");
		
		while (rpos() < length()) {
			
			uint8_t code = read_8();
			
			if (code == DHCP_OPT_PADDING) break;

			printf("\n");

			switch (code) {
				case DHCP_OPT_SUBNET_MASK:{
					printf("Option: Subnet Mask (%d)\n",code);
					printf("        Length: %d\n", read_8());
					printf("        Subnet Mask: %s\n",read_string_ipv4());
					break;
				}
				case DHCP_OPT_ROUTER:{
					uint8_t length = read_8();
					uint8_t addresses = length >> 0x02;
					printf("Option: Router (%d)\n",code);
					printf("        Length: %d\n", length);
					while (addresses--) {
						printf("        Address: %s\n",read_string_ipv4());
					}
					break;
				}
				case DHCP_OPT_DNS:{
					uint8_t length = read_8();
					uint8_t addresses = length >> 0x02;
					printf("Option: Domain Name Server (%d)\n",code);
					printf("        Length: %d\n", length);
					while (addresses--) {
						printf("        Address: %s\n",read_string_ipv4());
					}
					break;
				}
				case DHCP_OPT_REQUESTED_IP:{
					printf("Option: Requested IP Address (%d)\n",code);
					printf("        Length: %d\n",read_8());
					printf("        Address: %s\n",read_string_ipv4());
					break;
				}
				case DHCP_OPT_IP_ADDRESS_LEASE_TIME:{
					printf("Option: IP Address Lease Time (%d)\n",code);
					printf("        Length: %d\n", read_8());
					printf("        Lease Time: %lu\n", ntohl(read_32()));
					break;
				}
				case DHCP_OPT_MESSAGE_TYPE:{
					uint8_t length = read_8();
					uint8_t type = read_8();
					printf("Option: Message Type (%d)\n",code);
					printf("        Length: %d\n", length);
					printf("        Type: ");
					switch (type) {
						case DHCP_MSG_DISCOVER: printf("DISCOVER "); break;
						case DHCP_MSG_OFFER:    printf("OFFER ");    break;
						case DHCP_MSG_REQUEST:  printf("REQUEST ");  break;
						case DHCP_MSG_DECLINE:  printf("DECLINE ");  break;
						case DHCP_MSG_ACK:      printf("ACK ");      break;
						case DHCP_MSG_NAK:      printf("NAK ");      break;
						case DHCP_MSG_RELEASE:  printf("RELEASE ");  break;
						case DHCP_MSG_INFORM:   printf("INFORM ");   break;
						default:                printf("Unknown ");  break;
					}
					printf("(%d)\n", type);
					break;
				}
				case DHCP_OPT_SERVER_IDENTIFIER:{
					printf("Option: Server Identifier (%d)\n",code);
					printf("        Length: %d\n", read_8());
					printf("        Address: %s\n",read_string_ipv4());
					break;
				}
				case DHCP_OPT_CLIENT_IDENTIFIER:{
					uint8_t length = read_8();
					uint8_t ilen = (length > 0) ? length - 1 : 0;
					uint8_t type = read_8();
					printf("Option: Client Identifier (%d)\n",code);
					printf("        Length: %d\n",length);
					switch (type) {
						case HARDWARE_ETHERNET:
							printf("        Type: Ethernet (%d)\n",HARDWARE_ETHERNET);
							printf("        MAC: %s\n",read_string_mac());
							break;
						default:
							printf("        Type: Unknown (%d)\n",type);
							printf("        Identifier: {");
							for (int i = 0; i < ilen; ++i) {
								printf("%.2X", read_8());
								if (i < ilen - 1) {
									printf(",");
								}
							}
							printf("}\n");
							break;
					}
					break;
				}
				case DHCP_OPT_END:{
					printf("Option: End (%d)\n",code);
					break;
				}
				default:
					return;
			}
		}

		set_rpos(0);
	}

	void print(){
		printf("\n-------- DHCP --------\n");
		HDR hdr = read_hdr();

		printf("Opcode: ");
		switch(hdr.op){
			case BOOT_MSG_REQUEST: printf("Boot Request "); break;
			case BOOT_MSG_REPLY: printf("Boot Reply "); break;
			default: printf("Unknown "); break;
		}
		printf("(%d)\n",hdr.op);
		
		printf("Hardware Type: %s (%d)\n",sprint_hardware_type(hdr.htype),hdr.htype);

		printf("Hardware Address Length: %d\n",hdr.hlen);

		printf("Hops: %d\n",hdr.hops);
		printf("Transaction ID: %lu\n",hdr.xid);
		printf("Seconds: %d\n",hdr.secs);
		printf("Flags: 0x%.4X\n",hdr.flags);
		printf("Client IP Address: %s\n",sprint_ipv4(&hdr.ciaddr));
		printf("Yout IP Address: %s\n",sprint_ipv4(&hdr.yiaddr));
		printf("Server IP Address: %s\n",sprint_ipv4(&hdr.siaddr));
		printf("Gateway IP Address: %s\n",sprint_ipv4(&hdr.giaddr));
		
		printf("Client Hardware Address: ");
		if(hdr.htype == HARDWARE_ETHERNET && hdr.hlen == MAC_ADDRESS_LENGTH){
			printf("%s\n",sprint_mac(hdr.chaddr));
		}
		else{
			hdr.hlen = (hdr.hlen > sizeof(HDR::chaddr)) ? sizeof(HDR::chaddr) : hdr.hlen;
			printf("{ ");
			for(int i = 0; i < hdr.hlen; ++i) printf("%.2X ",hdr.chaddr[i]);
			printf("}\n");
		}
		advance_rpos(sizeof(HDR::chaddr) - hdr.hlen);

		printf("Server Name: %s\n",sprint_string(hdr.sname,sizeof(hdr.sname)));
		printf("File Name: %s\n",sprint_string(hdr.file,sizeof(hdr.file)));

		print_options();
	}
};


#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define DHCPV6_OPTIONS_OFFSET 4

#define DHCPV6_MSG_SOLICIT 1
#define DHCPV6_MSG_ADVERTISE 2
#define DHCPV6_MSG_REQUEST 3
#define DHCPV6_MSG_CONFIRM 4
#define DHCPV6_MSG_RENEW 5
#define DHCPV6_MSG_REBIND 6
#define DHCPV6_MSG_REPLY 7
#define DHCPV6_MSG_RELEASE 8
#define DHCPV6_MSG_DECLINE 9
#define DHCPV6_MSG_RECONFIGURE 10
#define DHCPV6_MSG_INFORMATION_REQUEST 11
#define DHCPV6_MSG_RELAY_FORWARD 12
#define DHCPV6_MSG_RELAY_REPLY 13

#define DHCPV6_OPT_CLIENTID 1
#define DHCPV6_OPT_SERVERID 2
#define DHCPV6_OPT_IA_NA 3
#define DHCPV6_OPT_IA_TA 4
#define DHCPV6_OPT_IAADDR 5
#define DHCPV6_OPT_REQUEST 6
#define DHCPV6_OPT_ELAPSED_TIME 8
#define DHCPV6_OPT_STATUS_CODE 13
#define DHCPV6_OPT_DNS_SERVERS 23
#define DHCPV6_OPT_DOMAIN_LIST 24
#define DHCPV6_OPT_IA_PD 25
#define DHCPV6_OPT_IA_PREFIX 26
#define DHCPV6_OPT_SNTP_SERVERS 31
#define DHCPV6_OPT_INFORMATION_REFRESH_TIME 32
#define DHCPV6_OPT_NTP_SERVER 56
#define DHCPV6_OPT_INF_MAX_RT 83

#define DHCPV6_STATUS_SUCCESS 0
#define DHCPV6_STATUS_UNSPECFAIL 1
#define DHCPV6_STATUS_NOADDRSAVAIL 2
#define DHCPV6_STATUS_NOBINDING 3
#define DHCPV6_STATUS_NOTONLINK 4
#define DHCPV6_STATUS_USEMULTICAST 5
#define DHCPV6_STATUS_NOPREFIXAVAIL 6


#define DUID_LLT 1
#define DUID_EN 2
#define DUID_LL 3
#define DUID_UUID 4

struct DHCPV6 : PACKET {
private:
    uint8_t* odata;
	size_t ocapacity;
	size_t olen;
public:

	struct OPTION {
		OPTION* next;
		uint16_t opcode;
		uint16_t length;
		uint8_t* data;
	};

	struct HDR {
		uint8_t msg_type;
		uint32_t id;
	};

	DHCPV6():odata(nullptr),ocapacity(0),olen(0){}

	~DHCPV6(){
		free(odata);
	}


	bool is_valid_option_code(uint16_t opcode){
		if(opcode == 0 || opcode == 10 || opcode == 35 || opcode >= 151) return false;
		return true;
	}

	HDR read_hdr(){
		set_rpos(0);
		HDR hdr = {0};
		hdr.msg_type = read_8();
		read(&hdr.id,3);
		return hdr;
	}

	const OPTION* read_options(){

		set_rpos(DHCPV6_OPTIONS_OFFSET);
		
		size_t options = 0;
		size_t odata_length = 0;

		while(rpos() < length()){
			uint16_t opcode = ntohs(read_16());
			if(!is_valid_option_code(opcode)) break;
			options++;
			odata_length += ntohs(read_16());
			advance_rpos(odata_length);
		}

		if(!options || !odata_length) return nullptr;

		olen = (options * sizeof(OPTION)) + odata_length;

		if(olen > ocapacity){
			void* new_odata = realloc(odata,ocapacity + olen);
			if(!new_odata){
				printf("function: %s line: %d realloc: failed\n",__func__,__LINE__);
				exit(1);
			}

			odata = (uint8_t*)new_odata;
			ocapacity += olen;
		}

		set_rpos(DHCPV6_OPTIONS_OFFSET);

		size_t option_offset = 0;
		OPTION option;

		for(int i = 0; i < options; ++i){

			option.opcode = ntohs(read_16());
			option.length = ntohs(read_16());
			option.data = odata + option_offset + sizeof(OPTION);
			
			if(i == options - 1){
				option.next = nullptr;
			}
			else{
				option.next = (OPTION*)(option.data + option.length);
			}

			memcpy(odata + option_offset,&option,sizeof(OPTION));

			read(option.data,option.length);

			option_offset += sizeof(OPTION) + option.length;
		}

		return (OPTION*)odata;
	}


	void write_information_request(uint32_t id){
		set_length(0);
		write_8(DHCPV6_MSG_INFORMATION_REQUEST);
		id &= 0x00FFFFFF;
		write(&id,3);
	}


	void write_option_client_id_llt(uint32_t time,const uint8_t* haddr){
		write_16(htons(DHCPV6_OPT_CLIENTID));         //Opcode
		write_16(htons(8 + MAC_ADDRESS_LENGTH)); //Length
		write_16(htons(DUID_LLT));                    //DUID Type
		write_16(htons(HARDWARE_ETHERNET));           //Hardware Type
		write_32(htonl(time));                        //Time
		write(haddr,MAC_ADDRESS_LENGTH);         //Hardware Address
	}

	void write_option_client_id_en(uint32_t en,const uint8_t* id_data,uint32_t id_length){
		write_16(htons(DHCPV6_OPT_CLIENTID)); //Opcode
		write_16(htons(6 + id_length));       //Length
		write_16(htons(DUID_EN));             //DUID Type
		write_32(htonl(en));                  //Enterprise-Number
		write(id_data,id_length);             //Identifier
	}

	void write_option_client_id_ll(const uint8_t* haddr){
		write_16(htons(DHCPV6_OPT_CLIENTID));         //Opcode
		write_16(htons(4 + MAC_ADDRESS_LENGTH)); //Length
		write_16(htons(DUID_LL));                     //DUID Type
		write_16(htons(HARDWARE_ETHERNET));           //Hardware 
		write(haddr,MAC_ADDRESS_LENGTH);         //Hardware Address
	}

	void write_option_client_id_uuid(const uint8_t* uuid){
		write_16(htons(DHCPV6_OPT_CLIENTID)); //Opcode
		write_16(htons(2 + UUID_LENGTH));     //Length
		write_16(htons(DUID_UUID));           //DUID Type
		write(uuid,UUID_LENGTH);              //UUID
	}


	void write_option_ia_na(uint32_t iaid){
		write_16(htons(DHCPV6_OPT_IA_NA));
	}

	void write_option_ia_ta(uint32_t iaid){
		write_16(htons(DHCPV6_OPT_IA_TA));
	}


	void write_option_elapsed_time(uint16_t time){
		write_16(htons(DHCPV6_OPT_ELAPSED_TIME)); //Opcode
		write_16(htons(2)); //Length
		write_16(htons(time)); //Elapsed Time
	}


	void write_option_request(const void* ro,uint16_t len){
		write_16(htons(DHCPV6_OPT_REQUEST)); //Opcode
		write_16(htons(len & ~0x01)); //Length
		write(ro,len);
	}


	void print(){
		printf("\n-------- DHCPv6 --------\n");
		HDR hdr = read_hdr();

		printf("Message Type: %s (%d)\n",sprint_msg_type(hdr.msg_type),hdr.msg_type);

		printf("Transaction ID: %06X\n",hdr.id);

		const OPTION* option = read_options();

		while(option != nullptr){
			printf("\n");
			printf("Option: %s (%d)\n",sprint_option_code(option->opcode),option->opcode);
			printf("        Length: %d\n",option->length);
			PACKET packet;
			packet.write(option->data,option->length);

			switch(option->opcode){
				case DHCPV6_OPT_CLIENTID:
				case DHCPV6_OPT_SERVERID:{
					uint16_t duid_type = ntohs(packet.read_16());
					
					printf("        DUID Type: %s (%d)\n",sprint_duid_type(duid_type),duid_type);
					switch(duid_type){
						case DUID_LLT:{
							uint16_t htype = ntohs(packet.read_16());
							printf("        Hardware Type: %s (%d)\n",sprint_hardware_type(htype),htype);
							printf("        Time: %ds\n",ntohl(packet.read_32()));
							printf("        MAC: %s\n",packet.read_string_mac());
							break;
						}
						case DUID_EN:{
							printf("        Enterprise-Number: %08X\n",ntohl(packet.read_32()));
							printf("        Identifier: %s\n",packet.read_string(packet.length() - packet.rpos()));
							break;
						}
						case DUID_LL:{
							uint16_t htype = ntohs(packet.read_16());
							printf("        Hardware Type: %s (%d)\n",sprint_hardware_type(htype),htype);
							printf("        MAC: %s\n",packet.read_string_mac());
							break;
						}
						case DUID_UUID:{
							printf("        UUID: %s\n",packet.read_string_uuid());
							break;
						}
					}
					break;
				}
				case DHCPV6_OPT_IA_NA:{
					break;
				}
				case DHCPV6_OPT_IA_TA:{
					break;
				}
				case DHCPV6_OPT_REQUEST:{
					uint16_t options = packet.length() >> 0x01;

					for(int i = 0; i < options; ++i){
						uint16_t opcode = ntohs(packet.read_16());
						printf("        Option: %s (%d)\n",sprint_option_code(opcode),opcode);
					}
					break;
				}
				case DHCPV6_OPT_ELAPSED_TIME:{
					printf("        Time: %ds\n",ntohl(packet.read_16()));
					break;
				}
				case DHCPV6_OPT_STATUS_CODE:{
					break;
				}
				case DHCPV6_OPT_DNS_SERVERS:{
					int i = 0;
					while(true){
						const char* server_address = packet.read_string_ipv6();
						if(!server_address) break;
						printf("        %d DNS Server Address: %s\n",i++,server_address);
					}
					break;
				}
				case DHCPV6_OPT_DOMAIN_LIST:{
					int i = 0;
					while(true){
						const char* domain_name = packet.read_domain_name();
						if(!domain_name) break;
						printf("        %d Domain Name: %s\n",i++,domain_name);
					}
					break;
				}
				case DHCPV6_OPT_SNTP_SERVERS:{
					int i = 0;
					while(true){
						const char* server_address = packet.read_string_ipv6();
						if(!server_address) break;
						printf("        %d SNTP Server Address: %s\n",i++,server_address);
					}
					break;
				}
				case DHCPV6_OPT_INFORMATION_REFRESH_TIME: break;
				case DHCPV6_OPT_NTP_SERVER: break;
				case DHCPV6_OPT_INF_MAX_RT: break;
				default: break;
			}
			option = option->next;
		}
	}


	const char* sprint_msg_type(uint8_t type);
	const char* sprint_option_code(uint16_t code);
	const char* sprint_status_code(uint16_t code);
	const char* sprint_duid_type(uint16_t type);
};


#define DNS_SERVER_PORT 53

struct DNS : PACKET {
public:
	enum TYPE {
		A = 1,
		NS = 2,
		AAAA = 28
	};

	enum CLASS {
		INTERNET = 1,
		CSNET = 2,
		CHAOS = 3,
		HESIOD = 4,
	};

	enum FLAG {
		RCODE  = 0x000F,
		Z      = 0x0070,
		RA     = 0x0080,
		RD     = 0x0100,
		TC     = 0x0200,
		AA     = 0x0400,
		OPCODE = 0x7800,
		QR     = 0x8000,
	};

	enum OPCODE {
		QUERY = 0,
		IQUERY = 1,
		STATUS = 2,
		NOTIFY = 4,
		UPDATE = 5,
		DSO = 6
	};

	enum RCODE {
		NOERROR = 0,
		FORMERR = 1,
		SERVFAIL = 2,
		NXDOMAIN = 3,
		NOIMP = 4,
		REFUSED = 5
	};

	struct FLAGS {
		uint8_t rcode : 4;
		uint8_t rsv : 3;
		bool ra : 1;
		bool rd : 1;
		bool tc : 1;
		bool aa : 1;
		uint8_t opcode : 4;
		bool qr : 1;
	};

	struct QUESTION {
		char qname[DNS_MAX_NAME_LENGTH + 1];
		uint16_t qtype;
		uint16_t qclass;
	};

	struct RR {
		char rname[DNS_MAX_NAME_LENGTH + 1];
		uint16_t rtype;
		uint16_t rclass;
		uint32_t rttl;
		uint16_t rlength;
		size_t rdata_offset;
	};

	typedef RR ANSWER,AUTHORITY,ADDITIONAL;

	struct MESSAGE {
		uint16_t length;
		uint16_t id;
		FLAGS flags;
		uint16_t qdcount;
		uint16_t ancount;
		uint16_t nscount;
		uint16_t arcount;
		const QUESTION* question;
		const ANSWER* answer;
		const AUTHORITY* authority;
		const ADDITIONAL* additional;
	};

	DNS():pdata(nullptr),pcapacity(0),plen(0){}

	~DNS(){
		free(pdata);
	}

	template<bool tcp>
	void write_hdr(uint16_t id,FLAGS flags,uint16_t qdcount,uint16_t ancount,uint16_t nscount,uint16_t arcount){
		set_length(0);

		if constexpr (tcp){
			write_16(0); //prefix length
		}

		write_16(htons(id));
		uint16_t _flags = (flags.qr     << 0x0F) | 
		                  (flags.opcode << 0x0B) | 
						  (flags.aa     << 0x0A) | 
						  (flags.tc     << 0x09) | 
						  (flags.rd     << 0x08) | 
						  (flags.ra     << 0x07) | 
						  (flags.rcode  << 0x00);
		write_16(_flags);
		write_16(htons(qdcount));
		write_16(htons(ancount));
		write_16(htons(nscount));
		write_16(htons(arcount));
	}

	void write_question(const char* qname,uint16_t qtype,uint16_t qclass){
		write_domain_name(qname);
		write_16(htons(qtype));
		write_16(htons(qclass));
	}
    
	void set_prefix_length(){
		uint16_t l = length();
		if(l >= 2){
			write_16(htons(l - 2),0);
		}
	}


	template<bool tcp>
	MESSAGE read_message(){
		set_rpos(0);

		MESSAGE msg = {0};
		
		if constexpr (tcp){
			msg.length = ntohs(read_16());
		}

		msg.id = ntohs(read_16());

		uint16_t _flags = ntohs(read_16());
		msg.flags.qr     = (_flags & FLAG::QR) >> 0x0F;
		msg.flags.opcode = (_flags & FLAG::OPCODE) >> 0x0B;
		msg.flags.aa     = (_flags & FLAG::AA) >> 0x0A;
		msg.flags.tc     = (_flags & FLAG::TC) >> 0x09;
		msg.flags.rd     = (_flags & FLAG::RD) >> 0x08;
		msg.flags.ra     = (_flags & FLAG::RA) >> 0x07;
		msg.flags.rsv    = (_flags & FLAG::Z) >> 0x04;
		msg.flags.rcode  = (_flags & FLAG::RCODE) >> 0x00;

		msg.qdcount = ntohs(read_16());
		msg.ancount = ntohs(read_16());
		msg.nscount = ntohs(read_16());
		msg.arcount = ntohs(read_16());

		size_t question_len = msg.qdcount * sizeof(QUESTION);
		size_t answer_len = msg.ancount * sizeof(ANSWER);
		size_t authority_len = msg.nscount * sizeof(AUTHORITY);
		size_t additional_len = msg.arcount * sizeof(ADDITIONAL);

		size_t len = question_len + answer_len + authority_len + additional_len;

		if(reserve(len)){
			plen = len;
			uint8_t* ptr = pdata;

			msg.question = (QUESTION*)ptr;
			read_question<tcp>((QUESTION*)ptr,msg.qdcount);
			ptr += question_len;

			msg.answer = (ANSWER*)ptr;
			read_rr<tcp>((ANSWER*)ptr,msg.ancount);
			ptr += answer_len;

			msg.authority = (AUTHORITY*)ptr;
			read_rr<tcp>((AUTHORITY*)ptr,msg.nscount);
			ptr += authority_len;

			msg.additional = (ADDITIONAL*)ptr;
			read_rr<tcp>((ADDITIONAL*)ptr,msg.arcount);
			ptr += additional_len;
		}

		return msg;
	}


	void print_question(const QUESTION* qptr,uint16_t count){
		if(!count || !qptr) return;
		printf("Question: {\n");
		for(uint16_t i = 0; i < count; ++i){
			printf("\n");
			const QUESTION& quest = qptr[i];
			printf("    Name: %s\n",quest.qname);
			printf("    Type: %s (%d)\n",sprint_type(quest.qtype),quest.qtype);
			printf("    Class: %s (%d)\n",sprint_class(quest.qclass),quest.qclass);
		}
		printf("}\n");
	}

	template<bool tcp>
	void print_rr(const char* name,const RR* rrptr,uint16_t count){
		if(!count || !rrptr) return;
		
		printf("%s: {\n",name);
		
		for(uint16_t i = 0; i < count; ++i){
			
			printf("\n");
			
			const RR& rr = rrptr[i];

			printf("    Name: %s\n",rr.rname);
			printf("    Type: %s (%d)\n",sprint_type(rr.rtype),rr.rtype);
			printf("    Class: %s (%d)\n",sprint_class(rr.rclass),rr.rclass);
			printf("    Time To Live: %lus\n",rr.rttl);
			printf("    Data Length: %d\n",rr.rlength);

			switch(rr.rclass){
				case CLASS::INTERNET:{
					switch(rr.rtype){
						case TYPE::A:{
							if(rr.rlength >= IPV4_ADDRESS_LENGTH){
								printf("    Address: %s\n",read_string_ipv4(rr.rdata_offset));
							}
							break;
						}
						case TYPE::NS:{
							printf("    Name Server: %s\n",read_domain_name(tcp ? 2 : 0,rr.rdata_offset));
							break;
						}
						case TYPE::AAAA:{
							if(rr.rlength >= IPV6_ADDRESS_LENGTH){
								printf("    Address: %s\n",read_string_ipv6(rr.rdata_offset));
							}
							break;
						}
					}
					break;
				}
				case CLASS::CSNET:{
					break;
				}
				case CLASS::CHAOS:{
					break;
				}
				case CLASS::HESIOD:{
					break;
				}
			}

		}
		printf("}\n");
	}

	template<bool tcp>
	void print(){

		MESSAGE msg = read_message<tcp>();
		
		printf("\n-------- DNS --------\n");
		
		if constexpr (tcp){
			printf("Length: %d\n",msg.length);
		}

		printf("ID: 0x%04x\n",msg.id);
		
		printf("Flags: {\n");
		printf("    Message: %s (%d)\n",msg.flags.qr ? "Response" : "Query",msg.flags.qr);
		printf("    Opcode: %s (%d)\n",sprint_opcode(msg.flags.opcode),msg.flags.opcode);
		printf("    Authoritative Answer: %s\n",msg.flags.aa ? "True" : "False");
		printf("    Truncated: %s\n",msg.flags.tc ? "True" : "False");
		printf("    Recursion Desired: %s\n",msg.flags.rd ? "True" : "False");
		printf("    Recursion Available: %s\n",msg.flags.ra ? "True" : "False");
		printf("    Reserved: %d\n",msg.flags.rsv);
		printf("    Response Code: %s (%d)\n",sprint_rcode(msg.flags.rcode),msg.flags.rcode);
		printf("}\n");

		printf("Questions: %d\n",msg.qdcount);
		printf("Answer RRs: %d\n",msg.ancount);
		printf("Authority RRs: %d\n",msg.nscount);
		printf("Additional RRs: %d\n",msg.arcount);
		
		print_question(msg.question,msg.qdcount);
		print_rr<tcp>("Answer",msg.answer,msg.ancount);
		print_rr<tcp>("Authority",msg.authority,msg.nscount);
		print_rr<tcp>("Additional",msg.additional,msg.arcount);
	}

	const char* sprint_opcode(uint8_t code);
	const char* sprint_rcode(uint8_t code);
	const char* sprint_type(uint16_t type);
	const char* sprint_class(uint16_t _class);

private:
	uint8_t* pdata;
	size_t pcapacity;
	size_t plen;

	bool reserve(size_t len){
		if(len <= pcapacity) return true;

		void* new_pdata = realloc(pdata,pcapacity + len);
		if(!new_pdata){
			fprintf(stderr,"function: %s line: %d realloc: failed\n",__func__,__LINE__);
			return false;
		}

		pdata = (uint8_t*)new_pdata;
		pcapacity += len;

		return true;
	}

	template<bool tcp>
	void read_question(QUESTION* qptr,uint16_t count){
		for(uint16_t i = 0; i < count; ++i){
			QUESTION& quest = qptr[i];
			snprintf(quest.qname,sizeof(quest.qname),"%s",read_domain_name(tcp ? 2 : 0));
			quest.qtype = ntohs(read_16());
			quest.qclass = ntohs(read_16());
		}
	}

	template<bool tcp>
	void read_rr(RR* rrptr,uint16_t count){
		for(uint16_t i = 0; i < count; ++i){
			RR& rr = rrptr[i];
			snprintf(rr.rname,sizeof(rr.rname),"%s",read_domain_name(tcp ? 2 : 0));
			rr.rtype = ntohs(read_16());
			rr.rclass = ntohs(read_16());
			rr.rttl = ntohl(read_32());
			rr.rlength = ntohs(read_16());
			rr.rdata_offset = rpos();
			advance_rpos(rr.rlength);
		}
	}

};
