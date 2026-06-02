#include <Packet.h>

thread_local char _buffer[BUFFER_MAX_LENGTH] = {0};

#define PRINT(s) snprintf(_buffer,sizeof(_buffer),s)
#define MIN(x,y) ((x > y) ? y : x)
#define MAX(x,y) ((x > y) ? x : y)


const char* sprint_mac(const void* data){
	const uint8_t* d = (uint8_t*)data;
	snprintf(
		_buffer,
		sizeof(_buffer),
		"%02x-%02x-%02x-%02x-%02x-%02x",
		d[0],d[1],d[2],d[3],d[4],d[5]
	);
	return _buffer;
}

const char* sprint_ipv4(const void* data){
	const uint8_t* d = (uint8_t*)data;
	snprintf(
		_buffer,
		sizeof(_buffer),
		"%d.%d.%d.%d",
		d[0],d[1],d[2],d[3]
	);
	return _buffer;
}

const char* sprint_ipv6(const void* data){
	inet_ntop(AF_INET6,data,_buffer,sizeof(_buffer));
	return _buffer;
}


const char* sprint_string(const uint8_t* data,size_t len){
	snprintf(_buffer,sizeof(_buffer),"%.*s",(int)len,data);
	return _buffer;
}


const char* sprint_hardware_type(uint16_t htype){
	switch(htype){
		case HARDWARE_ETHERNET:                  PRINT("Ethernet (10Mb)");                               break;
		case HARDWARE_EXPERIMENTAL_ETHERNET:     PRINT("Experimental Ethernet (3Mb)");                   break;
		case HARDWARE_AMATEUR_RADIO_AX25:        PRINT("Amateur Radio AX.25");                           break;
		case HARDWARE_PROTEON_PRONET_TOKEN_RING: PRINT("Proteon ProNET Token Ring");                     break;
		case HARDWARE_CHAOS:                     PRINT("Chaos");                                         break;
		case HARDWARE_IEEE_802_NETWORKS:         PRINT("IEEE 802 Networks");                             break;
		case HARDWARE_ARCNET:                    PRINT("ARCNET");                                        break;
		case HARDWARE_HYPERCHANNEL:              PRINT("Hyperchannel");                                  break;
		case HARDWARE_LANSTAR:                   PRINT("Lanstar");                                       break;
		case HARDWARE_AUTONET_SHORT_ADDRESS:     PRINT("Autonet Short Address");                         break;
		case HARDWARE_LOCALTALK:                 PRINT("LocalTalk");                                     break;
		case HARDWARE_LOCALNET:                  PRINT("LocalNet (IBM PCNet or SYTEK LocalNET)");        break;
		case HARDWARE_ULTRA_LINK:                PRINT("Ultra link");                                    break;
		case HARDWARE_SMDS:                      PRINT("SMDS");                                          break;
		case HARDWARE_FRAME_RELAY:               PRINT("Frame Relay");                                   break;
		case HARDWARE_ATM1:                      PRINT("Asynchronous Transmission Mode (ATM)");          break;
		case HARDWARE_HDLC:                      PRINT("HDLC");                                          break;
		case HARDWARE_FIBRE_CHANNEL:             PRINT("Fibre Channel");                                 break;
		case HARDWARE_ATM2:                      PRINT("Asynchronous Transmission Mode (ATM)");          break;
		case HARDWARE_SERIAL_LINE:               PRINT("Serial Line");                                   break;
		case HARDWARE_ATM3:                      PRINT("Asynchronous Transmission Mode (ATM)");          break;
		case HARDWARE_MIL_STD_188_220:           PRINT("MIL-STD-188-220");                               break;
		case HARDWARE_METRICOM:                  PRINT("Metricom");                                      break;
		case HARDWARE_IEEE_1394_1995:            PRINT("IEEE 1394.1995");                                break;
		case HARDWARE_MAPOS:                     PRINT("MAPOS");                                         break;
		case HARDWARE_TWINAXIAL:                 PRINT("Twinaxial");                                     break;
		case HARDWARE_EUI64:                     PRINT("EUI-64");                                        break;
		case HARDWARE_HIPARP:                    PRINT("HIPARP");                                        break;
		case HARDWARE_IP_AND_ARP:                PRINT("IP and ARP over ISO 7816-3");                    break;
		case HARDWARE_ARPSEC:                    PRINT("ARPSec");                                        break;
		case HARDWARE_IPSEC_TUNNEL:              PRINT("IPsec tunnel");                                  break;
		case HARDWARE_INFINIBAND:                PRINT("InfiniBand (TM)");                               break;
		case HARDWARE_CAI:                       PRINT("TIA-102 Project 25 Common Air Interface (CAI)"); break;
		case HARDWARE_WIEGAND_INTERFACE:         PRINT("Wiegand Interface");                             break;
		case HARDWARE_PURE_IP:                   PRINT("Pure IP");                                       break;
		case HARDWARE_HW_EXP1:                   PRINT("HW_EXP1");                                       break;
		case HARDWARE_HFI:                       PRINT("HFI");                                           break;
		case HARDWARE_UNIFIED_BUS:               PRINT("Unified Bus (UB)");                              break;
		case HARDWARE_HW_EXP2:                   PRINT("HW_EXP2");                                       break;
		case HARDWARE_AETHERNET:                 PRINT("AEthernet");                                     break;
		default:                                 PRINT("Unknown");                                       break;
	}
	return _buffer;
}

const char* sprint_ip_protocol(uint8_t protocol){
	switch(protocol){
		case IPPROTOCOL_ICMP:   PRINT("ICMP");    break;
		case IPPROTOCOL_TCP:    PRINT("TCP");     break;
		case IPPROTOCOL_UDP:    PRINT("UDP");     break;
		case IPPROTOCOL_ICMPV6: PRINT("ICMPv6");  break;
		default:                PRINT("Unknown"); break;
	}
	return _buffer;
}

const char* sprint_uuid(const void* data){
	const uint8_t* d = (uint8_t*)data;
	snprintf(
		_buffer,
		sizeof(_buffer),
		"%02x%02x%02x%02x-"
		"%02x%02x-"
		"%02x%02x-"
		"%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		d[0],d[1],d[2],d[3],
		d[4],d[5],
		d[6],d[7],
		d[8],d[9],
		d[10],d[11],d[12],d[13],d[14],d[15]
	);
	return _buffer;
}


uint16_t network_checksum(PACKET *pheader,PACKET *packet){
	uint32_t sum = 0x00;
	
	if (pheader) {
		uint16_t* ptr = (uint16_t*)pheader->data();
		size_t len = pheader->length() & ~0x01;

		while (len > 0x01) {
			sum += *ptr++;
			len -= 0x02;
		}
	}

	if (packet) {
		uint16_t* ptr = (uint16_t*)packet->data();
		size_t len = packet->length();

		while (len > 0x01) {
			sum += *ptr++;
			len -= 0x02;
		}

		if (len == 1) {
			sum += *(uint8_t*)ptr;
		}
	}

	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 0x10);

	uint16_t result = ~sum;
	return ((result & 0x00FF) << 0x08) | ((result & 0xFF00) >> 0x08);
}



void PACKET::write_domain_name(const char* s,uint16_t ptr_offset){
	size_t len = 0;
	if(s && (len = strlen(s))){
		len++;
	    size_t start = 0;

		for (size_t i = 0; i < len; ++i) {
			if(s[i] != '.' && s[i] != '\0') continue;
				
			size_t n = i - start;
			
			if (n > 0) {
				_data[_len++] = n;
				memcpy(_data + _len,s + start,n);
				_len += n;
			}
			
			start += n + 1;

			if (s[i] == '\0' && ptr_offset == (uint16_t)-1) {
				_data[_len++] = '\0';
			}
		}
	}
	if(ptr_offset != (uint16_t)-1){
		write_16(htons(0xC000 | (ptr_offset & 0x3FFFF)));
	}
}

const char* PACKET::read_domain_name(uint16_t offset,size_t pos){
	size_t pointer_depth = 0;
	size_t wpos = 0;
	size_t ptr_offset = 0;
	size_t* rptr = (pos < (size_t)-1) ? &pos : &_rpos;

	while(true){
		if(*rptr >= _len) break;

		uint8_t ll = _data[(*rptr)++];

		if((ll & 0xC0) == 0xC0){
			if(++pointer_depth > DNS_MAX_PTR_DEPTH) break;

			if(*rptr >= _len) break;
			
			ptr_offset = ((ll & DNS_LABEL_MASK_LENGTH) << 0x08) | _data[(*rptr)++];
			ptr_offset += offset;

			rptr = &ptr_offset;
			
			continue;
		}

		ll &= DNS_LABEL_MASK_LENGTH;

		if(!ll) break;

		if(*rptr + ll > _len) ll = _len - *rptr;


		if(wpos >= sizeof(_buffer) - 1 || wpos >= DNS_MAX_NAME_LENGTH) break;

		if (wpos > 0) _buffer[wpos++] = '.';

		if(wpos + ll >= DNS_MAX_NAME_LENGTH) ll = DNS_MAX_NAME_LENGTH - wpos;

		if (wpos + ll >= sizeof(_buffer) - 1) ll = sizeof(_buffer) - 1 - wpos;


		memcpy(_buffer + wpos,_data + *rptr,ll);

		wpos += ll;
		*rptr += ll;
	}

	_buffer[wpos] = '\0';

	return _buffer;
}


ETHERNET PACKET::unpack_ethernet(){
	ETHERNET ethernet;
	size_t len = MIN(_len,ETHERNET_HDR_LENGTH);
	ethernet.write(_data,len);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
	return ethernet;
}

void PACKET::unpack_ethernet_void(){
	size_t len = MIN(_len,ETHERNET_HDR_LENGTH);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
}


IPV4 PACKET::unpack_ipv4(){
	IPV4 ipv4;
	uint8_t hdr_length = (peek_8(0) & 0x0F) << 0x02;
	size_t len = MIN(_len,hdr_length);
	ipv4.write(_data,len);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
	return ipv4;
}

void PACKET::unpack_ipv4_void(){
	uint8_t hdr_length = (peek_8(0) & 0x0F) << 0x02;
	size_t len = MIN(_len,hdr_length);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
}


IPV6 PACKET::unpack_ipv6(){
	IPV6 ipv6;
	size_t len = MIN(_len,IPV6_HDR_LENGTH);
	ipv6.write(_data,len);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
	return ipv6;
}

void PACKET::unpack_ipv6_void(){
	size_t len = MIN(_len,IPV6_HDR_LENGTH);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
}


TCP PACKET::unpack_tcp(){
	TCP tcp;
	uint8_t hdr_length = (peek_8(12) >> 0x04) << 0x02;
	size_t len = MIN(_len,hdr_length);
	tcp.write(_data,len);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
	return tcp;
}

void PACKET::unpack_tcp_void(){
	uint8_t hdr_length = (peek_8(12) >> 0x04) << 0x02;
	size_t len = MIN(_len,hdr_length);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
}


UDP PACKET::unpack_udp(){
	UDP udp;
	size_t len = MIN(_len,UDP_HDR_LENGTH);
	udp.write(_data,len);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
	return udp;
}

void PACKET::unpack_udp_void(){
	size_t len = MIN(_len,UDP_HDR_LENGTH);
	_len -= len;
	memmove(_data,_data + len,_len);
	update_rpos();
}


const char* DHCPV6::sprint_msg_type(uint8_t type){
	switch(type){
		case DHCPV6_MSG_SOLICIT:             PRINT("Solicit");             break;
		case DHCPV6_MSG_ADVERTISE:           PRINT("Advertise");           break;
		case DHCPV6_MSG_REQUEST:             PRINT("Request");             break;
		case DHCPV6_MSG_CONFIRM:             PRINT("Confirm");             break;
		case DHCPV6_MSG_RENEW:               PRINT("Renew");               break;
		case DHCPV6_MSG_REBIND:              PRINT("Rebind");              break;
		case DHCPV6_MSG_REPLY:               PRINT("Reply");               break;
		case DHCPV6_MSG_RELEASE:             PRINT("Release");             break;
		case DHCPV6_MSG_DECLINE:             PRINT("Decline");             break;
		case DHCPV6_MSG_RECONFIGURE:         PRINT("Reconfigure");         break;
		case DHCPV6_MSG_INFORMATION_REQUEST: PRINT("Information Request"); break;
		case DHCPV6_MSG_RELAY_FORWARD:       PRINT("Relay Forward");       break;
		case DHCPV6_MSG_RELAY_REPLY:         PRINT("Relay Reply");         break;
		default:                             PRINT("Unknown");             break;
	}
	return _buffer;
}

const char* DHCPV6::sprint_option_code(uint16_t code){
	switch(code){
		case DHCPV6_OPT_CLIENTID:                 PRINT("Client ID"); break;
		case DHCPV6_OPT_SERVERID:                 PRINT("Server ID"); break;
		case DHCPV6_OPT_IA_NA:                    PRINT("IA Non-Temporary Addresses"); break;
		case DHCPV6_OPT_IA_TA:                    PRINT("IA Temporary Addresses"); break;
		case DHCPV6_OPT_IAADDR:                   PRINT("IA Address"); break;
		case DHCPV6_OPT_REQUEST:                  PRINT("Option Request"); break;
		case DHCPV6_OPT_ELAPSED_TIME:             PRINT("Elapsed Time"); break;
		case DHCPV6_OPT_STATUS_CODE:              PRINT("Status Code"); break;
		case DHCPV6_OPT_DNS_SERVERS:              PRINT("DNS Servers"); break;
		case DHCPV6_OPT_DOMAIN_LIST:              PRINT("Domain List"); break;
		case DHCPV6_OPT_IA_PD:                    PRINT("IA Prefix Delegation"); break;
		case DHCPV6_OPT_IA_PREFIX:                PRINT("IA Prefix"); break;
		case DHCPV6_OPT_SNTP_SERVERS:             PRINT("SNTP Servers"); break;
		case DHCPV6_OPT_INFORMATION_REFRESH_TIME: PRINT("Information Refresh Time"); break;
		case DHCPV6_OPT_NTP_SERVER:               PRINT("NTP Server"); break;
		case DHCPV6_OPT_INF_MAX_RT:               PRINT("INF_MAX_RT"); break;
		default:                                  PRINT("Unknown"); break;
	}
	return _buffer;
}

const char* DHCPV6::sprint_status_code(uint16_t code){
	switch(code){
		case DHCPV6_STATUS_SUCCESS:       PRINT("Success"); break;
		case DHCPV6_STATUS_UNSPECFAIL:    PRINT("UnspecFail"); break;
		case DHCPV6_STATUS_NOADDRSAVAIL:  PRINT("NoAddrsAvail"); break;
		case DHCPV6_STATUS_NOBINDING:     PRINT("NoBinding"); break;
		case DHCPV6_STATUS_NOTONLINK:     PRINT("NotOnLink"); break;
		case DHCPV6_STATUS_USEMULTICAST:  PRINT("UseMulticast"); break;
		case DHCPV6_STATUS_NOPREFIXAVAIL: PRINT("NoPrefixAvail"); break;
		default:                          PRINT("Unknown"); break;
	}
	return _buffer;
}

const char* DHCPV6::sprint_duid_type(uint16_t type){
	switch(type){
		case DUID_LLT:  PRINT("Link-Layer Address Plus Time");  break;
		case DUID_EN:   PRINT("Enterprise Number");             break;
		case DUID_LL:   PRINT("Link-Layer Address");            break;
		case DUID_UUID: PRINT("UUID");                          break;
		default:        PRINT("Unknown");                       break;
	}
	return _buffer;
}


const char* DNS::sprint_opcode(uint8_t code){
	switch(code){
		case OPCODE::QUERY:  PRINT("Query");                   break;
		case OPCODE::IQUERY: PRINT("IQuery");                  break;
		case OPCODE::STATUS: PRINT("Status");                  break;
		case OPCODE::NOTIFY: PRINT("Notify");                  break;
		case OPCODE::UPDATE: PRINT("Update");                  break;
		case OPCODE::DSO:    PRINT("DNS Stateful Operations"); break;
		default:             PRINT("Unknown");                 break;
	}
	return _buffer;
}

const char* DNS::sprint_rcode(uint8_t code){
	switch(code){
		case RCODE::NOERROR:  PRINT("No Error");            break;
		case RCODE::FORMERR:  PRINT("Format Error");        break;
		case RCODE::SERVFAIL: PRINT("Server Failure");      break;
		case RCODE::NXDOMAIN: PRINT("Non-Existent Domain"); break;
		case RCODE::NOIMP:    PRINT("Not Implemented");     break;
		case RCODE::REFUSED:  PRINT("Query Refused");       break;
		default:              PRINT("Unknown");             break;
	}
	return _buffer;
}

const char* DNS::sprint_type(uint16_t type){
	switch(type){
		case TYPE::A:    PRINT("A (host address)"); break;
		case TYPE::NS:   PRINT("NS (authoritative name server)"); break;
		case TYPE::AAAA: PRINT("AAAA (IP6 Address)"); break;
		default:         PRINT("Unknown"); break;
	}
	return _buffer;
}

const char* DNS::sprint_class(uint16_t _class){
	switch(_class){
		case CLASS::INTERNET: PRINT("Internet"); break;
		case CLASS::CSNET:    PRINT("CSNET");    break;
		case CLASS::CHAOS:    PRINT("Chaos");    break;
		case CLASS::HESIOD:   PRINT("Hesiod");   break;
		default:              PRINT("Unknown");  break;
	}
	return _buffer;
}
