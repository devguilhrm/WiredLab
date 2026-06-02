#pragma once

#include <linux/filter.h>

/*
https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.5-RELEASE
*/


#define READH(v) (((uint32_t)(v)[0] << 0x08) | ((uint32_t)(v)[1] << 0x00))
#define READW(v) (((uint32_t)(v)[0] << 0x18) | ((uint32_t)(v)[1] << 0x10) | ((uint32_t)(v)[2] << 0x08) | ((uint32_t)(v)[3] << 0x00))

#define ETHERNET_DST_OFFSET 0
#define ETHERNET_SRC_OFFSET 6
#define ETHERNET_TYPE_OFFSET 12
#define ETHERNET_HDR_LENGTH 14

#define ARP_HARDWARE_TYPE_OFFSET 0
#define ARP_PROTOCOL_TYPE_OFFSET 2
#define ARP_HARDWARE_LENGTH_OFFSET 4
#define ARP_PROTOCOL_LENGTH_OFFSET 5
#define ARP_OPERATION_OFFSET 6
#define ARP_SENDER_HADDR_OFFSET 8
#define ARP_SENDER_IP_ADDRESS 14
#define ARP_TARGET_HADDR_OFFSET 18
#define ARP_TARGET_IP_ADDRESS 24

#define IPV4_IHL_OFFSET 0
#define IPV4_PROTOCOL_OFFSET 9

#define IPV6_PAYLOAD_LENGTH_OFFSET 4
#define IPV6_NEXT_HDR_OFFSET 6
#define IPV6_HOP_LIMIT_OFFSET 7
#define IPV6_SRC_ADDR_OFFSET 8
#define IPV6_DST_ADDR_OFFSET 24
#define IPV6_HDR_LENGTH 40

#define SRC_PORT_OFFSET 0
#define DST_PORT_OFFSET 2

#define ICMPV6_TYPE_OFFSET 0