#pragma once
#include "athena.h"

struct ether_header
{
	uint8_t  dest[6];
	uint8_t  src[6];
	uint16_t type;
};

struct arp_header {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	uint8_t src_mac[6];
	uint8_t src_ip[4];
	uint8_t t_mac[6];
	uint8_t t_ip[4];
};