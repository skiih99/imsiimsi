#pragma once
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

#define Ethhdr_Len 14
#define Arphdr_Len 28

uint32_t parse_ip(char* addr);
void get_attacker_ip(char* ipaddr,  char* dev);
void get_attacker_mac(char* macaddr, char* dev);
void check_sender_mac(char* senderip, char* sendermac, char* attip, char* attmac, pcap_t* handle);
void send_arp_reply(uint32_t senderip, uint8_t* sendermac, uint32_t targip, uint8_t* attmac, pcap_t* handle);

struct EthHeader {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ArpHeader {
    uint16_t hwtype;
    uint16_t prottype;
    uint8_t  hwlen;
	uint8_t  protlen;
    uint16_t OP;
    uint8_t smac[6];
    uint32_t sip;
    uint8_t tmac[6];
    uint32_t tip;
};

struct ArpPacket {
    struct EthHeader eh_field;
    struct ArpHeader ah_field;
};