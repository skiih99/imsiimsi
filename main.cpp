#include <stdio.h>
#include <pcap.h>
#include "send-arp.h"


void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp ens32 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0) {
		usage();
		return -1;
	}
    
    char sender_ip[50];
    char target_ip[50];
    char attack_ip[50];
    char sender_mac[20];
    char attack_mac[20];
    
    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
    if (handle == nullptr) {
        fprintf(stderr, "Device open error! %s return nullptr : %s\n", dev, errbuf);
        return -1;
    }
    
    get_attacker_ip(attack_ip, argv[1]);
    get_attacker_mac(attack_mac, argv[1]);
    
    int cnt = 1;
    while (1) {
        if (cnt == (argc / 2)) break;
        
        sender_ip = argv[cnt*2];
        target_ip = argv[cnt*2+1];
        check_sender_mac(sender_ip, sender_mac, attack_ip, attack_mac, handle);
        //send_arp_reply(sender_ip, sender_mac, target_ip, attack_mac, handle);
        printf("Success. Victim: %s\n", argv[cnt*2]);

        cnt++;
    }

    pcap_close(handle);    
}