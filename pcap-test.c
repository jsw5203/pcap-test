#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "stc.h" 

void payload_print(const u_char* payload, int len) {
    for (int i = 0; i < len && i < 20; i++) { 
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}



int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
		printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth->ether_type) == 0x0800) { 
            struct libnet_ipv4_hdr* ipv4 = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            if (ipv4->ip_p == IPPROTO_TCP) { 
                struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((u_char*)ipv4 + (ipv4->ip_hl << 2));

                printf("SRC MAC: \n");
                for(int i = 0; i < 6; i++) printf("%02x:", eth->ether_shost[i]);
                printf("DST MAC: \n");
                for(int i = 0; i < 6; i++) printf("%02x:", eth->ether_dhost[i]);
                printf("\nSRC IP: %s\n", inet_ntoa(ipv4->ip_src));
                printf("DST IP: %s\n", inet_ntoa(ipv4->ip_dst));
                printf("SRC PORT: %d\n", ntohs(tcp->th_sport));
                printf("DST PORT: %d\n", ntohs(tcp->th_dport));

                const u_char* payload = (u_char*)tcp + (tcp->th_off << 2);
                int len = ntohs(ipv4->ip_len) - (ipv4->ip_hl << 2) - (tcp->th_off << 2);
                printf("Payload: ");
                if (len > 0) {
                    payload_print(payload, len);
                } else {
                    printf("there is no data\n");
                }

            }
        }
    }

    pcap_close(pcap);
    return 0;
}

