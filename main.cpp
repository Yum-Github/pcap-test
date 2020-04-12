#include "pcap-test.h"


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // packet
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        typedef struct libnet_ethernet_hdr ethernet_mac;
        ethernet_mac *eth;
        eth = (ethernet_mac*)packet;

        typedef struct libnet_ipv4_hdr ipv4_ip;
        ipv4_ip *ip;
        ip = (ipv4_ip*)(packet + sizeof(ethernet_mac));

        typedef struct libnet_tcp_hdr tcp_port;
        tcp_port *tcp;
        tcp = (tcp_port*)(packet + ((*ip).ip_hl*4) + sizeof(ethernet_mac));

        if ((ntohs((*eth).ether_type) == ETHERTYPE_IP)&&((*ip).ip_p == IPPROTO_TCP))
        {
        printf("\n\nDst mac = %02x : %02x : %02x : %02x : %02x : %02x\n",
                   (*eth).ether_dhost[0], (*eth).ether_dhost[1], (*eth).ether_dhost[2],
                   (*eth).ether_dhost[3], (*eth).ether_dhost[4], (*eth).ether_dhost[5]);
        printf("Src mac = %02x : %02x : %02x : %02x : %02x : %02x\n",
                   (*eth).ether_shost[0], (*eth).ether_shost[1], (*eth).ether_shost[2],
                   (*eth).ether_shost[3], (*eth).ether_shost[4], (*eth).ether_shost[5]);

        printf("Dst IP = %u . %u . %u . %u\n",
                   (*ip).dst_IP[0], (*ip).dst_IP[1], (*ip).dst_IP[2], (*ip).dst_IP[3]);
        printf("Src IP = %u . %u . %u . %u\n",
                   (*ip).src_IP[0], (*ip).src_IP[1], (*ip).src_IP[2], (*ip).src_IP[3]);

        printf("Dst Port = %u\n", ntohs((*tcp).th_dport));
        printf("Src Port = %u\n", ntohs((*tcp).th_sport));

        uint8_t data = ntohs((*ip).ip_len) - ((*ip).ip_hl*4) - ((*tcp).th_off*4);
        const u_char *payload = packet + sizeof(ethernet_mac) + (*ip).ip_hl*4 + (*tcp).th_off*4;
        if(data >=1)
        {
            for(int i=1;i<=16;i++){
                printf(" %02x ", payload[i]);
            }
        }
        }
    }
    pcap_close(handle);
}
