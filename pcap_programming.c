#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "myheader.h"

/* 패킷 핸들링 하는 함수 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    /* Ethernet 헤더 출력 */
    printf("Ethernet Header>\n");
    printf("\tSrc MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("\tDst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* IP 패킷 확인 */
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethheader));

        /* IP 헤더 출력 */
        printf("IP Header>\n");
        printf("\tSrc IP: %s\n", inet_ntoa(ip_header->iph_sourceip));
        printf("\tDst IP: %s\n", inet_ntoa(ip_header->iph_destip));

        /* TCP 패킷 확인 */
        if (ip_header->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp_header = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip_header->iph_ihl * 4));

            /* TCP 헤더 출력 */
            printf("TCP Header>\n");
            printf("\tSrc Port: %d\n", ntohs(tcp_header->tcp_sport));
            printf("\tDst Port: %d\n", ntohs(tcp_header->tcp_dport));

            /* Message 출력 */
            const u_char *payload = (const u_char *)(packet + sizeof(struct ethheader) + (ip_header->iph_ihl * 4) + (TH_OFF(tcp_header) * 4));
            int payload_length = ntohs(ip_header->iph_len) - (ip_header->iph_ihl * 4) - (TH_OFF(tcp_header) * 4);

            printf("Message>\n\n");
            for (int i = 0; i < payload_length; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        }
    }

    printf("ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net;

    /* wsl, eth0 사용 */
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
