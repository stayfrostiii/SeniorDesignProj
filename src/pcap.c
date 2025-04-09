#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>  // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <arpa/inet.h>   // For inet_ntoa()
#include <netinet/ip_icmp.h> // Add at the top
#include <pcap.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    printf("Packet captured: Length = %d bytes\n", pkthdr->len);

    // Extract IP header information
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    /* Convert IP in binary form to readable string */
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    printf("Source IP: %s\n", source_ip);
    printf("Destination IP: %s\n", dest_ip);

    // Check the protocol type (TCP or UDP)
    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header
        printf("Protocol: TCP\n");
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header
        printf("Protocol: UDP\n");
        printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    } if (ip_header->ip_p == IPPROTO_ICMP) {
        printf("Protocol: ICMP (ping)\n");
    } else {
        printf("Protocol: Other\n");
    }
    printf("-----------------------------\n");
}

int main() 
{
    // Getting device
    pcap_if_t *allDevs;
    pcap_if_t dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Starting packet capture sesh
    pcap_t* handle;
    int activate;

    char ipaddr[256];
    char pingComm[256] = "ping -c 10 ";
    int ipaddrFound;
    int result;

    /* Finds all devices */
    if (pcap_findalldevs(&allDevs, errbuf) != 0)
    {
        printf("%s\n", errbuf);
        return -1;
    }

    /* Take the first device */
    dev = *allDevs;
    printf("%s\n", dev.name);

    /* Open capturing sesh */
    handle = pcap_create(dev.name, errbuf);
    if (handle == NULL)
    {
        printf("%s\n", errbuf);
        return -1;
    }

    pcap_freealldevs(allDevs);

    /* -------------------------------- */
    pcap_set_snaplen(handle, 65536);              // Max bytes per packet
    pcap_set_promisc(handle, 1);                  // Promiscuous mode
    pcap_set_timeout(handle, 1000);               // 1 second timeout    
    /* -------------------------------- */

    activate = pcap_activate(handle);
    if (activate != 0)
    {
        char* pcaperr = pcap_geterr(handle);
        if (activate < 0)
        {
            printf("Error activating handle: %s\n", pcaperr);
            return -1;
        }
        else
        {
            printf("Warning activating handle: %s\n", pcaperr);
        }
    }

    ipaddrFound = 0;

    while (ipaddrFound == 0)
    {
        printf("Enter IP address: ");
        scanf("%255s", ipaddr);
        strcat(pingComm, ipaddr);
        strcat(pingComm, " > /dev/null 2>&1 &");
        printf("\nrunning: %s\n", pingComm);
        result = system(pingComm);

        if (result == 0) 
            ipaddrFound = 1;

        else 
            printf("Ping command failed.\n");
    }

    if (pcap_loop(handle, -1, packet_handler, NULL) < 0) 
    {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle);
    return 0;
}