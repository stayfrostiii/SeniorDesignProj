#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>  // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <arpa/inet.h>   // For inet_ntoa()
#include <pcap.h>

struct packetInfo
{
    
};

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    printf("Packet captured: Length = %d bytes\n", pkthdr->len);

    // Extract IP header information
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
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
    } else {
        printf("Protocol: Other\n");
    }
    printf("-----------------------------\n");
}

int main() {

    char ipaddr[256];
    char pingComm[256] = "ping -c 10 ";
    int ipaddrFound;
    int result;

    ipaddrFound = 0;

    while (ipaddrFound == 0)
    {
        printf("Enter IP address: ");
        scanf("%255s", ipaddr);
        strcat(pingComm, ipaddr);
        strcat(pingComm, " &");
        printf("\nrunning: %s\n", pingComm);
        result = system(pingComm);

        if (result == 0) 
            ipaddrFound = 1;

        else 
            printf("Ping command failed.\n");
    }

    char *dev = pcap_lookupdev(NULL); // Get the default network device
    if (dev == NULL) {
        printf("Error: %s\n", pcap_geterr(NULL));
        return -1;
    }
    
    printf("Device: %s\n", dev);
    
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, NULL); // Open device for capturing packets
    if (handle == NULL) {
        printf("Error opening device: %s\n", pcap_geterr(handle));
        return -1;
    }

    // Capture 10 packets and process them using packet_handler
    if (pcap_loop(handle, 10, packet_handler, NULL) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    pcap_close(handle); // Close the pcap handle
    return 0;
}