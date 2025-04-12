#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>  // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <arpa/inet.h>   // For inet_ntoa()
#include <netinet/ip_icmp.h> // Add at the top
#include <pthread.h>
#include <pcap.h>
#include <nftables/libnftables.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <msgpack.h>

/* Global Variables */

// Multithread stuff
pthread_mutex_t lock;
pthread_cond_t cond;
int pauseCap = 0;

typedef struct {
    char src_ip[16];
    char dest_ip[16];
    char prot[10];
} Packet;

typedef struct {
    pcap_t* handle;
} pc_args;

typedef struct 
{

};

void* pc_thread(void* args)
{
    while(1)
    {
        pthread_mutex_lock(&lock);

        // If user input, pauseCap = 1
        if (pauseCap)
        {
            pthread_mutex_unlock(&lock);

            while(pauseCap)
                usleep(100000);

            pauseCap = 0;
            pthread_mutex_lock(&lock);
        }

        pthread_mutex_unlock(&lock);

        // Capture packets here

    }
}

// void* ui_thread(void* args)
// {
//     while(1)
//     {
//         // Wait for user input from connection
//         // If user input
//         if ()
//         {
//             pthread_mutex_lock(&lock);
//             pauseCap = 1;
//             pthread_cond_signal(&cond);
//             // Code for modifications
//             pthread_mutex_unlock(&lock);
//         }
//     }
// }
ui_args;

// Packet stuff
Packet packet_buffer1[1000];
Packet packet_buffer2[1000];

int pbuf_size = 0;
int pbuf_active = 0;
int logFile_counter = 0;

void serialize_packet(Packet *p, msgpack_packer *pk)
{
    msgpack_pack_map(pk, 3);  // 3 key-value pairs (src_ip, dst_ip, protocol)
    
    // src_ip
    msgpack_pack_str(pk, strlen("src_ip"));
    msgpack_pack_str_body(pk, "src_ip", strlen("src_ip"));
    msgpack_pack_str(pk, strlen(p->src_ip));
    msgpack_pack_str_body(pk, p->src_ip, strlen(p->src_ip));
    
    // dst_ip
    msgpack_pack_str(pk, strlen("dst_ip"));
    msgpack_pack_str_body(pk, "dst_ip", strlen("dst_ip"));
    msgpack_pack_str(pk, strlen(p->dest_ip));
    msgpack_pack_str_body(pk, p->dest_ip, strlen(p->dest_ip));
    
    // protocol
    msgpack_pack_str(pk, strlen("protocol"));
    msgpack_pack_str_body(pk, "protocol", strlen("protocol"));
    msgpack_pack_str(pk, strlen(p->prot));
    msgpack_pack_str_body(pk, p->prot, strlen(p->prot));
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) 
{
    Packet packet_info;

    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    printf("Packet captured: Length = %d bytes\n", pkthdr->len);

    // Extract IP header information
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    /* Convert IP in binary form to readable string */
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dest_ip);

    strcpy(packet_info.src_ip, src_ip);
    strcpy(packet_info.dest_ip, dest_ip);

    // Check the protocol type (TCP or UDP)
    if (ip_header->ip_p == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header
        /*
        printf("Protocol: TCP\n");
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport)); 
        */

        strcpy(packet_info.prot, "TCP");

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header
        /*
        printf("Protocol: UDP\n");
        printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
        */

        strcpy(packet_info.prot, "UDP");

    } if (ip_header->ip_p == IPPROTO_ICMP) {
        // printf("Protocol: ICMP (ping)\n");
        strcpy(packet_info.prot, "ICMP");
    } else {
        // printf("Protocol: Other\n");
        strcpy(packet_info.prot, "Other");
    }
    printf("-----------------------------\n");

    if (pbuf_active == 0)
    {
        packet_buffer1[pbuf_size] = packet_info;
    }
    else
    {
        packet_buffer2[pbuf_size] = packet_info;
    }
    pbuf_size++;
}

void *pb_thread(void* args)
{
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */

    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    while(1)
    {
        if (pbuf_size >= 30)
        {
            char file_name[32] = "./logs/packets";
            char temp[4];

            pbuf_active = ~pbuf_active;
            for (int i = 0; i < pbuf_size; i++)
            {
                serialize_packet(&packet_buffer1[i], &pk);
            }

            sprintf(temp, "%02d", logFile_counter);
            strcat(file_name, temp);
            strcat(file_name, ".msgpack");
            FILE *file = fopen(file_name, "wb");
            fwrite(sbuf.data, 1, sbuf.size, file);
            fclose(file);
            pbuf_size = 0;
            logFile_counter++;
            if (logFile_counter >= 4)
            {
                logFile_counter = 0;
            }
        }
    }
    msgpack_sbuffer_destroy(&sbuf);

}

void* pc_thread(void* args)
{
    pc_args* args_f = (pc_args*)args;

    while(1)
    {
        pthread_mutex_lock(&lock);

        // If user input, pauseCap = 1
        if (pauseCap)
        {
            pthread_mutex_unlock(&lock);

            while(pauseCap) {};

            pthread_mutex_lock(&lock);
        }

        pthread_mutex_unlock(&lock);

        // Capture packets here
        if (pcap_loop(args_f->handle, 1, packet_handler, NULL) < 0) 
        {
            printf("Error capturing packets: %s\n", pcap_geterr(args_f->handle));
            pcap_close(args_f->handle);
            exit(1);
        }
    }
}

void* ui_thread(void* args)
{
    struct timespec req, rem;
    req.tv_sec = 1;
    req.tv_nsec = 500000000L;

    while(1)
    {
        // Wait for user input from connection
        // If user input

        // sleep(5);

        // pthread_mutex_lock(&lock);
        // pauseCap = 1;
        // pthread_cond_signal(&cond);
        // // Code for modifications

        // nanosleep(&req, &rem);
        // printf("Modification made...\n");
        // nanosleep(&req, &rem);

        // pauseCap = 0;

        // pthread_mutex_unlock(&lock);
    }
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

    // For inputting IP address for ping command
    char ipaddr[256];
    char pingComm[256] = "ping -c 10 ";
    int ipaddrFound;
    int result;

    // Thread stuff
    pthread_t threads[3];
    int pcT, uiT, pbT;

    //nftables stuff
    struct nft_ctx *ctx;
    const char *cmd;
    
    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
    {
        fprintf(stderr,"nftables failed to creat");
    }

    //Tables
    const char *tables[] = 
    {
        "add table ip ipv4_table",       // IPv4 table
        "add table ip6 ipv6_table",      // IPv6 table
        "add table arp arp_table",       // ARP table
        "add table inet combined_table" // Combined IPv4/IPv6 table
    };

    for (int i = 0; i < 4; i++) 
    {
        cmd = tables[i];
        if (nft_run_cmd_from_buffer(ctx, cmd) < 0)
        {
            fprintf(stderr, "Failed to create table");
        } 
        else 
        {
            printf("Successfully created table: %s\n", cmd);
        }
    }

    //chains
    const char *chains[] = 
    {
        "add chain ip ipv4_table input_chain { type filter hook input priority 0; policy drop; }",
        "add chain ip6 ipv6_table input_chain { type filter hook input priority 0; policy accept; }",
        "add chain arp arp_table arp_chain { type filter hook input priority 0; policy accept; }",
        "add chain inet combined_table input_chain { type filter hook input priority 0; policy accept; }"
    };

    for (int i = 0; i < 4; i++) 
    {
        cmd = chains[i];
        if (nft_run_cmd_from_buffer(ctx, cmd) < 0)
        {
            fprintf(stderr, "Failed to create chain");
        } 
        else 
        {
            printf("Successfully created chain: %s\n", cmd);
        }
    }
    //rules
    const char *rules[] = {
        "add rule ip ipv4_table input_chain ip saddr 192.168.1.0/24 accept",
        "add rule ip6 ipv6_table input_chain ip6 saddr fe80::/10 accept",
        "add rule arp arp_table arp op request accept",
        "add rule inet combined_table input_chain ct state established,related accept"
    };
    for (int i = 0; i < 4; i++) 
    {
        cmd = rules[i];
        if (nft_run_cmd_from_buffer(ctx, cmd) < 0)
        {
            fprintf(stderr, "Failed to add rule");
        } 
        else 
        {
            printf("Successfully added rule: %s\n", cmd);
        }
    }

    int pcT, uiT;
    pc_args pcArg;


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

    pcArg.handle = handle;
    pcT = pthread_create(&threads[0], NULL, pc_thread, &pcArg);
    uiT = pthread_create(&threads[1], NULL, ui_thread, NULL);
    pbT = pthread_create(&threads[2], NULL, pb_thread, NULL);

    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    pthread_join(threads[2], NULL);

    pcap_close(handle);
    return 0;
}