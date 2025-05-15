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
#include <time.h>
#include <unistd.h>
#include <msgpack.h>
// #include <ndpi/ndpi_api.h>
#include <fcntl.h>  // For open()
#include <sys/mman.h>

// gcc src/pcap.c -o build/pcap -lpcap -lmsgpackc -lpthread -lnftables 

/* Global Variables */
int counter = 0;
// Packet capture stuff
struct ndpi_detection_module_struct *ndpi_module;
u_int32_t detection_tick_resolution = 1000;
// Multithread stuff
pthread_mutex_t lock;
pthread_cond_t cond;
int pauseCap = 0;

pthread_mutex_t pbuf_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t pbuf_cond = PTHREAD_COND_INITIALIZER;

typedef struct {
    char src_ip[16];
    char dest_ip[16];
    char prot[10];
    int src_port;
    int dest_port;
    char time[26];
} Packet;


typedef struct 
{
    volatile int status;
    Packet packet_info;
} smData;

typedef struct {
    pcap_t* handle;
} pc_args;

// Packet stuff
Packet packet_buffer1[20000];
Packet packet_buffer2[20000];

int pbuf_size = 0;
int pbuf_active = 0;
int logFile_counter = 0;

#define SHM_NAME "/my_shm"
#define SHM_SIZE 1024

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
    smData *data = (smData*)user_data;
    // printf("%d\n", data->status);

    struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;


    // printf("Packet captured: Length = %d bytes\n", pkthdr->len);

    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    char protocol[10] = "Other"; // Default protocol
    int src_port = 0, dest_port = 0;

    time_t now = time(NULL);
    strncpy(packet_info.time, ctime(&now), sizeof(packet_info.time));
    packet_info.time[sizeof(packet_info.time) - 1] = '\0';

    // Extract IP header information
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    strncpy(packet_info.src_ip, src_ip, INET_ADDRSTRLEN);
    strncpy(packet_info.dest_ip, dest_ip, INET_ADDRSTRLEN);

    packet_info.src_ip[INET_ADDRSTRLEN - 1] = '\0';
    packet_info.dest_ip[INET_ADDRSTRLEN - 1] = '\0';

    // Check the protocol type (TCP or UDP)
    if (ip_header->ip_p == IPPROTO_TCP) 
    {
        tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header
        
        // printf("Protocol: TCP\n");
        // printf("Source IP: %s\n", src_ip);
        // printf("Destination IP: %s\n", dest_ip); 
        printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_header->th_dport)); 

        packet_info.src_port = ntohs(tcp_header->th_sport);
        packet_info.dest_port = ntohs(tcp_header->th_dport);

        strncpy(packet_info.prot, "TCP", sizeof(packet_info.prot));
        packet_info.prot[sizeof(packet_info.prot)-1] = '\0';
    } 
    
    else if (ip_header->ip_p == IPPROTO_UDP) 
    {
        udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

        // printf("Protocol: UDP\n");
        // printf("Source IP: %s\n", src_ip);
        // printf("Destination IP: %s\n", dest_ip); 

        /*
        printf("Protocol: UDP\n");
        */
        printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
        

        packet_info.src_port = ntohs(udp_header->uh_sport);
        packet_info.dest_port = ntohs(udp_header->uh_dport);

        strncpy(packet_info.prot, "UDP", sizeof(packet_info.prot));
        packet_info.prot[sizeof(packet_info.prot)-1] = '\0';
    } 
    
    else if (ip_header->ip_p == IPPROTO_ICMP) 
    {
        icmp_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        // printf("Protocol: ICMP\n");
        // printf("Source IP: %s\n", src_ip);
        // printf("Destination IP: %s\n", dest_ip); 

        packet_info.src_port = ntohs(icmp_header->ih_sport);
        packet_info.dest_port = ntohs(icmp_header->ih_dport);

        strncpy(packet_info.prot, "ICMP", sizeof(packet_info.prot));
        packet_info.prot[sizeof(packet_info.prot)-1] = '\0';
    }

    else 
    {
        other_header = (struct icmphdr *)(packet + 14 + (ip_header->ip_hl << 2));
        // printf("Protocol: Other\n");

        // printf("Protocol: Other\n");
        // printf("Source IP: %s\n", src_ip);
        // printf("Destination IP: %s\n", dest_ip); 

        packet_info.src_port = 0;
        packet_info.dest_port = 0;

        strncpy(packet_info.prot, "Other", sizeof(packet_info.prot));
        packet_info.prot[sizeof(packet_info.prot)-1] = '\0';
    }
    /*
    if (payload && payload_length > 0) 
    {

        // Use nDPI to detect the protocol
        struct ndpi_flow_struct flow;
        memset(&flow, 0, sizeof(flow));

        // Process the packet and get the detected protocol
        ndpi_protocol detected_protocol = ndpi_detection_process_packet(ndpi_module, &flow, payload, payload_length, time(NULL), NULL);

        // Get the protocol ID from the detected_protocol struct
        u_int16_t protocol_id = ndpi_get_lower_proto(detected_protocol);

        // Get the protocol name using the protocol ID
        const char *protocol_name = ndpi_get_proto_name(ndpi_module, protocol_id);

        printf("Detected protocol: %s\n", protocol_name);

        // Detect malicious traffic
        if (strcmp(protocol_name, "Malware") == 0) 
        {
            printf("Warning: Malicious traffic detected from %s to %s\n", src_ip, dest_ip);
        }

        // Detect potential intrusion (e.g., large payloads)
        if (payload_length > 10000) 
        { 
            printf("Potential intrusion detected: Large payload size (%d bytes) from %s to %s\n", payload_length, src_ip, dest_ip);
        }
    }
    printf("-----------------------------\n");
*/
    pthread_mutex_lock(&pbuf_lock);

    /* Prevent overloading buffer array */
    if (pbuf_active == 0)
    {
        packet_buffer1[pbuf_size] = packet_info;
    }
    else
    {
        packet_buffer2[pbuf_size] = packet_info;
    }

    while (data->status != 0 && data->status != 2)
    {
        // Wait for status = 1 to write
    }

    data->packet_info = packet_info;
    data->status = 1;
    
    pbuf_size++;
    
    pthread_mutex_unlock(&pbuf_lock);  // Always unlock
    
    if (pbuf_size > 10000)
    {
        pthread_cond_signal(&pbuf_cond);  // Notify the waiting thread
    }

    if (counter % 1000 == 0)
        printf("%d\n", counter);
    counter++;

}

void *pb_thread(void* args)
{
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */

    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    while(1)
    {
        pthread_mutex_lock(&pbuf_lock);

        // Wait until the condition is met (pbuf_size > 10000)
        while (pbuf_size <= 10000)
        {
            pthread_cond_wait(&pbuf_cond, &pbuf_lock);
        }

        // At this point, pbuf_size > 10000

        // Do the rest of the processing
        char file_name[32] = "./logs/packets";
        char temp[4];

        pbuf_active = !pbuf_active;
        for (int i = 0; i < pbuf_size; i++)
        {
            serialize_packet(&packet_buffer1[i], &pk);
        }

        pbuf_size = 0;  // Reset pbuf_size

        sprintf(temp, "%02d", logFile_counter);
        strcat(file_name, temp);
        strcat(file_name, ".msgpack");

        FILE *file = fopen(file_name, "wb");
        fwrite(sbuf.data, 1, sbuf.size, file);
        fclose(file);

        logFile_counter++;
        if (logFile_counter > 9)
        {
            logFile_counter = 0;
        }

        // Unlock the mutex
        pthread_mutex_unlock(&pbuf_lock);
    }
    msgpack_sbuffer_destroy(&sbuf);
}

void* pc_thread(void* args)
{
    pc_args* args_f = (pc_args*)args;
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(1);
    }

    // Configure size
    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        perror("ftruncate");
        exit(1);
    }

    // Map memory
    smData *ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    ptr->status = 0;

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
        if (pcap_loop(args_f->handle, 1, packet_handler, (u_char *)ptr) < 0) 
        {
            printf("Error capturing packets: %s\n", pcap_geterr(args_f->handle));
            pcap_close(args_f->handle);
            exit(1);
        }
    }

    // Cleanup
    munmap(ptr, SHM_SIZE);
    close(shm_fd);
    shm_unlink(SHM_NAME);
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

    // Threads for Pipe
    pthread_t pipeT;

    int pcT, uiT, pbT;
    pc_args pcArg;

    /*
    // nDPI stuff
    ndpi_module = ndpi_init_detection_module(detection_tick_resolution);
    if (ndpi_module == NULL) 
    {
        fprintf(stderr, "Failed to initialize nDPI module\n");
        return -1;
    }*/

    /*
    // Set up protocol detection
    NDPI_PROTOCOL_BITMASK detection_bitmask;
    NDPI_BITMASK_SET_ALL(detection_bitmask); // Enable detection for all protocols
    ndpi_set_protocol_detection_bitmask2(ndpi_module, &detection_bitmask);*/

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

    pthread_join(threads[0], NULL);

    pcap_close(handle);
    return 0;
}