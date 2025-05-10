
#ifndef PACKET_SORT
#define PACKET_SORT

typedef struct {
    char src_ip[16];
    char dest_ip[16];
    char prot[10];
} Packet;

void filter_packets(char* filename, char* filter, char* value, int* packet_num);

#endif