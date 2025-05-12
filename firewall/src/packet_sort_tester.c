
#include <stdio.h>
#include "./libs/packet_sort.h"

// gcc packet_sort_tester.c libs/packet_sort.c -o exe -lmsgpackc

int main()
{
    int protCount = 0;
    char* prot_filter = "protocol";
    char* prot = "TCP";

    int dest_ipCount = 0;
    char* dest_ipFilter = "dst_ip";
    char* dest_ip = "0.0.0.0";

    int src_ipCount = 0;
    char* src_ipFilter = "src_ip";
    char* src_ip = "0.0.0.0";

    filter_packets("./logs/packets00.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets01.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets02.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets03.msgpack", prot_filter, prot, &protCount);
    printf("\nNumber of %s Protocols: %d\n", prot, protCount);

    filter_packets("./logs/packets00.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets01.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets02.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets03.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    printf("\nNumber of %s Destination IPs: %d\n", dest_ip, dest_ipCount);

    filter_packets("./logs/packets00.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets01.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets02.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets03.msgpack", src_ipFilter, src_ip, &src_ipCount);
    printf("\nNumber of %s Source IPs: %d\n", src_ip, src_ipCount);

    return 0;
}