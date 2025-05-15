
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "./libs/packet_sort.h"

// gcc packet_sort_tester.c libs/packet_sort.c -o exe -lmsgpackc

int main()
{
    uint64_t protCount = 0;
    char* prot_filter = "protocol";
    char* prot = "UDP";

    uint64_t dest_ipCount = 0;
    char* dest_ipFilter = "dst_ip";
    char* dest_ip = "10.0.0.224";

    uint64_t src_ipCount = 0;
    char* src_ipFilter = "src_ip";
    char* src_ip = "10.0.0.224";

    filter_packets("./logs/packets00.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets01.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets02.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets03.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets04.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets05.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets06.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets07.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets08.msgpack", prot_filter, prot, &protCount);
    filter_packets("./logs/packets09.msgpack", prot_filter, prot, &protCount);
    printf("\nNumber of %s Protocols: %llu\n", prot, protCount);

    filter_packets("./logs/packets00.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets01.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets02.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets03.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets04.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets05.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets06.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets07.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets08.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    filter_packets("./logs/packets09.msgpack", dest_ipFilter, dest_ip, &dest_ipCount);
    printf("\nNumber of %s Destination IPs: %llu\n", dest_ip, dest_ipCount);

    filter_packets("./logs/packets00.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets01.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets02.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets03.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets04.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets05.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets06.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets07.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets08.msgpack", src_ipFilter, src_ip, &src_ipCount);
    filter_packets("./logs/packets09.msgpack", src_ipFilter, src_ip, &src_ipCount);
    printf("\nNumber of %s Source IPs: %llu\n", src_ip, src_ipCount);

    return 0;
}