// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <netinet/in.h>
// #include <linux/netfilter.h>        // for NF_ACCEPT
// #include <libnetfilter_queue/libnetfilter_queue.h>
// #include <arpa/inet.h>
// #include <netinet/ip.h>

// // Callback function to process each packet
// static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
//               struct nfq_data *nfa, void *data)
// {
//     struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
//     if (!ph) return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);

//     uint32_t id = ntohl(ph->packet_id);

//     unsigned char *payload;
//     int payload_len = nfq_get_payload(nfa, &payload);

//     if (payload_len >= 20) {
//         struct iphdr *ip_header = (struct iphdr *)payload;
//         char src_ip[INET_ADDRSTRLEN];
//         char dst_ip[INET_ADDRSTRLEN];

//         inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
//         inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

//         printf("Packet ID %u: %s -> %s, protocol: %u\n", id, src_ip, dst_ip, ip_header->protocol);
//     }

//     // Accept the packet (could use NF_DROP to drop)
//     return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
// }

// int main()
// {
//     struct nfq_handle *h;
//     struct nfq_q_handle *qh;
//     int fd;
//     int rv;
//     char buf[4096] __attribute__ ((aligned));

//     printf("Opening library handle\n");
//     h = nfq_open();
//     if (!h) {
//         fprintf(stderr, "Error during nfq_open()\n");
//         exit(1);
//     }

//     printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
//     if (nfq_unbind_pf(h, AF_INET) < 0) {
//         fprintf(stderr, "Error during nfq_unbind_pf()\n");
//         exit(1);
//     }

//     printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
//     if (nfq_bind_pf(h, AF_INET) < 0) {
//         fprintf(stderr, "Error during nfq_bind_pf()\n");
//         exit(1);
//     }

//     printf("Binding this socket to queue '0'\n");
//     qh = nfq_create_queue(h, 0, &cb, NULL);
//     if (!qh) {
//         fprintf(stderr, "Error during nfq_create_queue()\n");
//         exit(1);
//     }

//     printf("Setting copy_packet mode\n");
//     if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
//         fprintf(stderr, "Can't set packet_copy mode\n");
//         exit(1);
//     }

//     fd = nfq_fd(h);

//     while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
//         nfq_handle_packet(h, buf, rv);
//     }

//     printf("Unbinding from queue 0\n");
//     nfq_destroy_queue(qh);

//     printf("Closing library handle\n");
//     nfq_close(h);

//     return 0;
// }

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <linux/netfilter.h>  // NF_ACCEPT, NF_DROP
#include <libnetfilter_queue/libnetfilter_queue.h>

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);

    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 1)  // no payload
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    // We'll try to detect IP version first (4 or 6)
    uint8_t version = payload[0] >> 4;

    if (version == 4) {
        // IPv4
        if (payload_len < (int)sizeof(struct iphdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        struct iphdr *ip4 = (struct iphdr *)payload;
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip4->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip4->daddr, dst_ip, sizeof(dst_ip));

        printf("IPv4 packet: %s -> %s, protocol: %u\n", src_ip, dst_ip, ip4->protocol);

        switch(ip4->protocol) {
            case IPPROTO_TCP:
                if (payload_len < (int)(ip4->ihl * 4 + sizeof(struct tcphdr)))
                    break;

                {
                    struct tcphdr *tcp = (struct tcphdr *)(payload + ip4->ihl * 4);
                    uint16_t src_port = ntohs(tcp->source);
                    uint16_t dst_port = ntohs(tcp->dest);
                    printf("TCP packet: src port %u, dst port %u\n", src_port, dst_port);

                    // Accept SSH (22), HTTP (80), HTTPS (443) immediately
                    if (dst_port == 22 || dst_port == 80 || dst_port == 443)
                        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                break;

            case IPPROTO_UDP:
                if (payload_len < (int)(ip4->ihl * 4 + sizeof(struct udphdr)))
                    break;

                {
                    struct udphdr *udp = (struct udphdr *)(payload + ip4->ihl * 4);
                    uint16_t src_port = ntohs(udp->source);
                    uint16_t dst_port = ntohs(udp->dest);
                    printf("UDP packet: src port %u, dst port %u\n", src_port, dst_port);
                    // You can add special handling for UDP ports here if needed
                }
                break;

            case IPPROTO_ICMP:
                printf("ICMP packet detected\n");
                // handle ICMP here if you want
                break;

            default:
                printf("Other IPv4 protocol: %u\n", ip4->protocol);
        }
    }
    else if (version == 6) {
        // IPv6
        if (payload_len < (int)sizeof(struct ip6_hdr))
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(dst_ip));

        printf("IPv6 packet: %s -> %s, next header: %u\n", src_ip, dst_ip, ip6->ip6_nxt);

        // ip6_nxt holds the next header protocol number
        switch(ip6->ip6_nxt) {
            case IPPROTO_TCP:
                if (payload_len < (int)(sizeof(struct ip6_hdr) + sizeof(struct tcphdr)))
                    break;

                {
                    struct tcphdr *tcp = (struct tcphdr *)(payload + sizeof(struct ip6_hdr));
                    uint16_t src_port = ntohs(tcp->source);
                    uint16_t dst_port = ntohs(tcp->dest);
                    printf("TCP packet: src port %u, dst port %u\n", src_port, dst_port);

                    if (dst_port == 22 || dst_port == 80 || dst_port == 443)
                        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                break;

            case IPPROTO_UDP:
                if (payload_len < (int)(sizeof(struct ip6_hdr) + sizeof(struct udphdr)))
                    break;

                {
                    struct udphdr *udp = (struct udphdr *)(payload + sizeof(struct ip6_hdr));
                    uint16_t src_port = ntohs(udp->source);
                    uint16_t dst_port = ntohs(udp->dest);
                    printf("UDP packet: src port %u, dst port %u\n", src_port, dst_port);
                }
                break;

            case IPPROTO_ICMPV6:
                printf("ICMPv6 packet detected\n");
                break;

            default:
                printf("Other IPv6 next header: %u\n", ip6->ip6_nxt);
        }
    }
    else {
        printf("Unknown IP version: %u\n", version);
    }

    // For all other packets or not matched cases, accept for now
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}