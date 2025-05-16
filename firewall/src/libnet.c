#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>        // for NF_ACCEPT
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

// Callback function to process each packet
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);

    uint32_t id = ntohl(ph->packet_id);

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len >= 20) {
        struct iphdr *ip_header = (struct iphdr *)payload;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip));

        printf("Packet ID %u: %s -> %s, protocol: %u\n", id, src_ip, dst_ip, ip_header->protocol);
    }

    // Accept the packet (could use NF_DROP to drop)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("Binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("Closing library handle\n");
    nfq_close(h);

    return 0;
}