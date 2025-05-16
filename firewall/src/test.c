#include <pcap.h>
#include <stdio.h>

int main()
{
    pcap_if_t *allDevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;

    // Find all devices
    if (pcap_findalldevs(&allDevs, errbuf) != 0)
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Print all devices
    for (dev = allDevs; dev != NULL; dev = dev->next)
    {
        printf("%d. %s", ++i, dev->name);
        if (dev->description)
            printf(" - %s", dev->description);
        printf("\n");
    }

    if (i == 0)
    {
        printf("No interfaces found.\n");
    }

    // Free the device list
    pcap_freealldevs(allDevs);

    return 0;
}