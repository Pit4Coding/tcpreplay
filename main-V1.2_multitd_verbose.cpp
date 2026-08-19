#include <pcap.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <algorithm>
#include <queue>
#include <mutex>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iomanip>
#include <sstream>

std::string format_pcap_ts(const timeval& ts)
{
    std::time_t tt = ts.tv_sec;
    std::tm tm;
    localtime_s(&tm, &tt);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(6) << std::setfill('0') << ts.tv_usec;

    return oss.str();
}
std::string now_precise()
{
    auto tp = std::chrono::system_clock::now();
    auto s = std::chrono::time_point_cast<std::chrono::seconds>(tp);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(tp - s).count();

    std::time_t tt = std::chrono::system_clock::to_time_t(s);
    std::tm tm;
    localtime_s(&tm, &tt);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(6) << std::setfill('0') << us;

    return oss.str();
}

#pragma comment(lib, "ws2_32.lib")

// -----------------------------
// STRUCTURES RESEAU
// -----------------------------
#pragma pack(push, 1)

struct eth_header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct ip_header {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    uint32_t saddr;
    uint32_t daddr;
};

struct udp_header {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t crc;
};

struct EthernetHeader
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct IpHeader
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    uint32_t saddr;
    uint32_t daddr;
};

struct TcpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UdpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

#pragma pack(pop)

// -----------------------------
// CHECKSUM
// -----------------------------
uint16_t compute_checksum(uint16_t* data, int len)
{
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += *data++;
        len -= 2;
    }

    if (len)
        sum += *(uint8_t*)data;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

uint16_t compute_tcp_udp_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol,
    uint8_t* segment,
    int segment_len)
{
    struct
    {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.src = src_ip;
    pseudo.dst = dst_ip;
    pseudo.zero = 0;
    pseudo.proto = protocol;
    pseudo.len = htons(segment_len);

    std::vector<uint8_t> buffer(sizeof(pseudo) + segment_len);
    memcpy(buffer.data(), &pseudo, sizeof(pseudo));
    memcpy(buffer.data() + sizeof(pseudo), segment, segment_len);

    return compute_checksum((uint16_t*)buffer.data(), (int)buffer.size());
}

// -----------------------------
// PACKET
// -----------------------------
struct Packet
{
    std::vector<u_char> data;
    int len = 0;
    timeval ts{ 0, 0 };
};

// -----------------------------
std::queue<Packet> packetQueue;
std::mutex queueMutex;
bool doneReading = false;

// -----------------------------
// REWRITE CONFIG
// -----------------------------
bool rewriteSrc = false;
bool rewriteDst = false;
uint32_t newSrcIP = 0;
uint32_t newDstIP = 0;

// -----------------------------
// REWRITE FUNCTION
// -----------------------------
void rewritePacket(u_char* buffer, int len)
{
    if (len < sizeof(EthernetHeader)) return;

    EthernetHeader* eth = (EthernetHeader*)buffer;

    if (ntohs(eth->type) != 0x0800) return; // IPv4 only

    IpHeader* ip = (IpHeader*)(buffer + sizeof(EthernetHeader));
    int ip_len = (ip->ver_ihl & 0x0F) * 4;

    if (len < sizeof(EthernetHeader) + ip_len) return;

    if (rewriteSrc) ip->saddr = newSrcIP;
    if (rewriteDst) ip->daddr = newDstIP;

    // ---- IP checksum ----
    ip->crc = 0;
    ip->crc = compute_checksum((uint16_t*)ip, ip_len);

    uint8_t* l4 = buffer + sizeof(EthernetHeader) + ip_len;
    int l4_len = ntohs(ip->tlen) - ip_len;

    if (l4_len <= 0) return;

    // ---- TCP ----
    if (ip->proto == 6)
    {
        TcpHeader* tcp = (TcpHeader*)l4;
        tcp->checksum = 0;

        tcp->checksum = compute_tcp_udp_checksum(
            ip->saddr, ip->daddr, 6, (uint8_t*)tcp, l4_len);
    }

    // ---- UDP ----
    else if (ip->proto == 17)
    {
        UdpHeader* udp = (UdpHeader*)l4;

        // checksum UDP optionnel (0 = disabled)
        if (udp->checksum != 0)
        {
            udp->checksum = 0;
            udp->checksum = compute_tcp_udp_checksum(
                ip->saddr, ip->daddr, 17, (uint8_t*)udp, l4_len);
        }
    }
}

// -----------------------------
// THREADS
// -----------------------------
void readerThread(const char* filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);

    struct pcap_pkthdr* header;
    const u_char* data;

    while (pcap_next_ex(pcap, &header, &data) >= 0)
    {
        Packet pkt;
        pkt.len = header->caplen;
        pkt.data.assign(data, data + header->caplen);
        pkt.ts = header->ts;

        // ---- PARSE + LOG ----
        if (pkt.len >= sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header))
        {
            eth_header* eth = (eth_header*)pkt.data.data();

            if (ntohs(eth->type) == 0x0800) // IPv4
            {
                ip_header* ip = (ip_header*)(pkt.data.data() + 14);

                if (ip->proto == 17) // UDP
                {
                    udp_header* udp = (udp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));

                    char src_ip[16], dst_ip[16];
                    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
                    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

                    std::cout << "[PCAP " << format_pcap_ts(pkt.ts) << "] "
                        << "UDP "
                        << src_ip << ":" << ntohs(udp->sport)
                        << " -> "
                        << dst_ip << ":" << ntohs(udp->dport)
                        << " size=" << pkt.len
                        << std::endl;
                }
            }
        }

        // ---- QUEUE ----
        std::lock_guard<std::mutex> lock(queueMutex);
        packetQueue.push(std::move(pkt));
    }

    doneReading = true;
    pcap_close(pcap);
}

void senderThread(pcap_t* dev, bool showDelta)
{
    auto last_send = std::chrono::high_resolution_clock::now();

    while (!doneReading || !packetQueue.empty())
    {
        Packet pkt;

        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (packetQueue.empty())
                continue;

            pkt = std::move(packetQueue.front());
            packetQueue.pop();
        }

        // ---- REWRITE ----
        rewritePacket(pkt.data.data(), pkt.len);

        // ---- TIMESTAMP ----
        auto now = std::chrono::high_resolution_clock::now();

        if (showDelta)
        {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(now - last_send).count();
            std::cout << "Delta send: " << delta << " us" << std::endl;
        }

        last_send = now;

        // ---- PARSE PACKET ----
        if (pkt.len >= sizeof(eth_header) + sizeof(ip_header) + sizeof(udp_header))
        {
            eth_header* eth = (eth_header*)pkt.data.data();

            if (ntohs(eth->type) == 0x0800) // IPv4
            {
                ip_header* ip = (ip_header*)(pkt.data.data() + 14);

                if (ip->proto == 17) // UDP
                {
                    udp_header* udp = (udp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));

                    char src_ip[16], dst_ip[16];
                    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
                    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

                    std::cout << "[" << now_precise() << "] "
                        << "UDP "
                        << src_ip << ":" << ntohs(udp->sport)
                        << " -> "
                        << dst_ip << ":" << ntohs(udp->dport)
                        << " size=" << pkt.len
                        << std::endl;
                }
            }
        }

        // ---- SEND ----
        pcap_sendpacket(dev, pkt.data.data(), pkt.len);
    }
}
// -----------------------------
// GET INTERFACE BY INDEX
// -----------------------------
std::string getInterfaceByIndex(int index)
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Erreur récupération interfaces: " << errbuf << std::endl;
        return "";
    }

    int i = 0;
    std::string result;

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        if (i == index)
        {
            result = d->name;
            break;
        }
        i++;
    }

    pcap_freealldevs(alldevs);
    return result;
}
// -----------------------------
// SHOW INTERFACES
// -----------------------------
void showInterfaces()
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Erreur récupération interfaces: " << errbuf << std::endl;
        return;
    }

    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        std::cout << "[" << i++ << "] " << d->name;

        if (d->description)
            std::cout << " (" << d->description << ")";

        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
}
// -----------------------------
// MAIN
// -----------------------------
int main(int argc, char* argv[])
{
    bool showDelta = false;

    if (argc < 2)
    {
        std::cout << "Usage:\n";
        std::cout << "  --showinterfaces\n";
        std::cout << "  <iface_index|name> <file.pcap> [--src-ip X] [--dst-ip X]\n";
        return 1;
    }

    // ---- OPTION SHOW INTERFACES ----
    if (std::string(argv[1]) == "--showinterfaces")
    {
        showInterfaces();
        return 0;
    }
    if (argc < 3)
    {
        std::cout << "Usage:\n";
        std::cout << "  <iface> <file.pcap> [--src-ip X] [--dst-ip X]\n";
        return 1;
    }

    std::string ifaceArg = argv[1];
    std::string devName;

    // Si c’est un index
    if (std::all_of(ifaceArg.begin(), ifaceArg.end(), ::isdigit))
    {
        int index = std::stoi(ifaceArg);
        devName = getInterfaceByIndex(index);

        if (devName.empty())
        {
            std::cerr << "Index interface invalide\n";
            return 1;
        }
    }
    else
    {
        devName = ifaceArg;
    }

    const char* file = argv[2];

    for (int i = 3; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--src-ip" && i + 1 < argc)
        {
            rewriteSrc = true;
            InetPtonA(AF_INET, argv[++i], &newSrcIP);
        }

        if (arg == "--dst-ip" && i + 1 < argc)
        {
            rewriteDst = true;
            InetPtonA(AF_INET, argv[++i], &newDstIP);
        }
        if (arg == "--show-delta")
            showDelta = true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* dev = pcap_open_live(devName.c_str(), 65536, 1, 1, errbuf);
    if (!dev)
    {
        std::cerr << errbuf << std::endl;
        return 1;
    }

    std::thread r(readerThread, file);
    std::thread s(senderThread, dev, showDelta);

    r.join();
    s.join();

    pcap_close(dev);

    std::cout << "Replay terminé\n";
    return 0;
}