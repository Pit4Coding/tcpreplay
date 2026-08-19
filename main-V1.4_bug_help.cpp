#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>


#pragma comment(lib, "ws2_32.lib")

// ===================== CONFIG =====================

struct Config
{
    std::string iface;
    int iface_index = -1;
    std::string src_ip;
    std::string dst_ip;
    int sport = -1;
    int dport = -1;
    bool log = false;
    bool showDelta = false;
    bool preload = false;
};

// ===================== HEADERS =====================

#pragma pack(push, 1)

struct tcp_header {
    uint16_t sport;
    uint16_t dport;
};

struct icmp_header {
    uint8_t type;
    uint8_t code;
};

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

#pragma pack(pop)


// ===================== TIME =====================

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

// ===================== CHECKSUM =====================

uint16_t checksum(uint16_t* buf, int nwords)
{
    uint32_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// ===================== REWRITE =====================

void rewritePacket(uint8_t* data, size_t len, const Config& cfg)
{
    if (len < sizeof(eth_header) + sizeof(ip_header))
        return;

    eth_header* eth = (eth_header*)data;
    if (ntohs(eth->type) != 0x0800)
        return;

    ip_header* ip = (ip_header*)(data + 14);

    // ---- IP rewrite ----
    if (!cfg.src_ip.empty())
        inet_pton(AF_INET, cfg.src_ip.c_str(), &ip->saddr);

    if (!cfg.dst_ip.empty())
        inet_pton(AF_INET, cfg.dst_ip.c_str(), &ip->daddr);

    // ---- UDP rewrite ----
    if (ip->proto == 17)
    {
        udp_header* udp = (udp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));

        if (cfg.sport != -1)
            udp->sport = htons(cfg.sport);

        if (cfg.dport != -1)
            udp->dport = htons(cfg.dport);
    }

    // ---- IP checksum ----
    ip->crc = 0;
    ip->crc = checksum((uint16_t*)ip, (ip->ver_ihl & 0x0F) * 2);
}

std::vector<std::vector<uint8_t>> preloadPcap(const char* filename)
{
    std::vector<std::vector<uint8_t>> packets;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);

    if (!pcap)
    {
        std::cerr << "Erreur ouverture pcap: " << errbuf << "\n";
        return packets;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    while (pcap_next_ex(pcap, &header, &data) >= 0)
    {
        packets.emplace_back(data, data + header->caplen);
    }

    pcap_close(pcap);

    std::cout << "Preload OK: " << packets.size() << " paquets en mémoire\n";

    return packets;
}

void logPacket(const std::vector<uint8_t>& pkt)
{
    eth_header* eth = (eth_header*)pkt.data();

    if (ntohs(eth->type) != 0x0800)
        return;

    ip_header* ip = (ip_header*)(pkt.data() + 14);

    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    std::cout << "[" << now_precise() << "] ";

    switch (ip->proto)
    {
    case 17:
    {
        udp_header* udp = (udp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));
        std::cout << "UDP " << src_ip << ":" << ntohs(udp->sport)
            << " -> " << dst_ip << ":" << ntohs(udp->dport);
        break;
    }
    case 6:
    {
        tcp_header* tcp = (tcp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));
        std::cout << "TCP " << src_ip << ":" << ntohs(tcp->sport)
            << " -> " << dst_ip << ":" << ntohs(tcp->dport);
        break;
    }
    case 1:
    {
        icmp_header* icmp = (icmp_header*)((uint8_t*)ip + ((ip->ver_ihl & 0x0F) * 4));
        std::cout << "ICMP " << src_ip << " -> " << dst_ip
            << " type=" << (int)icmp->type;
        break;
    }
    default:
        std::cout << "PROTO(" << (int)ip->proto << ")";
    }

    std::cout << " size=" << pkt.size() << "\n";
}

void replayMemory(const std::vector<std::vector<uint8_t>>& packets, pcap_t* dev, const Config& cfg)
{
    auto last_send = std::chrono::high_resolution_clock::now();

    for (auto& raw : packets)
    {
        std::vector<uint8_t> pkt = raw;

        rewritePacket(pkt.data(), pkt.size(), cfg);

        auto now = std::chrono::high_resolution_clock::now();

        if (cfg.showDelta)
        {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(now - last_send).count();
            std::cout << "Delta: " << delta << " us\n";
        }

        last_send = now;

        if (cfg.log)
            logPacket(pkt);

        if (pcap_sendpacket(dev, pkt.data(), pkt.size()) != 0)
        {
            std::cerr << "Send failed: " << pcap_geterr(dev) << "\n";
            break;
        }
    }
}



// ===================== REPLAY =====================

void replayPcap(const char* filename, pcap_t* dev, const Config& cfg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);

    struct pcap_pkthdr* header;
    const u_char* data;

    auto last_send = std::chrono::high_resolution_clock::now();

    while (pcap_next_ex(pcap, &header, &data) >= 0)
    {
        std::vector<uint8_t> pkt(data, data + header->caplen);

        rewritePacket(pkt.data(), pkt.size(), cfg);

        auto now = std::chrono::high_resolution_clock::now();

        if (cfg.showDelta)
        {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(now - last_send).count();
            std::cout << "Delta: " << delta << " us\n";
        }

        last_send = now;

        if (cfg.log)
            logPacket(pkt);

        if (pcap_sendpacket(dev, pkt.data(), pkt.size()) != 0)
        {
            std::cerr << "Send failed: " << pcap_geterr(dev) << "\n";
            break;
        }
    }

    pcap_close(pcap);
}

// ===================== ARG PARSER =====================

Config parseArgs(int argc, char* argv[])
{
    Config cfg;

    for (int i = 2; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--iface") cfg.iface = argv[++i];
        else if (arg == "--src-ip") cfg.src_ip = argv[++i];
        else if (arg == "--dst-ip") cfg.dst_ip = argv[++i];
        else if (arg == "--sport") cfg.sport = atoi(argv[++i]);
        else if (arg == "--dport") cfg.dport = atoi(argv[++i]);
        else if (arg == "--log") cfg.log = true;
        else if (arg == "--show-delta") cfg.showDelta = true;
        else if (arg == "--preload") cfg.preload = true;
        else if (arg == "--iface-index") cfg.iface_index = atoi(argv[++i]);
    }

    return cfg;
}

std::string getInterfaceByIndex(int index)
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error: " << errbuf << std::endl;
        return "";
    }

    int i = 0;
    std::string result;

    for (pcap_if_t* d = alldevs; d; d = d->next)
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

void listInterfaces()
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error: " << errbuf << std::endl;
        return;
    }

    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next)
    {
        std::cout << i++ << ": ";

        if (d->name)
            std::cout << d->name;

        if (d->description)
            std::cout << " (" << d->description << ")";

        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
}

// -----------------------------
// HELP
// -----------------------------
void showHelp()
{
    std::cout << "Usage:\n";
    std::cout << "  tcpreplay.exe --showinterfaces\n";
    std::cout << "  tcpreplay.exe <file.pcap> <iface_index|name> [options]\n\n";

    std::cout << "Options:\n";
    std::cout << "  --help                 Affiche cette aide\n";
    std::cout << "  --preload              pre-chargement des trames en mémoire avant envoi\n";
    std::cout << "  --show-interfaces       Liste les interfaces disponibles\n";
    std::cout << "  --src-ip <ip>          Reecrit l'IP source\n";
    std::cout << "  --dst-ip <ip>          Reecrit l'IP destination\n";
    std::cout << "  --show-delta           Affiche le temps entre envois (µs)\n\n";

    std::cout << "Exemples:\n";
    std::cout << "  tcpreplay.exe --showinterfaces\n";
    std::cout << "  tcpreplay.exe capture.pcap --iface-index 3 \n";
    std::cout << "  tcpreplay.exe capture.pcap --iface-index 3 --src-ip 192.168.1.10\n";
    std::cout << "  tcpreplay.exe capture.pcap --iface-index 3 --dst-ip 10.0.0.5 --show-delta\n";
}

bool checkNpcap()
{
    HMODULE h = LoadLibraryA("wpcap.dll");
    if (!h)
    {
        std::cerr << "[ERREUR] Npcap non installe (wpcap.dll introuvable)\n";
        std::cerr << "Installe Npcap: https://npcap.com\n";
        return false;
    }

    FreeLibrary(h);

    // Vérification fonctionnelle
    const char* version = pcap_lib_version();
    if (!version)
    {
        std::cerr << "[ERREUR] Npcap detecte mais non fonctionnel\n";
        return false;
    }

    std::cout << "[OK] Npcap: " << version << "\n";
    return true;
}

bool isAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}
bool checkInterfaces()
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "[ERREUR] Impossible de lister les interfaces: " << errbuf << "\n";
        return false;
    }

    int count = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
        count++;

    pcap_freealldevs(alldevs);

    if (count == 0)
    {
        std::cerr << "[ERREUR] Aucune interface detectee\n";
        return false;
    }

    std::cout << "[OK] " << count << " interfaces detectees\n";
    return true;
}
bool checkInterfaceOpen(const std::string& devName)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* dev = pcap_open_live(devName.c_str(), 65536, 1, 1000, errbuf);

    if (!dev)
    {
        std::cerr << "[ERREUR] Impossible d'ouvrir l'interface:\n";
        std::cerr << "  " << devName << "\n";
        std::cerr << "  " << errbuf << "\n";
        return false;
    }

    pcap_close(dev);
    return true;
}

// ===================== MAIN =====================

int main(int argc, char* argv[])
{
    std::cout << "=== TCPReplay Tool v1.1 Pierre FAURANT 2026===\n";

    // 1. Npcap
    if (!checkNpcap())
        return 1;

    // 2. Admin
    if (!isAdmin())
    {
        std::cerr << "[ERREUR] Le programme doit etre lance en mode administrateur\n";
        return 1;
    }

    // 3. Interfaces
    if (!checkInterfaces())
        return 1;

    if (argc < 2)
    {
        showHelp();
        return 0;
    }

    if (std::string(argv[1]) == "--help")
    {
        showHelp();
        return 0;
    }
    if (argc >= 2 && std::string(argv[1]) == "--show-interfaces")
    {
        listInterfaces();
        return 0;
    }
    if (argc < 3)
    {
        std::cout << "Usage: program <pcap> --iface <name> [options]\n";
        return 1;
    }

    const char* filename = argv[1];
    Config cfg = parseArgs(argc, argv);

    std::string iface_to_use;

    if (cfg.iface_index >= 0)
    {
        iface_to_use = getInterfaceByIndex(cfg.iface_index);

        if (iface_to_use.empty())
        {
            std::cerr << "Invalid interface index\n";
            return 1;
        }

        std::cout << "Using interface #" << cfg.iface_index
            << ": " << iface_to_use << std::endl;
    }
    else if (!cfg.iface.empty())
    {
        iface_to_use = cfg.iface;
    }
    else
    {
        std::cerr << "You must specify --iface or --iface-index\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* dev = pcap_open_live(iface_to_use.c_str(), 65536, 1, 1, errbuf);
    if (!dev)
    {
        std::cerr << "Error opening device: " << errbuf << "\n";
        return 1;
    }

    if (cfg.preload)
    {
        auto packets = preloadPcap(filename);

        if (packets.empty())
        {
            std::cerr << "Aucun paquet chargé\n";
            return 1;
        }

        replayMemory(packets, dev, cfg);
    }
    else
    {
        replayPcap(filename, dev, cfg);
    }

    pcap_close(dev);
    return 0;
}