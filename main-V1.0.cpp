#include <pcap.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <algorithm>
#include <queue>
#include <mutex>
#include <vector>

// -----------------------------
// STRUCT PACKET
// -----------------------------
struct Packet
{
    std::vector<u_char> data;
    int len;
    timeval ts;
};

// -----------------------------
// GLOBAL QUEUE
// -----------------------------
std::queue<Packet> packetQueue;
std::mutex queueMutex;
bool doneReading = false;

// -----------------------------
// SHOW INTERFACES
// -----------------------------
void showInterfaces()
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << errbuf << std::endl;
        return;
    }

    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next)
    {
        std::cout << "[" << i++ << "] " << d->name;
        if (d->description)
            std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);
}

// -----------------------------
// GET INTERFACE BY INDEX
// -----------------------------
std::string getInterfaceByIndex(int index)
{
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return "";

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

// -----------------------------
// READER THREAD
// -----------------------------
void readerThread(const char* filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);

    if (!pcap)
    {
        std::cerr << "Erreur lecture pcap: " << errbuf << std::endl;
        doneReading = true;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    while (pcap_next_ex(pcap, &header, &data) >= 0)
    {
        Packet pkt;
        pkt.len = header->caplen;
        pkt.data.assign(data, data + header->caplen);
        pkt.ts = header->ts;

        std::lock_guard<std::mutex> lock(queueMutex);
        packetQueue.push(std::move(pkt));
    }

    doneReading = true;
    pcap_close(pcap);
}

// -----------------------------
// SENDER THREAD
// -----------------------------
void senderThread(pcap_t* dev, bool topspeed, bool showDelta)
{
    timeval last_ts = { 0, 0 };
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

        // ---- TIMING PCAP ----
        if (!topspeed && last_ts.tv_sec != 0)
        {
            long sec = pkt.ts.tv_sec - last_ts.tv_sec;
            long usec = pkt.ts.tv_usec - last_ts.tv_usec;

            if (usec < 0)
            {
                usec += 1000000;
                sec--;
            }

            std::this_thread::sleep_for(
                std::chrono::seconds(sec) +
                std::chrono::microseconds(usec));
        }

        last_ts = pkt.ts;

        // ---- DELTA TEMPS REEL ----
        auto now = std::chrono::high_resolution_clock::now();

        if (showDelta)
        {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(now - last_send).count();
            std::cout << "Delta send: " << delta << " us" << std::endl;
        }

        last_send = now;

        // ---- SEND ----
        pcap_sendpacket(dev, pkt.data.data(), pkt.len);
    }
}

// -----------------------------
// MAIN
// -----------------------------
int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage:\n";
        std::cout << "  --showinterfaces\n";
        std::cout << "  <iface_index|name> <file.pcap> [--topspeed] [--show-delta]\n";
        return 1;
    }

    // ---- show interfaces ----
    if (std::string(argv[1]) == "--showinterfaces")
    {
        showInterfaces();
        return 0;
    }

    if (argc < 3)
    {
        std::cerr << "Usage: replay.exe <iface> <file> [--topspeed] [--show-delta]\n";
        return 1;
    }

    std::string ifaceArg = argv[1];
    std::string devName;

    // ---- interface selection ----
    if (std::all_of(ifaceArg.begin(), ifaceArg.end(), ::isdigit))
    {
        devName = getInterfaceByIndex(std::stoi(ifaceArg));

        if (devName.empty())
        {
            std::cerr << "Index invalide\n";
            return 1;
        }
    }
    else
    {
        devName = ifaceArg;
    }

    const char* filename = argv[2];

    bool topspeed = false;
    bool showDelta = false;

    for (int i = 3; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--topspeed")
            topspeed = true;

        if (arg == "--show-delta")
            showDelta = true;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // ---- open interface ----
    pcap_t* dev = pcap_open_live(devName.c_str(), 65536, 1, 1, errbuf);
    if (!dev)
    {
        std::cerr << "Erreur interface: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Interface: " << devName << std::endl;
    std::cout << "Mode: " << (topspeed ? "TOPSPEED" : "TIMED") << std::endl;
    if (showDelta)
        std::cout << "Delta affiché (microsecondes)\n";

    // ---- threads ----
    std::thread reader(readerThread, filename);
    std::thread sender(senderThread, dev, topspeed, showDelta);

    reader.join();
    sender.join();

    pcap_close(dev);

    std::cout << "Replay terminé\n";
    return 0;
}