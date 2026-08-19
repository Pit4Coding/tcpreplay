#define NOMINMAX
#include <pcap.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "packet_edit.h"
#include "pcap_source.h"

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {
constexpr const char* VERSION = "4.6.0-win.1";

struct Options {
    std::string input;
    std::string output;
    RewriteOptions rewrite;
    bool verbose = false;
};

void help() {
    std::cout
        << "tcprewrite version " << VERSION << " (Windows native)\n"
        << "Usage: tcprewrite.exe --infile <capture> --outfile <capture> [options]\n\n"
        << "  -i, --infile <fichier>   capture source\n"
        << "  -o, --outfile <fichier>  capture destination\n"
        << "      --src-ip <adresse>   reecrit l'adresse IPv4 source\n"
        << "      --dst-ip <adresse>   reecrit l'adresse IPv4 destination\n"
        << "      --sport <port>       reecrit le port TCP/UDP source\n"
        << "      --dport <port>       reecrit le port TCP/UDP destination\n"
        << "  -v, --verbose            affiche les paquets traites\n"
        << "  -V, --version            affiche la version\n"
        << "  -h, --help               affiche cette aide\n";
}

bool parsePort(const char* text, int& port) {
    if (!text || !*text || *text == '-') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(text, &end, 10);
    if (errno || !end || *end || value == 0 || value > 65535) return false;
    port = static_cast<int>(value);
    return true;
}

bool samePath(const std::string& left, const std::string& right) {
    char a[MAX_PATH]{}, b[MAX_PATH]{};
    if (!GetFullPathNameA(left.c_str(), MAX_PATH, a, nullptr) || !GetFullPathNameA(right.c_str(), MAX_PATH, b, nullptr)) return left == right;
    return _stricmp(a, b) == 0;
}

int parse(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> const char* {
            if (++i >= argc) { std::cerr << "Erreur: valeur manquante pour " << arg << "\n"; return nullptr; }
            return argv[i];
        };
        if (arg == "-h" || arg == "--help") { help(); return 1; }
        if (arg == "-V" || arg == "--version") { std::cout << "tcprewrite version " << VERSION << " (Windows native)\n"; return 1; }
        if (arg == "-v" || arg == "--verbose") { options.verbose = true; continue; }
        if (arg == "-i" || arg == "--infile") { auto value = next(); if (!value) return -1; options.input = value; continue; }
        if (arg == "-o" || arg == "--outfile") { auto value = next(); if (!value) return -1; options.output = value; continue; }
        if (arg == "--src-ip" || arg == "--dst-ip") {
            auto value = next(); if (!value) return -1; in_addr address{};
            if (inet_pton(AF_INET, value, &address) != 1) { std::cerr << "Erreur: adresse IPv4 invalide: " << value << "\n"; return -1; }
            if (arg == "--src-ip") options.rewrite.sourceIp = value; else options.rewrite.destinationIp = value;
            continue;
        }
        if (arg == "--sport" || arg == "--dport") {
            auto value = next(); if (!value) return -1; int port = -1;
            if (!parsePort(value, port)) { std::cerr << "Erreur: port invalide: " << value << "\n"; return -1; }
            if (arg == "--sport") options.rewrite.sourcePort = port; else options.rewrite.destinationPort = port;
            continue;
        }
        std::cerr << "Erreur: option inconnue: " << arg << "\n";
        return -1;
    }
    if (options.input.empty() || options.output.empty()) { std::cerr << "Erreur: --infile et --outfile sont obligatoires\n"; return -1; }
    if (samePath(options.input, options.output)) { std::cerr << "Erreur: les fichiers d'entree et de sortie doivent etre differents\n"; return -1; }
    return 0;
}
}

int main(int argc, char** argv) {
    Options options;
    int parsed = parse(argc, argv, options);
    if (parsed != 0) return parsed > 0 ? 0 : 1;

    char err[PCAP_ERRBUF_SIZE]{};
    pcap_t* input = pcap_open_offline(options.input.c_str(), err);
    if (!input) { std::cerr << "Erreur de lecture: " << err << "\n"; return 1; }
    pcap_dumper_t* output = pcap_dump_open(input, options.output.c_str());
    if (!output) { std::cerr << "Erreur de creation: " << pcap_geterr(input) << "\n"; pcap_close(input); return 1; }

    pcap_pkthdr* header = nullptr;
    const u_char* source = nullptr;
    uint64_t packets = 0;
    int result;
    while ((result = pcap_next_ex(input, &header, &source)) == 1) {
        std::vector<unsigned char> bytes(source, source + header->caplen);
        rewritePacket(bytes, options.rewrite);
        pcap_pkthdr rewritten = *header;
        pcap_dump(reinterpret_cast<u_char*>(output), &rewritten, bytes.data());
        ++packets;
        if (options.verbose) std::cout << "packet " << packets << ": " << bytes.size() << " octets\n";
    }
    bool ok = result != -1 && pcap_dump_flush(output) == 0;
    if (result == -1) std::cerr << "Erreur de lecture: " << pcap_geterr(input) << "\n";
    if (!ok && result != -1) std::cerr << "Erreur de finalisation du fichier PCAP\n";
    pcap_dump_close(output);
    pcap_close(input);
    if (ok) std::cout << packets << " packets written to " << options.output << "\n";
    return ok ? 0 : 1;
}
