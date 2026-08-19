#define NOMINMAX
#include "rewrite_cli.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cerrno>
#include <cstdlib>

bool isRewriteOption(const std::string& option) {
    return option == "--src-ip" || option == "--dst-ip" || option == "--sport" || option == "--dport";
}

bool applyRewriteOption(const std::string& option, const std::string& value, RewriteOptions& rewrite, std::string& error) {
    if (option == "--src-ip" || option == "--dst-ip") {
        in_addr address{};
        if (inet_pton(AF_INET, value.c_str(), &address) != 1) { error = "adresse IPv4 invalide: " + value; return false; }
        if (option == "--src-ip") rewrite.sourceIp = value; else rewrite.destinationIp = value;
        return true;
    }
    if (option == "--sport" || option == "--dport") {
        if (value.empty() || value[0] == '-') { error = "port invalide: " + value; return false; }
        char* end = nullptr;
        errno = 0;
        unsigned long port = std::strtoul(value.c_str(), &end, 10);
        if (errno || !end || *end || port == 0 || port > 65535) { error = "port invalide: " + value; return false; }
        if (option == "--sport") rewrite.sourcePort = static_cast<int>(port); else rewrite.destinationPort = static_cast<int>(port);
        return true;
    }
    error = "option de reecriture inconnue: " + option;
    return false;
}
