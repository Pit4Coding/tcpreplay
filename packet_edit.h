#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct RewriteOptions {
    std::string sourceIp;
    std::string destinationIp;
    int sourcePort = -1;
    int destinationPort = -1;
};

void rewritePacket(std::vector<unsigned char>& bytes, const RewriteOptions& options);
