#define NOMINMAX
#include "packet_edit.h"

#include <winsock2.h>
#include <ws2tcpip.h>

namespace {
uint16_t read16(const unsigned char* p) { return uint16_t(p[0]) << 8 | p[1]; }
void write16(unsigned char* p, uint16_t value) { p[0] = static_cast<unsigned char>(value >> 8); p[1] = static_cast<unsigned char>(value); }
uint32_t checksumAdd(uint32_t sum, const unsigned char* data, size_t length) {
    while (length > 1) { sum += read16(data); data += 2; length -= 2; }
    if (length) sum += uint16_t(data[0]) << 8;
    return sum;
}
uint16_t checksumFinish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
}

void rewritePacket(std::vector<unsigned char>& bytes, const RewriteOptions& options) {
    if (bytes.size() < 14) return;
    size_t ipOffset = 14;
    uint16_t etherType = read16(bytes.data() + 12);
    while ((etherType == 0x8100 || etherType == 0x88a8) && bytes.size() >= ipOffset + 4) {
        etherType = read16(bytes.data() + ipOffset + 2);
        ipOffset += 4;
    }
    if (etherType != 0x0800 || bytes.size() < ipOffset + 20) return;
    unsigned char* ip = bytes.data() + ipOffset;
    size_t ihl = (ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || bytes.size() < ipOffset + ihl) return;
    uint16_t totalLength = read16(ip + 2);
    if (totalLength < ihl) return;
    bool requested = !options.sourceIp.empty() || !options.destinationIp.empty() || options.sourcePort >= 0 || options.destinationPort >= 0;
    uint16_t fragment = read16(ip + 6);
    if (requested && ((fragment & 0x3fff) != 0 || bytes.size() < ipOffset + totalLength)) return;
    if (!options.sourceIp.empty()) inet_pton(AF_INET, options.sourceIp.c_str(), ip + 12);
    if (!options.destinationIp.empty()) inet_pton(AF_INET, options.destinationIp.c_str(), ip + 16);
    write16(ip + 10, 0);
    write16(ip + 10, checksumFinish(checksumAdd(0, ip, ihl)));
    if (!requested) return;
    unsigned char protocol = ip[9];
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return;
    size_t transportLength = totalLength - ihl;
    unsigned char* transport = ip + ihl;
    if ((protocol == IPPROTO_TCP && transportLength < 20) || (protocol == IPPROTO_UDP && transportLength < 8)) return;
    if (options.sourcePort >= 0) write16(transport, static_cast<uint16_t>(options.sourcePort));
    if (options.destinationPort >= 0) write16(transport + 2, static_cast<uint16_t>(options.destinationPort));
    size_t checksumOffset = protocol == IPPROTO_TCP ? 16 : 6;
    write16(transport + checksumOffset, 0);
    uint32_t sum = checksumAdd(0, ip + 12, 8);
    sum += protocol;
    sum += static_cast<uint16_t>(transportLength);
    sum = checksumAdd(sum, transport, transportLength);
    uint16_t result = checksumFinish(sum);
    if (protocol == IPPROTO_UDP && result == 0) result = 0xffff;
    write16(transport + checksumOffset, result);
}
