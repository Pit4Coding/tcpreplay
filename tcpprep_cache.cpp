#include "tcpprep_cache.h"

#include <cstring>
#include <fstream>

namespace {
uint64_t read64be(const unsigned char* p) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
}

bool loadTcpprepCache(const std::string& path, TcpprepCache& cache, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) { error = "impossible d'ouvrir le cache " + path; return false; }
    unsigned char header[24]{};
    if (!file.read(reinterpret_cast<char*>(header), sizeof(header))) { error = "en-tete de cache tcpprep incomplet"; return false; }
    const unsigned char magic[8] = {'t','c','p','p','r','e','p',0};
    if (std::memcmp(header, magic, 8) != 0) { error = "fichier non reconnu comme cache tcpprep"; return false; }
    if (header[8] != '0' || header[9] != '4') { error = "version de cache tcpprep non prise en charge (version 04 requise)"; return false; }
    cache.packetCount = read64be(header + 12);
    uint16_t packetsPerByte = uint16_t(header[20]) << 8 | header[21];
    uint16_t commentLength = uint16_t(header[22]) << 8 | header[23];
    if (packetsPerByte != 4) { error = "cache tcpprep invalide: packets_per_byte doit valoir 4"; return false; }
    if (cache.packetCount > UINT64_MAX - 3) { error = "cache tcpprep trop volumineux"; return false; }
    file.seekg(commentLength, std::ios::cur);
    if (!file) { error = "commentaire de cache tcpprep tronque"; return false; }
    size_t bytes = static_cast<size_t>((cache.packetCount + 3) / 4);
    cache.decisions.resize(bytes);
    if (bytes && !file.read(reinterpret_cast<char*>(cache.decisions.data()), static_cast<std::streamsize>(bytes))) { error = "donnees de cache tcpprep tronquees"; return false; }
    char extra;
    if (file.read(&extra, 1)) { error = "donnees superflues apres le cache tcpprep"; return false; }
    return true;
}

int tcpprepDirection(const TcpprepCache& cache, uint64_t packetNumber) {
    if (packetNumber == 0 || packetNumber > cache.packetCount) return -1;
    uint64_t zero = packetNumber - 1;
    unsigned char byte = cache.decisions[static_cast<size_t>(zero / 4)];
    unsigned bit = static_cast<unsigned>((zero % 4) * 2 + 1);
    if (!(byte & (1u << bit))) return -1;
    return (byte & (1u << (bit - 1))) ? 0 : 1;
}
