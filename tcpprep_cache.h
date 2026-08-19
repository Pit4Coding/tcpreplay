#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TcpprepCache {
    uint64_t packetCount = 0;
    std::vector<unsigned char> decisions;
};

bool loadTcpprepCache(const std::string& path, TcpprepCache& cache, std::string& error);
int tcpprepDirection(const TcpprepCache& cache, uint64_t packetNumber);
