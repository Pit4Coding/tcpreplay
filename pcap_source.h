#pragma once

#include <pcap.h>
#include <cstddef>
#include <string>
#include <vector>

struct Packet {
    std::vector<unsigned char> bytes;
    timeval timestamp{};
    int output = 0;
};

bool preloadPcap(const std::string& name, std::vector<Packet>& packets, std::string& error, int output = 0);

class PacketSource {
public:
    virtual ~PacketSource() = default;
    virtual bool reset(std::string& error) = 0;
    virtual int next(Packet& packet, std::string& error) = 0;
};

class MemorySource final : public PacketSource {
public:
    explicit MemorySource(const std::vector<Packet>& packets);
    bool reset(std::string& error) override;
    int next(Packet& packet, std::string& error) override;
private:
    const std::vector<Packet>& packets_;
    size_t index_ = 0;
};

class FileSource final : public PacketSource {
public:
    explicit FileSource(const std::vector<std::string>& names);
    ~FileSource();
    bool reset(std::string& error) override;
    int next(Packet& packet, std::string& error) override;
private:
    void close();
    const std::vector<std::string>& names_;
    size_t index_ = 0;
    pcap_t* file_ = nullptr;
};

class DualFileSource final : public PacketSource {
public:
    explicit DualFileSource(const std::vector<std::string>& names);
    ~DualFileSource();
    bool reset(std::string& error) override;
    int next(Packet& packet, std::string& error) override;
private:
    void close();
    bool fill(int side, std::string& error);
    const std::vector<std::string>& names_;
    pcap_t* files_[2]{nullptr, nullptr};
    Packet pending_[2];
    bool ready_[2]{false, false};
    bool eof_[2]{false, false};
};
