#define NOMINMAX
#include "pcap_source.h"

#include <utility>

bool preloadPcap(const std::string& name, std::vector<Packet>& packets, std::string& error, int output) {
    char err[PCAP_ERRBUF_SIZE]{};
    pcap_t* file = pcap_open_offline(name.c_str(), err);
    if (!file) { error = err; return false; }
    pcap_pkthdr* header = nullptr;
    const u_char* bytes = nullptr;
    int result;
    while ((result = pcap_next_ex(file, &header, &bytes)) == 1)
        if (header->caplen) packets.push_back({{bytes, bytes + header->caplen}, header->ts, output});
    if (result == -1) error = pcap_geterr(file);
    pcap_close(file);
    return result != -1;
}

MemorySource::MemorySource(const std::vector<Packet>& packets) : packets_(packets) {}
bool MemorySource::reset(std::string&) { index_ = 0; return true; }
int MemorySource::next(Packet& packet, std::string&) {
    if (index_ >= packets_.size()) return 0;
    packet = packets_[index_++];
    return 1;
}

FileSource::FileSource(const std::vector<std::string>& names) : names_(names) {}
FileSource::~FileSource() { close(); }
void FileSource::close() { if (file_) { pcap_close(file_); file_ = nullptr; } }
bool FileSource::reset(std::string&) { close(); index_ = 0; return true; }
int FileSource::next(Packet& packet, std::string& error) {
    while (true) {
        if (!file_) {
            if (index_ >= names_.size()) return 0;
            char err[PCAP_ERRBUF_SIZE]{};
            file_ = pcap_open_offline(names_[index_].c_str(), err);
            if (!file_) { error = "Erreur de lecture de " + names_[index_] + ": " + err; return -1; }
            ++index_;
        }
        pcap_pkthdr* header = nullptr;
        const u_char* bytes = nullptr;
        int result = pcap_next_ex(file_, &header, &bytes);
        if (result == 1) {
            if (!header->caplen) continue;
            packet.bytes.assign(bytes, bytes + header->caplen);
            packet.timestamp = header->ts;
            packet.output = 0;
            return 1;
        }
        if (result == -1) { error = pcap_geterr(file_); close(); return -1; }
        close();
    }
}

DualFileSource::DualFileSource(const std::vector<std::string>& names) : names_(names) {}
DualFileSource::~DualFileSource() { close(); }
void DualFileSource::close() { for (auto& file : files_) if (file) { pcap_close(file); file = nullptr; } }
bool DualFileSource::reset(std::string& error) {
    close();
    for (int side = 0; side < 2; ++side) {
        char err[PCAP_ERRBUF_SIZE]{};
        files_[side] = pcap_open_offline(names_[side].c_str(), err);
        if (!files_[side]) { error = "Erreur de lecture de " + names_[side] + ": " + err; close(); return false; }
        ready_[side] = eof_[side] = false;
    }
    return true;
}
bool DualFileSource::fill(int side, std::string& error) {
    if (ready_[side] || eof_[side]) return true;
    pcap_pkthdr* header = nullptr;
    const u_char* bytes = nullptr;
    int result;
    while ((result = pcap_next_ex(files_[side], &header, &bytes)) == 1) {
        if (!header->caplen) continue;
        pending_[side] = {{bytes, bytes + header->caplen}, header->ts, side};
        ready_[side] = true;
        return true;
    }
    if (result == -1) { error = pcap_geterr(files_[side]); return false; }
    eof_[side] = true;
    return true;
}
int DualFileSource::next(Packet& packet, std::string& error) {
    if (!fill(0, error) || !fill(1, error)) return -1;
    if (!ready_[0] && !ready_[1]) return 0;
    int side;
    if (!ready_[1]) side = 0;
    else if (!ready_[0]) side = 1;
    else side = (pending_[0].timestamp.tv_sec < pending_[1].timestamp.tv_sec ||
        (pending_[0].timestamp.tv_sec == pending_[1].timestamp.tv_sec && pending_[0].timestamp.tv_usec <= pending_[1].timestamp.tv_usec)) ? 0 : 1;
    packet = std::move(pending_[side]);
    ready_[side] = false;
    return 1;
}
