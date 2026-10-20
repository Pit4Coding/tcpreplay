#include <tcpreplay/tcpreplay_api.h>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: libtcpreplay_cpp_example <interface|output.pcap> <input.pcap>\n";
        return 2;
    }
    tcpreplay_context* replay = tcpreplay_create();
    if (!replay) return 1;
    const std::string output = argv[1];
    int result = tcpreplay_add_pcap(replay, argv[2]);
    result |= output.size() >= 5 && output.substr(output.size()-5) == ".pcap"
        ? tcpreplay_set_output_pcap(replay, output.c_str())
        : tcpreplay_set_interface(replay, output.c_str());
    result |= tcpreplay_set_speed(replay, TCPREPLAY_SPEED_TOP, 0.0);
    if (result == 0) result = tcpreplay_run(replay);
    if (result != 0) std::cerr << tcpreplay_last_error(replay) << '\n';
    tcpreplay_stats stats{};
    tcpreplay_get_stats(replay, &stats);
    std::cout << stats.packets << " packets, " << stats.bytes << " bytes\n";
    tcpreplay_destroy(replay);
    return result == 0 ? 0 : 1;
}
