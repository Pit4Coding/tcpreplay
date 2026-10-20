#define NOMINMAX
#define TCPREPLAY_EXPORTS
#include <tcpreplay/tcpreplay_api.h>

#include <pcap.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

namespace {
constexpr const char* kVersion = "4.6.0-win.2";

struct ApiContext {
    std::vector<std::string> inputs;
    std::string interface_name;
    std::string output_path;
    tcpreplay_speed_mode speed = TCPREPLAY_SPEED_CAPTURE;
    tcpreplay_timer_mode timer = TCPREPLAY_TIMER_HYBRID;
    double speed_value = 1.0;
    double duration = 0.0;
    uint64_t loops = 1;
    uint64_t limit = 0;
    std::atomic_bool stop_requested{false};
    std::atomic_bool running{false};
    std::atomic_bool stopped{false};
    std::atomic_uint64_t packets{0};
    std::atomic_uint64_t bytes{0};
    std::atomic_uint64_t failed{0};
    std::atomic_uint64_t processed{0};
    std::atomic_uint64_t loops_completed{0};
    std::atomic_int64_t started_ns{0};
    std::atomic_int64_t finished_ns{0};
    mutable std::mutex error_mutex;
    std::string error;
};

ApiContext* impl(tcpreplay_context* context) { return reinterpret_cast<ApiContext*>(context); }
const ApiContext* impl(const tcpreplay_context* context) { return reinterpret_cast<const ApiContext*>(context); }

int fail(ApiContext* context, const std::string& message) {
    if (context) {
        std::lock_guard<std::mutex> lock(context->error_mutex);
        context->error = message;
    }
    return -1;
}

bool configurable(ApiContext* context) {
    return context && !context->running.load(std::memory_order_acquire);
}

uint64_t capture_delta_us(const timeval& current, const timeval& previous) {
    const int64_t delta = (int64_t(current.tv_sec) - previous.tv_sec) * 1000000LL +
                          current.tv_usec - previous.tv_usec;
    return delta > 0 ? static_cast<uint64_t>(delta) : 0;
}

void wait_until(ApiContext* context, std::chrono::steady_clock::time_point target) {
    if (context->timer == TCPREPLAY_TIMER_SELECT) {
        while (!context->stop_requested && std::chrono::steady_clock::now() < target)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return;
    }
    if (context->timer == TCPREPLAY_TIMER_GTOD || context->timer == TCPREPLAY_TIMER_IOPORT) {
        while (!context->stop_requested && std::chrono::steady_clock::now() < target) SwitchToThread();
        return;
    }
    if (context->timer == TCPREPLAY_TIMER_NANO) {
        while (!context->stop_requested && std::chrono::steady_clock::now() < target) {}
        return;
    }
    while (!context->stop_requested) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= target) break;
        const auto remaining = target - now;
        if (remaining > std::chrono::milliseconds(2))
            std::this_thread::sleep_for(remaining - std::chrono::milliseconds(1));
        else
            SwitchToThread();
    }
}

double packet_delay(const ApiContext* context, uint32_t size, const timeval& timestamp,
                    const timeval* previous) {
    switch (context->speed) {
    case TCPREPLAY_SPEED_TOP: return 0.0;
    case TCPREPLAY_SPEED_PPS: return 1.0 / context->speed_value;
    case TCPREPLAY_SPEED_MBPS: return size * 8.0 / (context->speed_value * 1000000.0);
    case TCPREPLAY_SPEED_MULTIPLIER:
        return previous ? capture_delta_us(timestamp, *previous) / 1000000.0 / context->speed_value : 0.0;
    default:
        return previous ? capture_delta_us(timestamp, *previous) / 1000000.0 : 0.0;
    }
}

int64_t steady_nanoseconds() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}

extern "C" {

tcpreplay_context* tcpreplay_create(void) {
    return reinterpret_cast<tcpreplay_context*>(new (std::nothrow) ApiContext());
}

void tcpreplay_destroy(tcpreplay_context* context) { delete impl(context); }
const char* tcpreplay_version(void) { return kVersion; }

int tcpreplay_add_pcap(tcpreplay_context* context, const char* path) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (!path || !*path) return fail(c, "pcap path is empty");
    c->inputs.emplace_back(path);
    return 0;
}

int tcpreplay_set_interface(tcpreplay_context* context, const char* name) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (!name || !*name) return fail(c, "interface name is empty");
    c->interface_name = name;
    c->output_path.clear();
    return 0;
}

int tcpreplay_set_output_pcap(tcpreplay_context* context, const char* path) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (!path || !*path) return fail(c, "output pcap path is empty");
    c->output_path = path;
    c->interface_name.clear();
    return 0;
}

int tcpreplay_set_speed(tcpreplay_context* context, tcpreplay_speed_mode mode, double value) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (mode < TCPREPLAY_SPEED_CAPTURE || mode > TCPREPLAY_SPEED_MULTIPLIER)
        return fail(c, "invalid speed mode");
    if (mode != TCPREPLAY_SPEED_TOP && (!std::isfinite(value) || value <= 0.0))
        return fail(c, "speed value must be greater than zero");
    c->speed = mode;
    c->speed_value = value;
    return 0;
}

int tcpreplay_set_timer(tcpreplay_context* context, tcpreplay_timer_mode mode) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (mode < TCPREPLAY_TIMER_HYBRID || mode > TCPREPLAY_TIMER_IOPORT)
        return fail(c, "invalid timer mode");
    c->timer = mode;
    return 0;
}

int tcpreplay_set_loop(tcpreplay_context* context, uint64_t count) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    c->loops = count;
    return 0;
}

int tcpreplay_set_limit(tcpreplay_context* context, uint64_t packets) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    c->limit = packets;
    return 0;
}

int tcpreplay_set_duration(tcpreplay_context* context, double seconds) {
    auto* c = impl(context);
    if (!configurable(c)) return fail(c, "context is null or replay is running");
    if (!std::isfinite(seconds) || seconds < 0.0) return fail(c, "duration must be zero or positive");
    c->duration = seconds;
    return 0;
}

int tcpreplay_run(tcpreplay_context* context) {
    auto* c = impl(context);
    if (!c) return -1;
    bool expected = false;
    if (!c->running.compare_exchange_strong(expected, true)) return fail(c, "replay is already running");
    struct RunningGuard { ApiContext* c; ~RunningGuard(){ c->finished_ns=steady_nanoseconds(); c->running=false; } } guard{c};
    if (c->inputs.empty()) return fail(c, "no input pcap configured");
    if (c->interface_name.empty() && c->output_path.empty()) return fail(c, "no output interface or pcap configured");

    c->stop_requested = false; c->stopped = false; c->packets = 0; c->bytes = 0;
    c->failed = 0; c->processed = 0; c->loops_completed = 0;
    { std::lock_guard<std::mutex> lock(c->error_mutex); c->error.clear(); }
    const auto started = std::chrono::steady_clock::now();
    c->started_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(started.time_since_epoch()).count();
    c->finished_ns = c->started_ns.load();
    const auto deadline = c->duration > 0.0
        ? started + std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(c->duration))
        : std::chrono::steady_clock::time_point::max();

    char error[PCAP_ERRBUF_SIZE]{};
    pcap_t* output = nullptr;
    pcap_t* template_pcap = nullptr;
    pcap_dumper_t* dumper = nullptr;
    if (!c->output_path.empty()) {
        template_pcap = pcap_open_offline(c->inputs.front().c_str(), error);
        if (!template_pcap) return fail(c, error);
        dumper = pcap_dump_open(template_pcap, c->output_path.c_str());
        if (!dumper) { const std::string message=pcap_geterr(template_pcap); pcap_close(template_pcap); return fail(c, message); }
    } else {
        output = pcap_open_live(c->interface_name.c_str(), 65535, 0, 1, error);
        if (!output) return fail(c, error);
    }

    int status = 0;
    auto target = std::chrono::steady_clock::now();
    for (uint64_t loop=0; (c->loops==0 || loop<c->loops) && !c->stop_requested && status==0; ++loop) {
        timeval previous{}; bool has_previous=false; bool found_packet=false;
        for (const auto& path : c->inputs) {
            pcap_t* input = pcap_open_offline(path.c_str(), error);
            if (!input) { status=fail(c, std::string("cannot open ")+path+": "+error); break; }
            pcap_pkthdr* header=nullptr; const u_char* data=nullptr; int read=0;
            while (!c->stop_requested && (read=pcap_next_ex(input, &header, &data))==1) {
                if (!header->caplen) continue;
                found_packet=true;
                const double seconds=packet_delay(c, header->caplen, header->ts, has_previous?&previous:nullptr);
                target += std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(seconds));
                wait_until(c, std::min(target, deadline));
                if (c->stop_requested || std::chrono::steady_clock::now()>=deadline) break;
                ++c->processed;
                if (dumper) pcap_dump(reinterpret_cast<u_char*>(dumper), header, data);
                else if (pcap_sendpacket(output, data, static_cast<int>(header->caplen)) != 0) {
                    ++c->failed; status=fail(c, pcap_geterr(output)); break;
                }
                ++c->packets; c->bytes += header->caplen; previous=header->ts; has_previous=true;
                if (c->limit && c->processed>=c->limit) break;
            }
            if (read==-1 && status==0) status=fail(c, pcap_geterr(input));
            pcap_close(input);
            if (status!=0 || c->stop_requested || std::chrono::steady_clock::now()>=deadline ||
                (c->limit && c->processed>=c->limit)) break;
        }
        if (!found_packet && status==0) status=fail(c, "input capture contains no packets");
        if (found_packet) ++c->loops_completed;
        if (c->limit && c->processed>=c->limit) break;
    }
    if (dumper && pcap_dump_flush(dumper)!=0 && status==0) status=fail(c, "cannot flush output pcap");
    if (dumper) pcap_dump_close(dumper);
    if (template_pcap) pcap_close(template_pcap);
    if (output) pcap_close(output);
    c->stopped = c->stop_requested.load();
    return status;
}

void tcpreplay_stop(tcpreplay_context* context) { if (auto* c=impl(context)) c->stop_requested=true; }

int tcpreplay_get_stats(const tcpreplay_context* context, tcpreplay_stats* stats) {
    const auto* c=impl(context); if (!c || !stats) return -1;
    const int64_t start=c->started_ns.load();
    const int64_t end=c->running.load()?steady_nanoseconds():c->finished_ns.load();
    const double elapsed=start==0?0.0:std::max(0.0,(end-start)/1000000000.0);
    stats->packets=c->packets; stats->bytes=c->bytes; stats->failed=c->failed; stats->processed=c->processed;
    stats->loops_completed=c->loops_completed; stats->elapsed_seconds=elapsed;
    stats->packets_per_second=elapsed>0.0?stats->packets/elapsed:0.0;
    stats->megabits_per_second=elapsed>0.0?stats->bytes*8.0/elapsed/1000000.0:0.0;
    stats->running=c->running?1:0; stats->stopped=c->stopped?1:0;
    return 0;
}

const char* tcpreplay_last_error(const tcpreplay_context* context) {
    const auto* c=impl(context); if (!c) return "invalid context";
    std::lock_guard<std::mutex> lock(c->error_mutex);
    return c->error.c_str();
}
}
