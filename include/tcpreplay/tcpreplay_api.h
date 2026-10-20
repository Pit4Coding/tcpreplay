#ifndef TCPREPLAY_API_H
#define TCPREPLAY_API_H

#include <stdint.h>

#if defined(_WIN32) && !defined(TCPREPLAY_STATIC)
#  if defined(TCPREPLAY_EXPORTS)
#    define TCPREPLAY_API __declspec(dllexport)
#  else
#    define TCPREPLAY_API __declspec(dllimport)
#  endif
#else
#  define TCPREPLAY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tcpreplay_context tcpreplay_context;

typedef enum tcpreplay_speed_mode {
    TCPREPLAY_SPEED_CAPTURE = 0,
    TCPREPLAY_SPEED_TOP = 1,
    TCPREPLAY_SPEED_PPS = 2,
    TCPREPLAY_SPEED_MBPS = 3,
    TCPREPLAY_SPEED_MULTIPLIER = 4
} tcpreplay_speed_mode;

typedef enum tcpreplay_timer_mode {
    TCPREPLAY_TIMER_HYBRID = 0,
    TCPREPLAY_TIMER_SELECT = 1,
    TCPREPLAY_TIMER_GTOD = 2,
    TCPREPLAY_TIMER_NANO = 3,
    TCPREPLAY_TIMER_IOPORT = 4
} tcpreplay_timer_mode;

typedef struct tcpreplay_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t failed;
    uint64_t processed;
    uint64_t loops_completed;
    double elapsed_seconds;
    double packets_per_second;
    double megabits_per_second;
    int running;
    int stopped;
} tcpreplay_stats;

/* Lifecycle. A context must not be destroyed while tcpreplay_run() is active. */
TCPREPLAY_API tcpreplay_context* tcpreplay_create(void);
TCPREPLAY_API void tcpreplay_destroy(tcpreplay_context* context);
TCPREPLAY_API const char* tcpreplay_version(void);

/* Configuration. Call before tcpreplay_run(). */
TCPREPLAY_API int tcpreplay_add_pcap(tcpreplay_context* context, const char* path);
TCPREPLAY_API int tcpreplay_set_interface(tcpreplay_context* context, const char* name);
TCPREPLAY_API int tcpreplay_set_output_pcap(tcpreplay_context* context, const char* path);
TCPREPLAY_API int tcpreplay_set_speed(tcpreplay_context* context, tcpreplay_speed_mode mode, double value);
TCPREPLAY_API int tcpreplay_set_timer(tcpreplay_context* context, tcpreplay_timer_mode mode);
TCPREPLAY_API int tcpreplay_set_loop(tcpreplay_context* context, uint64_t count);
TCPREPLAY_API int tcpreplay_set_limit(tcpreplay_context* context, uint64_t packets);
TCPREPLAY_API int tcpreplay_set_duration(tcpreplay_context* context, double seconds);

/* Synchronous replay. Use tcpreplay_stop() safely from another thread. */
TCPREPLAY_API int tcpreplay_run(tcpreplay_context* context);
TCPREPLAY_API void tcpreplay_stop(tcpreplay_context* context);
TCPREPLAY_API int tcpreplay_get_stats(const tcpreplay_context* context, tcpreplay_stats* stats);
TCPREPLAY_API const char* tcpreplay_last_error(const tcpreplay_context* context);

#ifdef __cplusplus
}
#endif

#endif
