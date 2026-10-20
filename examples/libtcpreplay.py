"""Minimal ctypes example for libtcpreplay.dll."""
import ctypes
import pathlib
import sys


class Stats(ctypes.Structure):
    _fields_ = [
        ("packets", ctypes.c_uint64), ("bytes", ctypes.c_uint64),
        ("failed", ctypes.c_uint64), ("processed", ctypes.c_uint64),
        ("loops_completed", ctypes.c_uint64), ("elapsed_seconds", ctypes.c_double),
        ("packets_per_second", ctypes.c_double),
        ("megabits_per_second", ctypes.c_double),
        ("running", ctypes.c_int), ("stopped", ctypes.c_int),
    ]


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: libtcpreplay.py <interface|output.pcap> <input.pcap>")
    dll = ctypes.CDLL(str(pathlib.Path(__file__).resolve().parent / "libtcpreplay.dll"))
    dll.tcpreplay_create.restype = ctypes.c_void_p
    dll.tcpreplay_add_pcap.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    dll.tcpreplay_set_interface.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    dll.tcpreplay_set_output_pcap.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    dll.tcpreplay_set_speed.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_double]
    dll.tcpreplay_run.argtypes = [ctypes.c_void_p]
    dll.tcpreplay_get_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(Stats)]
    dll.tcpreplay_last_error.argtypes = [ctypes.c_void_p]
    dll.tcpreplay_last_error.restype = ctypes.c_char_p
    dll.tcpreplay_destroy.argtypes = [ctypes.c_void_p]

    replay = dll.tcpreplay_create()
    output, source = (value.encode() for value in sys.argv[1:])
    try:
        result = dll.tcpreplay_add_pcap(replay, source)
        setter = dll.tcpreplay_set_output_pcap if output.lower().endswith(b".pcap") else dll.tcpreplay_set_interface
        result |= setter(replay, output)
        result |= dll.tcpreplay_set_speed(replay, 1, 0.0)
        if result == 0:
            result = dll.tcpreplay_run(replay)
        if result != 0:
            raise RuntimeError(dll.tcpreplay_last_error(replay).decode(errors="replace"))
        stats = Stats()
        dll.tcpreplay_get_stats(replay, ctypes.byref(stats))
        print(f"{stats.packets} packets, {stats.bytes} bytes, {stats.packets_per_second:.2f} pps")
    finally:
        dll.tcpreplay_destroy(replay)


if __name__ == "__main__":
    main()
