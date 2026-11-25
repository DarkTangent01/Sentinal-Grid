"""Process statistics helpers (memory), used by the ingest pipeline and by self-monitoring."""


def rss_mib() -> int:
    try:
        with open("/proc/self/status") as f:
            return next((int(line.split()[1]) // 1024 for line in f if line.startswith("VmRSS")), 0)
    except OSError:
        return 0


def release_memory() -> None:
    """Return freed memory to the OS after a backlog. CPython keeps freed blocks in its arenas and glibc keeps freed
    heap, so a parser that once buffered a ClickHouse stall stayed at that size; malloc_trim gives the pages back."""
    import ctypes
    import ctypes.util
    import gc
    gc.collect()
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")
        if hasattr(libc, "malloc_trim"):
            libc.malloc_trim(0)
    except OSError:
        pass
