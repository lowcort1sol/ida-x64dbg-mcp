#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static int debugger_present(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

static int timing_suspicious(void) {
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    LARGE_INTEGER freq;
    volatile DWORD spin = 0;

    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&start)) {
        return 0;
    }

    for (DWORD i = 0; i < 500000; ++i) {
        spin ^= i;
    }

    if (!QueryPerformanceCounter(&end)) {
        return 0;
    }

    return ((end.QuadPart - start.QuadPart) * 1000LL / freq.QuadPart) > 150 ? 1 : 0;
}

int main(void) {
    puts("anti_debug_demo");

    if (debugger_present()) {
        puts("debugger detected");
    } else {
        puts("no debugger flag");
    }

    if (timing_suspicious()) {
        puts("timing anomaly");
    } else {
        puts("timing normal");
    }

    puts("analysis complete");
    return 0;
}
