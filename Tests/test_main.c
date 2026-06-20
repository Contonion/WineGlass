#include "wg_log.h"
#include "wg_selftest.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    wg_log_init();

    printf("WineGlass — x86-64 Translation Engine for iOS\n");
    printf("Running self-tests...\n\n");

    bool ok = wg_selftest_run();

    printf("\n%s\n", ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return ok ? 0 : 1;
}
