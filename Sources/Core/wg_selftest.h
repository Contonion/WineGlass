#ifndef WG_SELFTEST_H
#define WG_SELFTEST_H

#include <stdbool.h>

// Runs built-in tests for the decoder, interpreter, and PE loader.
// Logs results to the console. Returns true if all tests pass.
// Run all tests including blink (for command-line testing on macOS)
bool wg_selftest_run(void);

// Run only safe tests — no blink VM creation (for iOS launch)
bool wg_selftest_run_safe(void);

#endif
