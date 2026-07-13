# WineGlass blink patches

The x86→ARM64 emulator core (blink, github.com/jart/blink, ISC) is a vendored
dependency built from a local clone at `~/Developer/blink`. These files capture
the WineGlass-specific modifications to it so the full translator is reproducible
without committing to the upstream repo.

- `wineglass-blink.patch` — all source changes: Path A (inline-TLB software MMU),
  Path B (native linear memory / kSkew big-region), machine.c `WG_STOREWATCH`,
  tunables `kSkew`, SMC/reset/jit tweaks, etc.
- `config.h.ios` — the WineGlass build config (drop into the blink clone root).

## Apply
```
git clone https://github.com/jart/blink ~/Developer/blink
cd ~/Developer/blink
git apply "<WineGlass>/Vendor/blink/patches/wineglass-blink.patch"
cp "<WineGlass>/Vendor/blink/patches/config.h.ios" config.h.ios
```
Then build via `Tests/build_mac_window.sh` (add `WG_BUILD_PATHB=1` for Path B).
