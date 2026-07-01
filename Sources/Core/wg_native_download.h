#ifndef WG_NATIVE_DOWNLOAD_H
#define WG_NATIVE_DOWNLOAD_H

// Host-side, blocking HTTPS download. Fetches `url` and writes the body to
// `dest_path`. Returns 1 on success (HTTP 200 + file written), 0 otherwise.
//
// Used to bypass the guest's fragile in-emulator download reactor: when Steam
// looks for a client package that isn't on disk yet, the engine fetches it
// natively here (rock-solid: real NSURLSession over the host network) so Steam
// finds it already present and skips its own multi-threaded download.
//
// BLOCKS the calling thread until the download finishes. Only call it from the
// engine thread (never the UI main thread — iOS would watchdog-kill a long block
// there). Implemented in WGNativeDownload.m (Foundation/NSURLSession).
int wg_native_download(const char *url, const char *dest_path);

#endif
