// wg_openssl_shim.h — Route Steam's statically-linked OpenSSL TLS through Apple
// SecureTransport, bypassing OpenSSL's crypto (which mis-builds the ClientHello
// under blink's 32-bit interpreter: no ECDHE ciphers, P-521-only curves).
//
// Steam's COpenSSLConnection uses OpenSSL with memory BIOs and pumps ciphertext
// between the socket and the BIOs itself:
//   recv(socket) -> BIO_write(rbio)  ; SSL_do_handshake reads rbio, writes wbio
//   BIO_read(wbio) -> send(socket)
// We hook the OpenSSL entry points (by hardcoded steam.exe address) and run a
// per-SSL SecureTransport context with the SAME buffer model as wg_schannel.c:
//   in_buf  = ciphertext from the network (fed via the rbio write path)
//   out_buf = ciphertext to send         (drained via the wbio read path)
//
// Each hook handler returns the value the guest expects (OpenSSL ABI) and the
// engine emulates the cdecl/stdcall return. SSL/BIO pointers are the guest's own
// (we let the real SSL_new/BIO_new run); shim state is keyed by those pointers.

// REMAINING WORK to make this live (engine wiring in wg_engine.c, guarded to
// steam.exe image_base 0x400000 — addresses from Steam.exe Jun 2024 build):
//   1. Hook these OpenSSL entry points (HLT thunk -> handler -> emulate return):
//        SSL_do_handshake = 0x69BF10 (known)  -> wg_ossl_do_handshake
//        SSL_get_error                         -> wg_ossl_get_error  (needs addr)
//        SSL_read / SSL_write                  -> wg_ossl_read/write  (needs addr)
//        SSL_set_bio / SSL_set0_rbio/wbio      -> wg_ossl_attach      (needs addr)
//        BIO_write(rbio,..) BIO_read(wbio,..)  -> feed/drain          (needs addr)
//        SSL_ctrl(SET_TLSEXT_HOSTNAME)         -> wg_ossl_set_host    (needs addr)
//        SSL_get_peer_certificate / verify     -> return OK           (needs addr)
//        SSL_free                              -> wg_ossl_free        (needs addr)
//   2. Make Steam's CustomVerifyCertificate pass (SecureTransport already
//      validated the chain + SNI, so return X509_V_OK / a non-null cert).
//   3. Re-entrancy: the BIO hooks must NOT call back into the real OpenSSL; they
//      only move bytes to/from our in_buf/out_buf, so no guest re-entry needed.
//   Find the addresses by tracing the SSL setup at [conn+0x298]=SSL* and the
//   BIO pump in the connection read/write completion handlers.

#ifndef WG_OPENSSL_SHIM_H
#define WG_OPENSSL_SHIM_H

#include <stdint.h>
#include <stdbool.h>

// OpenSSL SSL_get_error return codes we synthesize.
#define WG_SSL_ERROR_NONE        0
#define WG_SSL_ERROR_SSL         1
#define WG_SSL_ERROR_WANT_READ   2
#define WG_SSL_ERROR_WANT_WRITE  3
#define WG_SSL_ERROR_SYSCALL     5
#define WG_SSL_ERROR_ZERO_RETURN 6

// Lifecycle ------------------------------------------------------------------
// Associate (lazily) a SecureTransport client context with a guest SSL pointer.
// host may be NULL (set later via wg_ossl_set_host from SNI).
void wg_ossl_attach(uint32_t ssl, uint32_t rbio, uint32_t wbio);
void wg_ossl_set_host(uint32_t ssl, const char *host);
void wg_ossl_free(uint32_t ssl);
bool wg_ossl_known(uint32_t ssl);            // do we shim this SSL?
bool wg_ossl_bio_is_rbio(uint32_t bio);      // is bio a tracked read BIO?
bool wg_ossl_bio_is_wbio(uint32_t bio);      // is bio a tracked write BIO?
uint32_t wg_ossl_ssl_for_bio(uint32_t bio);  // owning SSL, or 0

// Data conduit (called from the BIO hook handlers) --------------------------
// Steam writing received network ciphertext into the read BIO -> our in_buf.
void wg_ossl_feed(uint32_t ssl, const uint8_t *cipher, uint32_t len);
// Steam draining ciphertext to send from the write BIO -> from our out_buf.
// Returns bytes copied into out (0 if none pending).
uint32_t wg_ossl_drain(uint32_t ssl, uint8_t *out, uint32_t cap);
uint32_t wg_ossl_pending_out(uint32_t ssl); // bytes available to drain

// TLS engine (called from the SSL hook handlers) ----------------------------
// Drive the handshake against in_buf/out_buf. Returns 1 done, 0/-1 incomplete.
int wg_ossl_do_handshake(uint32_t ssl);
// Last SSL_get_error code for this SSL.
int wg_ossl_get_error(uint32_t ssl);
// SSL_write(plain) -> out_buf ciphertext. Returns bytes consumed (>0) or <=0.
int wg_ossl_write(uint32_t ssl, const uint8_t *plain, uint32_t len);
// SSL_read -> plaintext from decrypted in_buf. Returns bytes (>0), 0, or <0.
int wg_ossl_read(uint32_t ssl, uint8_t *out, uint32_t cap);

#endif
