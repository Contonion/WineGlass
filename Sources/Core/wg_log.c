#include "wg_log.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

static WGLogCallback  s_callback = NULL;
static void          *s_userdata = NULL;
static WGLogLevel     s_minLevel = WG_LOG_DEBUG;
static pthread_mutex_t s_mutex   = PTHREAD_MUTEX_INITIALIZER;

static const char *level_names[] = { "DBG", "INF", "WRN", "ERR", "FTL" };

void wg_log_init(void) {
    s_callback = NULL;
    s_userdata = NULL;
    s_minLevel = WG_LOG_DEBUG;
}

void wg_log_set_callback(WGLogCallback callback, void *userdata) {
    pthread_mutex_lock(&s_mutex);
    s_callback = callback;
    s_userdata = userdata;
    pthread_mutex_unlock(&s_mutex);
}

void wg_log_set_level(WGLogLevel minLevel) {
    s_minLevel = minLevel;
}

void wg_log(WGLogLevel level, const char *tag, const char *fmt, ...) {
    if (level < s_minLevel) return;

    // Guard against bad callers: an out-of-range level or NULL tag/fmt would
    // otherwise crash inside fprintf (wild level_names[] read), which masks the
    // real error and aborts the whole process during a crash flush.
    int lvl = (level >= 0 && level <= WG_LOG_FATAL) ? (int)level : (int)WG_LOG_ERROR;
    const char *safe_tag = tag ? tag : "?";

    char buf[512];
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
    } else {
        buf[0] = '\0';
    }

    fprintf(stderr, "[%s/%s] %s\n", level_names[lvl], safe_tag, buf);

    pthread_mutex_lock(&s_mutex);
    if (s_callback) {
        char tagged[600];
        snprintf(tagged, sizeof(tagged), "[%s] %s", safe_tag, buf);
        s_callback((WGLogLevel)lvl, safe_tag, tagged, s_userdata);
    }
    pthread_mutex_unlock(&s_mutex);
}

void wg_log_ring_init(WGLogRingBuffer *ring) {
    memset(ring, 0, sizeof(*ring));
    ring->capacity = 256;
}

void wg_log_ring_push(WGLogRingBuffer *ring, WGLogLevel level, const char *message) {
    int idx = ring->head;
    strncpy(ring->lines[idx], message, 255);
    ring->lines[idx][255] = '\0';
    ring->levels[idx] = level;
    ring->head = (ring->head + 1) % ring->capacity;
    if (ring->count < ring->capacity) ring->count++;
}

int wg_log_ring_count(const WGLogRingBuffer *ring) {
    return ring->count;
}

const char *wg_log_ring_get(const WGLogRingBuffer *ring, int index, WGLogLevel *outLevel) {
    if (index < 0 || index >= ring->count) return NULL;
    int start = (ring->head - ring->count + ring->capacity) % ring->capacity;
    int actual = (start + index) % ring->capacity;
    if (outLevel) *outLevel = (WGLogLevel)ring->levels[actual];
    return ring->lines[actual];
}
