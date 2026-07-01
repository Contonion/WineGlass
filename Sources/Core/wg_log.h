#ifndef WG_LOG_H
#define WG_LOG_H

#include <stdarg.h>
#include <stdint.h>

typedef enum {
    WG_LOG_DEBUG,
    WG_LOG_INFO,
    WG_LOG_WARN,
    WG_LOG_ERROR,
    WG_LOG_FATAL
} WGLogLevel;

typedef void (*WGLogCallback)(WGLogLevel level, const char *tag, const char *message, void *userdata);

void wg_log_init(void);
void wg_log_set_callback(WGLogCallback callback, void *userdata);
void wg_log_set_level(WGLogLevel minLevel);
// Mirror all log output to a file (full, untruncated; capped at 150MB). Pass
// NULL to disable/close. Used to capture the engine log inside the bottle.
void wg_log_set_file(const char *path);

void wg_log(WGLogLevel level, const char *tag, const char *fmt, ...);

#define WG_LOGD(tag, ...) wg_log(WG_LOG_DEBUG, tag, __VA_ARGS__)
#define WG_LOGI(tag, ...) wg_log(WG_LOG_INFO,  tag, __VA_ARGS__)
#define WG_LOGW(tag, ...) wg_log(WG_LOG_WARN,  tag, __VA_ARGS__)
#define WG_LOGE(tag, ...) wg_log(WG_LOG_ERROR, tag, __VA_ARGS__)
#define WG_LOGF(tag, ...) wg_log(WG_LOG_FATAL, tag, __VA_ARGS__)

typedef struct {
    char    lines[256][256];
    int     levels[256];
    int     count;
    int     head;
    int     capacity;
} WGLogRingBuffer;

void wg_log_ring_init(WGLogRingBuffer *ring);
void wg_log_ring_push(WGLogRingBuffer *ring, WGLogLevel level, const char *message);
int  wg_log_ring_count(const WGLogRingBuffer *ring);
const char *wg_log_ring_get(const WGLogRingBuffer *ring, int index, WGLogLevel *outLevel);

#endif
