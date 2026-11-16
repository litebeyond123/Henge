/* Bounded, header-only capture at the guest Ethernet boundary. This is not a
   TLS interceptor: it cannot observe HTTP status or host-native DeviceCheck
   traffic. The only retained packet bytes are a validated contiguous prefix
   of link/network/transport headers. In particular 10.0.2.4 HTTP bodies never
   enter the capture buffer, even for fragments or short malformed headers. */
#define _POSIX_C_SOURCE 200809L
#include "net_capture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Tests compile this production file with a deterministic clock. No clock
   override or parser replacement is present in the application build. */
#ifndef HV_NET_CAPTURE_CLOCK_GETTIME
#define HV_NET_CAPTURE_CLOCK_GETTIME clock_gettime
#endif

#define PCAP_GLOBAL_SIZE 24u
#define PCAP_RECORD_SIZE 16u
#define JSON_CAPACITY (64u * 1024u)
#define NS_PER_SECOND UINT64_C(1000000000)
#define CAPTURE_DURATION_NS (HV_NET_CAPTURE_MAX_SECONDS * NS_PER_SECOND)
#define MAX_VLAN_TAGS 2u
#define MAX_IPV6_EXTENSIONS 8u

typedef struct PacketInfo {
    size_t header_length;
    uint8_t ip_version, protocol, source[16], destination[16];
    uint16_t source_port, destination_port;
    uint8_t ports_present, tcp_flags, unsupported, fragment;
} PacketInfo;

typedef struct CaptureFlow {
    PacketInfo key;
    HvNetCaptureDirection direction;
    uint64_t packets, wire_bytes, header_bytes;
    uint64_t first_ms, last_ms, syn_packets, fin_packets, rst_packets;
    uint8_t tcp_flags_or;
} CaptureFlow;

typedef struct Capture {
    uint8_t *bytes;
    size_t used;
    int started, active, replaced_previous_capture;
    HvNetCaptureStopReason stop_reason;
    char session[37], launch_id[37];
    uint64_t start_ns, end_ns, start_utc_us, last_frame_ns;
    uint64_t observed_frames, captured_frames, malformed_frames, unsupported_frames;
    uint64_t fragment_frames, omitted_frames, byte_limit_omitted_frames;
    uint64_t tx_frames, rx_frames, wire_bytes, header_bytes, rx_delivery_drops;
    uint64_t flow_omitted_frames;
    CaptureFlow flows[HV_NET_CAPTURE_MAX_FLOWS];
    size_t flow_count;
} Capture;

static Capture capture;
static pthread_mutex_t capture_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int capture_active;

static uint16_t be16(const uint8_t *p) { return (uint16_t)((unsigned)p[0] << 8 | p[1]); }

static void le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void le32(uint8_t *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8 * i));
}

static int read_time(clockid_t which, uint64_t scale, uint64_t *value) {
    struct timespec t;
    if (HV_NET_CAPTURE_CLOCK_GETTIME(which, &t) != 0) return errno ? errno : EIO;
    if (t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec >= (long)NS_PER_SECOND ||
        (uint64_t)t.tv_sec > UINT64_MAX / scale) return ERANGE;
    uint64_t seconds = (uint64_t)t.tv_sec * scale;
    uint64_t fraction = (uint64_t)t.tv_nsec / (NS_PER_SECOND / scale);
    if (seconds > UINT64_MAX - fraction) return ERANGE;
    *value = seconds + fraction;
    return 0;
}

static int uuid_copy(char result[37], const char *input) {
    if (!input || strlen(input) != 36) return 0;
    for (size_t i = 0; i < 36; i++) {
        unsigned char c = (unsigned char)input[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return 0;
        } else {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
            if (c >= 'A' && c <= 'F') c = (unsigned char)(c - 'A' + 'a');
        }
        result[i] = (char)c;
    }
    result[36] = 0;
    return 1;
}

/* Bounds are checked before a header can increase the retained prefix. Any
   malformed frame is discarded entirely; no guessed offset is ever copied.
   Ethernet padding, UDP data, TCP data and ICMP error quotes are excluded. */
static int transport_header(const uint8_t *p, size_t offset, size_t end, PacketInfo *info) {
    size_t remaining = end - offset;
    if (info->protocol == 6) {
        if (remaining < 20) return 0;
        size_t length = (size_t)(p[offset + 12] >> 4) * 4;
        if (length < 20 || length > remaining) return 0;
        /* Validate TCP option framing too. Bytes after EOL are padding; only
           zero padding is valid here. A forged offset must not turn a short
           TCP header followed by arbitrary HTTP text into captured options. */
        for (size_t option = offset + 20; option < offset + length;) {
            uint8_t kind = p[option];
            if (kind == 0) {
                for (; option < offset + length; option++) if (p[option] != 0) return 0;
                break;
            }
            if (kind == 1) { option++; continue; }
            if (offset + length - option < 2 || p[option + 1] < 2 ||
                p[option + 1] > offset + length - option) return 0;
            option += p[option + 1];
        }
        if (offset + length > HV_NET_CAPTURE_MAX_HEADER) {
            info->unsupported = 1;
            return 1; /* keep the preceding IP headers only */
        }
        info->header_length = offset + length;
        info->source_port = be16(p + offset);
        info->destination_port = be16(p + offset + 2);
        info->ports_present = 1;
        info->tcp_flags = p[offset + 13];
        return 1;
    }
    if (info->protocol == 17) {
        if (remaining < 8) return 0;
        size_t length = be16(p + offset + 4);
        if (length < 8 || length > remaining) return 0; /* no IPv6 jumbograms */
        if (offset + 8 > HV_NET_CAPTURE_MAX_HEADER) {
            info->unsupported = 1;
            return 1;
        }
        info->header_length = offset + 8;
        info->source_port = be16(p + offset);
        info->destination_port = be16(p + offset + 2);
        info->ports_present = 1;
        return 1;
    }
    if ((info->ip_version == 4 && info->protocol == 1) ||
        (info->ip_version == 6 && info->protocol == 58)) {
        if (remaining < 8) return 0;
        if (offset + 8 <= HV_NET_CAPTURE_MAX_HEADER) info->header_length = offset + 8;
        else info->unsupported = 1;
        return 1;
    }
    if (info->ip_version == 6 && info->protocol == 59) return 1; /* no next header */
    info->unsupported = 1;
    return 1;
}

static int packet_headers(const uint8_t *p, size_t length, PacketInfo *info) {
    memset(info, 0, sizeof *info);
    if (!p || length < 14 || length > UINT32_MAX) return 0;
    size_t offset = 14;
    uint16_t ether_type = be16(p + 12);
    for (unsigned tags = 0; ether_type == 0x8100 || ether_type == 0x88a8; tags++) {
        if (tags == MAX_VLAN_TAGS) {
            info->unsupported = 1;
            info->header_length = offset;
            return 1;
        }
        if (length - offset < 4) return 0;
        ether_type = be16(p + offset + 2);
        offset += 4;
    }
    info->header_length = offset;
    if (ether_type == 0x0800) {
        if (length - offset < 20 || p[offset] >> 4 != 4) return 0;
        size_t ip_length = (p[offset] & 15u) * 4u;
        size_t total = be16(p + offset + 2);
        if (ip_length < 20 || ip_length > total || total > length - offset) return 0;
        /* IPv4 option framing is checked before optional bytes are retained. */
        for (size_t option = offset + 20; option < offset + ip_length;) {
            uint8_t kind = p[option];
            if (kind == 0) {
                for (; option < offset + ip_length; option++) if (p[option] != 0) return 0;
                break;
            }
            if (kind == 1) { option++; continue; }
            if (offset + ip_length - option < 2 || p[option + 1] < 2 ||
                p[option + 1] > offset + ip_length - option) return 0;
            option += p[option + 1];
        }
        info->ip_version = 4;
        info->protocol = p[offset + 9];
        memcpy(info->source, p + offset + 12, 4);
        memcpy(info->destination, p + offset + 16, 4);
        info->header_length = offset + ip_length;
        if (be16(p + offset + 6) & 0x3fff) {
            info->fragment = 1;
            return 1; /* includes first fragments: never guess/reassemble L4 */
        }
        return transport_header(p, offset + ip_length, offset + total, info);
    }
    if (ether_type == 0x86dd) {
        if (length - offset < 40 || p[offset] >> 4 != 6) return 0;
        size_t payload = be16(p + offset + 4);
        if (payload > length - offset - 40) return 0;
        size_t end = offset + 40 + payload;
        info->ip_version = 6;
        info->protocol = p[offset + 6];
        memcpy(info->source, p + offset + 8, 16);
        memcpy(info->destination, p + offset + 24, 16);
        offset += 40;
        info->header_length = offset;
        for (unsigned extensions = 0;; extensions++) {
            if (info->protocol == 44) {
                if (end - offset < 8) return 0;
                if (offset + 8 > HV_NET_CAPTURE_MAX_HEADER) { info->unsupported = 1; return 1; }
                info->header_length = offset + 8;
                info->protocol = p[offset];
                info->fragment = 1;
                return 1; /* no data beyond a fragment header, even offset zero */
            }
            if (info->protocol != 0 && info->protocol != 43 && info->protocol != 60) break;
            if (extensions == MAX_IPV6_EXTENSIONS) { info->unsupported = 1; return 1; }
            if (end - offset < 8) return 0;
            size_t extension_length = ((size_t)p[offset + 1] + 1u) * 8u;
            if (extension_length > end - offset) return 0;
            if (offset + extension_length > HV_NET_CAPTURE_MAX_HEADER) { info->unsupported = 1; return 1; }
            /* Hop-by-hop and destination options use TLV lengths (Pad1=0).
               Routing headers have a different layout, but a fixed length. */
            if (info->protocol != 43) {
                for (size_t option = offset + 2; option < offset + extension_length;) {
                    if (p[option] == 0) { option++; continue; }
                    if (offset + extension_length - option < 2 ||
                        (size_t)p[option + 1] + 2 > offset + extension_length - option) return 0;
                    option += (size_t)p[option + 1] + 2;
                }
            }
            info->protocol = p[offset];
            offset += extension_length;
            info->header_length = offset;
        }
        return transport_header(p, offset, end, info);
    }
    /* Do not retain ARP bodies or unknown encapsulations. The verified
       Ethernet/VLAN prefix still identifies that traffic was observed. */
    info->unsupported = 1;
    return 1;
}

static void stop_locked(HvNetCaptureStopReason reason, uint64_t now) {
    if (!capture.active) return;
    capture.active = 0;
    capture.stop_reason = reason;
    capture.end_ns = now >= capture.start_ns ? now : capture.start_ns;
    atomic_store_explicit(&capture_active, 0, memory_order_release);
}

/* Caller holds the mutex. Also protects against a failed/backwards clock,
   rather than turning an invalid elapsed time into an unbounded capture. */
static int active_at_locked(uint64_t *now) {
    if (!capture.active) return 0;
    if (read_time(CLOCK_MONOTONIC, NS_PER_SECOND, now) != 0 || *now < capture.last_frame_ns) {
        stop_locked(HV_NET_CAPTURE_STOP_CLOCK_ERROR, capture.last_frame_ns);
        return 0;
    }
    if (*now - capture.start_ns >= CAPTURE_DURATION_NS) {
        stop_locked(HV_NET_CAPTURE_STOP_TIME_LIMIT, capture.start_ns + CAPTURE_DURATION_NS);
        return 0;
    }
    return 1;
}

int hv_net_capture_start(const char *session, const char *launch_id) {
    char session_uuid[37], launch_uuid[37];
    if (!uuid_copy(session_uuid, session) || !uuid_copy(launch_uuid, launch_id)) return EINVAL;
    pthread_mutex_lock(&capture_mutex);
    if (capture.started && !strcmp(capture.session, session_uuid) && !strcmp(capture.launch_id, launch_uuid)) {
        pthread_mutex_unlock(&capture_mutex);
        return 0;
    }
    uint64_t monotonic = 0, utc = 0;
    int error = read_time(CLOCK_MONOTONIC, NS_PER_SECOND, &monotonic);
    if (!error) error = read_time(CLOCK_REALTIME, UINT64_C(1000000), &utc);
    if (!error && (monotonic > UINT64_MAX - CAPTURE_DURATION_NS ||
                   utc / UINT64_C(1000000) > UINT32_MAX - HV_NET_CAPTURE_MAX_SECONDS)) error = ERANGE;
    uint8_t *bytes = capture.bytes;
    if (!error && !bytes) { bytes = malloc(HV_NET_CAPTURE_MAX_BYTES); if (!bytes) error = ENOMEM; }
    if (error) { pthread_mutex_unlock(&capture_mutex); return error; }
    /* Clearing the one reusable buffer prevents remnants of the previous
       capture from surviving a new launch. Only `used` bytes are exported. */
    int replacing = capture.started;
    memset(bytes, 0, HV_NET_CAPTURE_MAX_BYTES);
    memset(&capture, 0, sizeof capture);
    capture.bytes = bytes;
    capture.used = PCAP_GLOBAL_SIZE;
    capture.started = capture.active = 1;
    capture.replaced_previous_capture = replacing;
    capture.start_ns = capture.last_frame_ns = monotonic;
    capture.start_utc_us = utc;
    memcpy(capture.session, session_uuid, sizeof capture.session);
    memcpy(capture.launch_id, launch_uuid, sizeof capture.launch_id);
    /* Classic microsecond PCAP, explicit little endian, LINKTYPE_ETHERNET=1.
       orig_len remains the wire length; incl_len is the header-only prefix. */
    le32(bytes, 0xa1b2c3d4);
    le16(bytes + 4, 2);
    le16(bytes + 6, 4);
    le32(bytes + 16, HV_NET_CAPTURE_MAX_HEADER);
    le32(bytes + 20, 1);
    atomic_store_explicit(&capture_active, 1, memory_order_release);
    pthread_mutex_unlock(&capture_mutex);
    return 0;
}

void hv_net_capture_stop(HvNetCaptureStopReason reason) {
    if (reason < HV_NET_CAPTURE_STOP_USER || reason > HV_NET_CAPTURE_STOP_CLOCK_ERROR) return;
    pthread_mutex_lock(&capture_mutex);
    uint64_t now = capture.last_frame_ns;
    if (active_at_locked(&now)) stop_locked(reason, now);
    pthread_mutex_unlock(&capture_mutex);
}

void hv_net_capture_tick(void) {
    if (!atomic_load_explicit(&capture_active, memory_order_acquire)) return;
    pthread_mutex_lock(&capture_mutex);
    uint64_t now = 0;
    (void)active_at_locked(&now);
    pthread_mutex_unlock(&capture_mutex);
}

static int same_flow(const CaptureFlow *flow, const PacketInfo *info, HvNetCaptureDirection direction) {
    const PacketInfo *key = &flow->key;
    return flow->direction == direction && key->ip_version == info->ip_version &&
           key->protocol == info->protocol && key->ports_present == info->ports_present &&
           key->source_port == info->source_port && key->destination_port == info->destination_port &&
           !memcmp(key->source, info->source, sizeof key->source) &&
           !memcmp(key->destination, info->destination, sizeof key->destination);
}

static void count_flow_locked(const PacketInfo *info, HvNetCaptureDirection direction, size_t length, uint64_t now) {
    if (!info->ip_version) return;
    size_t i;
    for (i = 0; i < capture.flow_count; i++) if (same_flow(&capture.flows[i], info, direction)) break;
    if (i == capture.flow_count) {
        if (i == HV_NET_CAPTURE_MAX_FLOWS) { capture.flow_omitted_frames++; return; }
        CaptureFlow *fresh = &capture.flows[capture.flow_count++];
        fresh->key = *info;
        fresh->direction = direction;
        fresh->first_ms = (now - capture.start_ns) / UINT64_C(1000000);
    }
    CaptureFlow *flow = &capture.flows[i];
    flow->last_ms = (now - capture.start_ns) / UINT64_C(1000000);
    flow->packets++;
    flow->wire_bytes += length;
    flow->header_bytes += info->header_length;
    flow->tcp_flags_or |= info->tcp_flags;
    if (info->tcp_flags & 0x02) flow->syn_packets++;
    if (info->tcp_flags & 0x01) flow->fin_packets++;
    if (info->tcp_flags & 0x04) flow->rst_packets++;
}

void hv_net_capture_record(HvNetCaptureDirection direction, const uint8_t *frame, size_t length) {
    if (!atomic_load_explicit(&capture_active, memory_order_acquire)) return;
    if (direction != HV_NET_CAPTURE_TX && direction != HV_NET_CAPTURE_RX) return;
    pthread_mutex_lock(&capture_mutex);
    uint64_t now = 0;
    if (!active_at_locked(&now)) { pthread_mutex_unlock(&capture_mutex); return; }
    capture.observed_frames++;
    PacketInfo info;
    if (!packet_headers(frame, length, &info)) {
        capture.malformed_frames++;
        capture.omitted_frames++;
        pthread_mutex_unlock(&capture_mutex);
        return;
    }
    if (info.unsupported) capture.unsupported_frames++;
    if (info.fragment) capture.fragment_frames++;
    size_t record_size = PCAP_RECORD_SIZE + info.header_length;
    if (record_size > HV_NET_CAPTURE_MAX_BYTES - capture.used) {
        capture.omitted_frames++;
        capture.byte_limit_omitted_frames++;
        stop_locked(HV_NET_CAPTURE_STOP_BYTE_LIMIT, now);
        pthread_mutex_unlock(&capture_mutex);
        return;
    }
    uint64_t utc_us = capture.start_utc_us + (now - capture.start_ns) / UINT64_C(1000);
    uint8_t *record = capture.bytes + capture.used;
    le32(record, (uint32_t)(utc_us / UINT64_C(1000000)));
    le32(record + 4, (uint32_t)(utc_us % UINT64_C(1000000)));
    le32(record + 8, (uint32_t)info.header_length);
    le32(record + 12, (uint32_t)length);
    memcpy(record + PCAP_RECORD_SIZE, frame, info.header_length);
    capture.used += record_size;
    capture.last_frame_ns = now;
    capture.captured_frames++;
    if (direction == HV_NET_CAPTURE_TX) capture.tx_frames++; else capture.rx_frames++;
    capture.wire_bytes += length;
    capture.header_bytes += info.header_length;
    count_flow_locked(&info, direction, length, now);
    if (capture.used == HV_NET_CAPTURE_MAX_BYTES) stop_locked(HV_NET_CAPTURE_STOP_BYTE_LIMIT, now);
    pthread_mutex_unlock(&capture_mutex);
}

void hv_net_capture_note_rx_drop(void) {
    if (!atomic_load_explicit(&capture_active, memory_order_acquire)) return;
    pthread_mutex_lock(&capture_mutex);
    uint64_t now = 0;
    if (active_at_locked(&now)) capture.rx_delivery_drops++;
    pthread_mutex_unlock(&capture_mutex);
}

typedef struct Json { char *bytes; size_t used; int failed; } Json;

static void json_add(Json *out, const char *format, ...) {
    if (out->failed) return;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(out->bytes + out->used, JSON_CAPACITY - out->used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= JSON_CAPACITY - out->used) { out->failed = 1; return; }
    out->used += (size_t)count;
}

static const char *reason_name(HvNetCaptureStopReason reason) {
    switch (reason) {
        case HV_NET_CAPTURE_STOP_USER: return "user";
        case HV_NET_CAPTURE_STOP_BACKGROUND: return "background";
        case HV_NET_CAPTURE_STOP_VM_STOP: return "vm_stop";
        case HV_NET_CAPTURE_STOP_TIME_LIMIT: return "time_limit";
        case HV_NET_CAPTURE_STOP_BYTE_LIMIT: return "byte_limit";
        case HV_NET_CAPTURE_STOP_CLOCK_ERROR: return "clock_error";
        default: return "none";
    }
}

static void utc_string(uint64_t microseconds, char out[32]) {
    time_t seconds = (time_t)(microseconds / UINT64_C(1000000));
    struct tm date;
    char whole[24];
    if (!gmtime_r(&seconds, &date) || !strftime(whole, sizeof whole, "%Y-%m-%dT%H:%M:%S", &date)) {
        out[0] = 0;
        return;
    }
    snprintf(out, 32, "%s.%03uZ", whole, (unsigned)((microseconds % UINT64_C(1000000)) / 1000));
}

static char *metadata_locked(void) {
    uint64_t now = capture.last_frame_ns;
    (void)active_at_locked(&now);
    uint64_t end = capture.active ? now : capture.end_ns;
    uint64_t elapsed = capture.started && end >= capture.start_ns ? end - capture.start_ns : 0;
    char started[32] = "", stopped[32] = "";
    if (capture.started) {
        utc_string(capture.start_utc_us, started);
        if (!capture.active) utc_string(capture.start_utc_us + elapsed / 1000, stopped);
    }
    Json out = {.bytes = malloc(JSON_CAPACITY)};
    if (!out.bytes) return NULL;
    json_add(&out, "{\"protocol\":1,\"status\":\"%s\",\"active\":%s,\"stop_reason\":\"%s\","
             "\"replaced_previous_capture\":%s,"
             "\"session\":\"%s\",\"launch_id\":\"%s\",\"started_utc\":\"%s\",\"stopped_utc\":\"%s\","
             "\"start_monotonic_ms\":%" PRIu64 ",\"elapsed_ms\":%" PRIu64 ","
             "\"scope\":\"guest_ethernet_headers\",\"timestamps\":\"utc_start_plus_monotonic\","
             "\"tx_observation_point\":\"before_dns_or_nat\",\"rx_observation_point\":\"successful_guest_receive\","
             "\"application_payload_included\":false,\"host_native_devicecheck_traffic_included\":false,"
             "\"http_status_observable\":false,\"process_attribution\":false,\"dns_payload_included\":false,"
             "\"ip_fragment_body_included\":false,\"link_type\":1,\"pcap_format\":\"microsecond_little_endian\","
             "\"maximum_seconds\":%u,\"maximum_pcap_bytes\":%u,\"maximum_packet_header_bytes\":%u,"
             "\"maximum_flows\":%u,\"pcap_bytes\":%zu,"
             "\"observed_frames\":%" PRIu64 ",\"captured_frames\":%" PRIu64 ","
             "\"tx_captured_frames\":%" PRIu64 ",\"rx_delivered_captured_frames\":%" PRIu64 ","
             "\"wire_bytes\":%" PRIu64 ",\"captured_header_bytes\":%" PRIu64 ","
             "\"omitted_frames\":%" PRIu64 ",\"malformed_frames\":%" PRIu64 ","
             "\"unsupported_frames\":%" PRIu64 ",\"fragment_header_only_frames\":%" PRIu64 ","
             "\"byte_limit_omitted_frames\":%" PRIu64 ",\"rx_delivery_drops\":%" PRIu64 ","
             "\"flow_summary_omitted_frames\":%" PRIu64 ",\"flow_count\":%zu,\"flows\":[",
             !capture.started ? "not_started" : capture.active ? "capturing" : "stopped",
             capture.active ? "true" : "false", reason_name(capture.stop_reason),
             capture.replaced_previous_capture ? "true" : "false",
             capture.session, capture.launch_id, started, stopped, capture.start_ns / UINT64_C(1000000),
             elapsed / UINT64_C(1000000), HV_NET_CAPTURE_MAX_SECONDS, HV_NET_CAPTURE_MAX_BYTES,
             HV_NET_CAPTURE_MAX_HEADER, HV_NET_CAPTURE_MAX_FLOWS, capture.used,
             capture.observed_frames, capture.captured_frames, capture.tx_frames, capture.rx_frames,
             capture.wire_bytes, capture.header_bytes, capture.omitted_frames, capture.malformed_frames,
             capture.unsupported_frames, capture.fragment_frames, capture.byte_limit_omitted_frames,
             capture.rx_delivery_drops, capture.flow_omitted_frames, capture.flow_count);
    for (size_t i = 0; i < capture.flow_count; i++) {
        const CaptureFlow *flow = &capture.flows[i];
        char source[INET6_ADDRSTRLEN] = "", destination[INET6_ADDRSTRLEN] = "";
        int family = flow->key.ip_version == 4 ? AF_INET : AF_INET6;
        (void)inet_ntop(family, flow->key.source, source, sizeof source);
        (void)inet_ntop(family, flow->key.destination, destination, sizeof destination);
        json_add(&out, "%s{\"direction\":\"%s\",\"ip_version\":%u,\"ip_protocol\":%u,"
                 "\"source\":\"%s\",\"destination\":\"%s\",\"ports_present\":%s,"
                 "\"source_port\":%u,\"destination_port\":%u,\"packets\":%" PRIu64 ","
                 "\"wire_bytes\":%" PRIu64 ",\"captured_header_bytes\":%" PRIu64 ","
                 "\"tcp_flags_or\":%u,\"syn_packets\":%" PRIu64 ",\"fin_packets\":%" PRIu64 ","
                 "\"rst_packets\":%" PRIu64 ",\"first_elapsed_ms\":%" PRIu64 ",\"last_elapsed_ms\":%" PRIu64 "}",
                 i ? "," : "", flow->direction == HV_NET_CAPTURE_TX ? "tx" : "rx", flow->key.ip_version,
                 flow->key.protocol, source, destination, flow->key.ports_present ? "true" : "false",
                 flow->key.source_port, flow->key.destination_port, flow->packets, flow->wire_bytes,
                 flow->header_bytes, flow->tcp_flags_or, flow->syn_packets, flow->fin_packets, flow->rst_packets,
                 flow->first_ms, flow->last_ms);
    }
    json_add(&out, "]}");
    if (out.failed) { free(out.bytes); return NULL; }
    return out.bytes;
}

char *hv_net_capture_metadata_json(void) {
    pthread_mutex_lock(&capture_mutex);
    char *result = metadata_locked();
    pthread_mutex_unlock(&capture_mutex);
    return result;
}

int hv_net_capture_snapshot(char **metadata_json, uint8_t **pcap, size_t *pcap_length) {
    if (metadata_json) *metadata_json = NULL;
    if (pcap) *pcap = NULL;
    if (pcap_length) *pcap_length = 0;
    if (!metadata_json || !pcap || !pcap_length) return EINVAL;
    pthread_mutex_lock(&capture_mutex);
    char *metadata = metadata_locked();
    if (!metadata) { pthread_mutex_unlock(&capture_mutex); return ENOMEM; }
    uint8_t *copy = NULL;
    if (capture.used) {
        copy = malloc(capture.used);
        if (!copy) { free(metadata); pthread_mutex_unlock(&capture_mutex); return ENOMEM; }
        memcpy(copy, capture.bytes, capture.used);
    }
    *metadata_json = metadata;
    *pcap = copy;
    *pcap_length = capture.used;
    pthread_mutex_unlock(&capture_mutex);
    return 0;
}
