/* Compile the actual production module, with only its clock substituted. This
   allows the 120-second boundary to be exercised without sleeping or changing
   the application limits. Packet construction and PCAP decoding are separate
   from the production parser. Only synthetic traffic is used. */
#define _POSIX_C_SOURCE 200809L
#include <stdatomic.h>
#include <time.h>
static int fixture_clock_gettime(clockid_t, struct timespec *);
#define HV_NET_CAPTURE_CLOCK_GETTIME fixture_clock_gettime
#include "../host/net_capture.c"

static _Atomic uint64_t fixture_ns = UINT64_C(5000000000);
static _Atomic int fixture_clock_fails;
static unsigned checks, failures, launch_number;
static const char session_id[] = "00112233-4455-4677-8899-AABBCCDDEEFF";
static const char secret[] = "HENGE_SECRET_CANARY_cookie_token_signature_body";

static int fixture_clock_gettime(clockid_t clock, struct timespec *out) {
    if (atomic_load(&fixture_clock_fails)) { errno = EIO; return -1; }
    uint64_t ns = clock == CLOCK_REALTIME ? UINT64_C(1760000000123456000) : atomic_load(&fixture_ns);
    out->tv_sec = (time_t)(ns / UINT64_C(1000000000));
    out->tv_nsec = (long)(ns % UINT64_C(1000000000));
    return 0;
}

#define CHECK(condition, label) do { \
    checks++; \
    if (!(condition)) { failures++; fprintf(stderr, "FAIL %s at line %d\n", label, __LINE__); } \
} while (0)

typedef struct Snapshot { char *json; uint8_t *bytes; size_t length; } Snapshot;

static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int contains(const void *data, size_t length, const void *needle, size_t needle_length) {
    const uint8_t *p = data;
    if (needle_length > length) return 0;
    for (size_t i = 0; i <= length - needle_length; i++) if (!memcmp(p + i, needle, needle_length)) return 1;
    return 0;
}

static uint64_t json_integer(const char *json, const char *key) {
    char name[96];
    snprintf(name, sizeof name, "\"%s\":", key);
    const char *p = strstr(json, name);
    CHECK(p != NULL, "metadata integer exists");
    return p ? strtoull(p + strlen(name), NULL, 10) : UINT64_MAX;
}

static Snapshot snapshot(void) {
    Snapshot result = {0};
    int error = hv_net_capture_snapshot(&result.json, &result.bytes, &result.length);
    CHECK(error == 0 && result.json != NULL, "atomic snapshot succeeds");
    if (error || !result.json) exit(2);
    CHECK(json_integer(result.json, "pcap_bytes") == result.length, "paired metadata and PCAP agree");
    CHECK(!contains(result.bytes, result.length, secret, sizeof secret - 1), "PCAP excludes secret canary");
    CHECK(strstr(result.json, secret) == NULL, "metadata excludes secret canary");
    return result;
}

static void release_snapshot(Snapshot *value) {
    free(value->json);
    free(value->bytes);
    memset(value, 0, sizeof *value);
}

static size_t pcap_count(const Snapshot *value) {
    if (!value->length) return 0;
    CHECK(value->length >= 24, "PCAP has global header");
    if (value->length < 24) return 0;
    CHECK(u32(value->bytes) == UINT32_C(0xa1b2c3d4), "PCAP little-endian magic");
    CHECK(value->bytes[4] == 2 && value->bytes[6] == 4, "PCAP version 2.4");
    CHECK(u32(value->bytes + 20) == 1, "PCAP Ethernet link type");
    CHECK(u32(value->bytes + 16) == 512, "PCAP bounded snapshot length");
    size_t offset = 24, records = 0;
    while (offset < value->length) {
        if (value->length - offset < 16) { CHECK(0, "PCAP record is whole"); break; }
        uint32_t included = u32(value->bytes + offset + 8), original = u32(value->bytes + offset + 12);
        if (included > original || included > 512 || included > value->length - offset - 16) {
            CHECK(0, "PCAP header length fits record and original"); break;
        }
        if (u32(value->bytes + offset + 4) >= 1000000) { CHECK(0, "PCAP microseconds valid"); break; }
        offset += 16 + included;
        records++;
    }
    CHECK(offset == value->length, "PCAP ends at whole record");
    CHECK(records == json_integer(value->json, "captured_frames"), "PCAP records equal metadata");
    return records;
}

static void begin(void) {
    char launch[37];
    atomic_store(&fixture_ns, UINT64_C(5000000000));
    atomic_store(&fixture_clock_fails, 0);
    snprintf(launch, sizeof launch, "%08x-0000-4000-8000-000000000001", ++launch_number);
    CHECK(hv_net_capture_start(session_id, launch) == 0, "start valid capture");
}

static void put16(uint8_t *p, uint16_t value) { p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value; }

static void ethernet(uint8_t *p, uint16_t type) {
    memset(p, 0, 14);
    p[0] = 0x52; p[5] = 2; p[6] = 0x52; p[11] = 1;
    put16(p + 12, type);
}

static size_t ipv4(uint8_t *p, int udp, size_t ip_options, size_t tcp_options) {
    memset(p, 0, 1024);
    ethernet(p, 0x0800);
    size_t ip_length = 20 + ip_options;
    size_t transport = udp ? 8 : 20 + tcp_options;
    size_t length = 14 + ip_length + transport + sizeof secret;
    p[14] = (uint8_t)(0x40 | (ip_length / 4));
    put16(p + 16, (uint16_t)(length - 14));
    p[22] = 64; p[23] = udp ? 17 : 6;
    p[26] = p[30] = 10; p[28] = p[32] = 2; p[29] = 15; p[33] = 4;
    if (ip_options) p[34] = 1; /* NOP followed by EOL and zero padding */
    size_t t = 14 + ip_length;
    put16(p + t, 45000); put16(p + t + 2, udp ? 53 : 80);
    if (udp) put16(p + t + 4, (uint16_t)(transport + sizeof secret));
    else {
        p[t + 12] = (uint8_t)((transport / 4) << 4);
        p[t + 13] = 0x12; /* SYN + ACK */
        if (tcp_options) { p[t + 20] = 2; p[t + 21] = 4; p[t + 22] = 5; p[t + 23] = 0xb4; }
    }
    memcpy(p + t + transport, secret, sizeof secret);
    return length;
}

static size_t ipv6(uint8_t *p, int udp, unsigned extensions) {
    memset(p, 0, 1024);
    ethernet(p, 0x86dd);
    p[14] = 0x60; p[20] = extensions ? 0 : udp ? 17 : 6; p[21] = 64;
    p[22] = p[38] = 0x20; p[23] = p[39] = 1; p[24] = p[40] = 0x0d; p[25] = p[41] = 0xb8;
    p[37] = 1; p[53] = 2;
    size_t t = 54;
    for (unsigned i = 0; i < extensions; i++, t += 8) p[t] = i + 1 == extensions ? (udp ? 17 : 6) : 60;
    size_t transport = udp ? 8 : 20;
    put16(p + t, 46000); put16(p + t + 2, 443);
    if (udp) put16(p + t + 4, (uint16_t)(transport + sizeof secret));
    else { p[t + 12] = 0x50; p[t + 13] = 0x18; }
    memcpy(p + t + transport, secret, sizeof secret);
    size_t length = t + transport + sizeof secret;
    put16(p + 18, (uint16_t)(length - 54));
    return length;
}

static void single_record(uint8_t *frame, size_t length, size_t expected_header, const char *label) {
    begin();
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    Snapshot s = snapshot();
    CHECK(pcap_count(&s) == 1, label);
    CHECK(s.length == 24 + 16 + expected_header, "exact dynamic header cutoff");
    if (s.length >= 40 + expected_header) {
        CHECK(u32(s.bytes + 32) == expected_header, "PCAP incl_len equals actual header prefix");
        CHECK(u32(s.bytes + 36) == length, "PCAP orig_len preserves wire length");
        CHECK(!memcmp(s.bytes + 40, frame, expected_header), "saved headers are real packet bytes");
    }
    release_snapshot(&s);
}

static void test_no_start(void) {
    Snapshot s = snapshot();
    CHECK(s.bytes == NULL && s.length == 0 && strstr(s.json, "\"status\":\"not_started\""), "no stale PCAP before start");
    CHECK(strstr(s.json, "\"application_payload_included\":false") != NULL, "scope excludes application bytes");
    CHECK(strstr(s.json, "\"host_native_devicecheck_traffic_included\":false") != NULL, "scope excludes host Apple API traffic");
    release_snapshot(&s);
    CHECK(hv_net_capture_start(NULL, session_id) == EINVAL, "NULL UUID rejected");
    CHECK(hv_net_capture_start("../not-a-UUID", session_id) == EINVAL, "invalid UUID rejected");
    CHECK(hv_net_capture_snapshot(NULL, NULL, NULL) == EINVAL, "invalid snapshot outputs rejected");
}

static void test_headers(void) {
    uint8_t frame[1024];
    size_t length = ipv4(frame, 0, 0, 0);
    single_record(frame, length, 54, "plain HTTP TCP headers only");
    length = ipv4(frame, 1, 0, 0);
    single_record(frame, length, 42, "DNS UDP headers only");
    length = ipv4(frame, 0, 4, 4);
    single_record(frame, length, 62, "IPv4 and TCP options change cutoff");
    length = ipv4(frame, 0, 0, 0);
    memset(frame + length, 0x9a, 50);
    single_record(frame, length + 50, 54, "Ethernet padding not captured");
    length = ipv4(frame, 0, 0, 0);
    memmove(frame + 18, frame + 14, length - 14);
    put16(frame + 12, 0x8100); put16(frame + 14, 7); put16(frame + 16, 0x0800);
    single_record(frame, length + 4, 58, "single VLAN cutoff");
    memmove(frame + 18, frame + 14, length - 14 + 4);
    put16(frame + 12, 0x88a8); put16(frame + 14, 8); put16(frame + 16, 0x8100);
    single_record(frame, length + 8, 62, "double VLAN cutoff");
    /* An additional tag is unsupported, not an excuse to guess an IP offset. */
    memmove(frame + 18, frame + 14, length - 14 + 8);
    put16(frame + 14, 9); put16(frame + 16, 0x88a8);
    single_record(frame, length + 12, 22, "extra VLAN tag retains only verified prefix");
    length = ipv6(frame, 0, 0);
    single_record(frame, length, 74, "IPv6 TCP cutoff");
    length = ipv6(frame, 1, 0);
    single_record(frame, length, 62, "IPv6 UDP cutoff");
    length = ipv6(frame, 0, 2);
    single_record(frame, length, 90, "IPv6 extension chain cutoff");
    length = ipv6(frame, 0, 9);
    single_record(frame, length, 118, "IPv6 extension depth capped before unknown bytes");
    length = ipv6(frame, 0, 0);
    frame[20] = 51; /* AH deliberately unsupported; do not save authentication data. */
    single_record(frame, length, 54, "unsupported IPv6 protocol retains IP prefix only");
    length = ipv4(frame, 0, 0, 0);
    frame[23] = 1;
    memcpy(frame + 42, secret, sizeof secret);
    single_record(frame, length, 42, "ICMP quoted original payload omitted");
    ethernet(frame, 0x0806);
    memcpy(frame + 14, secret, sizeof secret);
    single_record(frame, 14 + sizeof secret, 14, "unsupported ARP retains Ethernet only");
}

static void test_fragments(void) {
    uint8_t frame[1024];
    size_t length = ipv4(frame, 0, 0, 0);
    put16(frame + 20, 0x2000); /* first fragment, MF */
    memcpy(frame + 34, secret, sizeof secret);
    single_record(frame, length, 34, "first IPv4 fragment omits entire fragment body");
    put16(frame + 20, 1);
    single_record(frame, length, 34, "later IPv4 fragment does not become fake TCP header");
    length = ipv4(frame, 0, 0, 0);
    put16(frame + 20, 0x4000); /* DF alone is not a fragment. */
    single_record(frame, length, 54, "DF IPv4 still has validated TCP header");
    length = ipv6(frame, 0, 1);
    frame[20] = 44; frame[54] = 6;
    put16(frame + 56, 1); /* first fragment, more flag */
    memcpy(frame + 62, secret, sizeof secret);
    single_record(frame, length, 62, "first IPv6 fragment omits body");
    put16(frame + 56, 8);
    single_record(frame, length, 62, "later IPv6 fragment omits body");
    put16(frame + 56, 0);
    single_record(frame, length, 62, "atomic IPv6 fragment conservatively omits body");
    Snapshot s = snapshot();
    CHECK(json_integer(s.json, "fragment_header_only_frames") == 1, "fragment policy counted");
    CHECK(strstr(s.json, "\"ports_present\":false") != NULL, "fragment ports not invented");
    release_snapshot(&s);
}

static void test_malformed(void) {
    uint8_t frame[1024];
    size_t length;
    begin();
    unsigned rejected = 0;
#define REJECT(size) do { hv_net_capture_record(HV_NET_CAPTURE_TX, frame, (size)); rejected++; } while (0)
    length = ipv4(frame, 0, 0, 0); REJECT(13);
    put16(frame + 12, 0x8100); REJECT(17);
    length = ipv4(frame, 0, 0, 0); frame[14] = 0x65; REJECT(length);
    length = ipv4(frame, 0, 0, 0); frame[14] = 0x44; REJECT(length);
    length = ipv4(frame, 0, 0, 0); put16(frame + 16, 19); REJECT(length);
    length = ipv4(frame, 0, 0, 0); put16(frame + 16, 1000); REJECT(length);
    length = ipv4(frame, 0, 0, 0); frame[46] = 0x40; REJECT(length);
    length = ipv4(frame, 0, 0, 0); put16(frame + 16, 30); REJECT(length);
    length = ipv4(frame, 0, 0, 0); frame[46] = 0xf0; put16(frame + 16, 40); REJECT(length);
    /* Claimed TCP options cannot simply consume an HTTP/token body. */
    length = ipv4(frame, 0, 0, 0); frame[46] = 0xf0; REJECT(length);
    length = ipv4(frame, 1, 0, 0); put16(frame + 38, 7); REJECT(length);
    length = ipv4(frame, 1, 0, 0); put16(frame + 38, 1000); REJECT(length);
    length = ipv4(frame, 0, 4, 0); frame[34] = 7; frame[35] = 8; REJECT(length);
    length = ipv6(frame, 0, 0); frame[14] = 0x40; REJECT(length);
    length = ipv6(frame, 0, 0); put16(frame + 18, 1000); REJECT(length);
    length = ipv6(frame, 0, 1); frame[55] = 200; REJECT(length);
    length = ipv6(frame, 0, 1); frame[56] = 2; frame[57] = 100; REJECT(length);
    length = ipv6(frame, 0, 0); frame[20] = 44; put16(frame + 18, 7); REJECT(length);
    hv_net_capture_record(HV_NET_CAPTURE_TX, NULL, 100); rejected++;
#if SIZE_MAX > UINT32_MAX
    REJECT((size_t)UINT32_MAX + 1);
#endif
#undef REJECT
    Snapshot s = snapshot();
    CHECK(s.length == 24 && pcap_count(&s) == 0, "malformed frames contribute no packet bytes");
    CHECK(json_integer(s.json, "malformed_frames") == rejected, "every malformed frame counted");
    CHECK(json_integer(s.json, "omitted_frames") == rejected, "malformed omissions explicit");
    release_snapshot(&s);
}

static void test_lifecycle_and_time(void) {
    uint8_t frame[1024]; size_t length = ipv4(frame, 0, 0, 0);
    begin();
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    Snapshot first = snapshot();
    atomic_fetch_add(&fixture_ns, UINT64_C(60000000000));
    char launch[37]; snprintf(launch, sizeof launch, "%08x-0000-4000-8000-000000000001", launch_number);
    CHECK(hv_net_capture_start("00112233-4455-4677-8899-aabbccddeeff", launch) == 0, "same UUID case-insensitive start succeeds");
    Snapshot again = snapshot();
    CHECK(first.length == again.length && !memcmp(first.bytes, again.bytes, first.length), "same launch does not reset packets");
    CHECK(json_integer(again.json, "elapsed_ms") == 60000, "same launch does not reset deadline");
    release_snapshot(&first); release_snapshot(&again);
    hv_net_capture_stop(HV_NET_CAPTURE_STOP_BACKGROUND);
    CHECK(hv_net_capture_start(session_id, launch) == 0, "same stopped launch stays idempotent");
    again = snapshot();
    CHECK(strstr(again.json, "\"active\":false") && strstr(again.json, "\"stop_reason\":\"background\""), "same launch does not re-enable capture");
    release_snapshot(&again);
    begin();
    again = snapshot();
    CHECK(again.length == 24 && pcap_count(&again) == 0, "new launch clears prior packet memory");
    CHECK(strstr(again.json, "\"replaced_previous_capture\":true") != NULL, "capture replacement explicit in metadata");
    release_snapshot(&again);
    atomic_store(&fixture_ns, UINT64_C(5000000000) + UINT64_C(120000000000) - 1);
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    atomic_fetch_add(&fixture_ns, 1);
    hv_net_capture_tick();
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    hv_net_capture_stop(HV_NET_CAPTURE_STOP_USER);
    again = snapshot();
    CHECK(pcap_count(&again) == 1, "packet exactly at time limit is not captured");
    CHECK(strstr(again.json, "\"stop_reason\":\"time_limit\"") != NULL, "time limit reason retained");
    CHECK(json_integer(again.json, "elapsed_ms") == 120000, "hard 120-second window");
    CHECK(u32(again.bytes + 24) == 1760000120u && u32(again.bytes + 28) == 123455u, "PCAP time derived from UTC plus monotonic delta");
    release_snapshot(&again);
    begin();
    hv_net_capture_note_rx_drop();
    hv_net_capture_record(HV_NET_CAPTURE_RX, frame, length);
    hv_net_capture_stop(HV_NET_CAPTURE_STOP_VM_STOP);
    again = snapshot();
    CHECK(json_integer(again.json, "rx_delivered_captured_frames") == 1 && json_integer(again.json, "rx_delivery_drops") == 1,
          "RX delivery drop is distinct from captured delivered frame");
    CHECK(pcap_count(&again) == 1 && strstr(again.json, "\"stop_reason\":\"vm_stop\""), "VM stop retains one actual RX record");
    release_snapshot(&again);
    begin();
    atomic_store(&fixture_clock_fails, 1);
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    atomic_store(&fixture_clock_fails, 0);
    again = snapshot();
    CHECK(strstr(again.json, "\"stop_reason\":\"clock_error\"") != NULL && pcap_count(&again) == 0,
          "clock failure closes capture without guessed timestamps");
    release_snapshot(&again);
    begin();
    atomic_store(&fixture_ns, UINT64_C(7000000000));
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    atomic_store(&fixture_ns, UINT64_C(6000000000));
    hv_net_capture_tick();
    again = snapshot();
    CHECK(strstr(again.json, "\"stop_reason\":\"clock_error\"") != NULL, "backwards clock cannot extend capture");
    release_snapshot(&again);
}

static void test_byte_and_flow_limits(void) {
    uint8_t frame[1024]; size_t length = ipv4(frame, 0, 0, 0);
    begin();
    size_t expected = (2097152u - 24u) / (16u + 54u);
    for (size_t i = 0; i < expected + 20; i++) hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    Snapshot s = snapshot();
    CHECK(s.length <= 2097152 && pcap_count(&s) == expected, "PCAP hard 2-MiB bound including record overhead");
    CHECK(strstr(s.json, "\"stop_reason\":\"byte_limit\"") != NULL, "byte limit stops capture");
    CHECK(json_integer(s.json, "byte_limit_omitted_frames") == 1, "first over-limit packet explicitly omitted");
    CHECK(json_integer(s.json, "observed_frames") == expected + 1, "stopped capture does not count subsequent packets");
    release_snapshot(&s);
    begin();
    for (unsigned i = 0; i < 65; i++) {
        frame[33] = (uint8_t)(i + 1);
        hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length);
    }
    s = snapshot();
    CHECK(pcap_count(&s) == 65 && json_integer(s.json, "flow_count") == 64, "flow summary capacity does not discard actual PCAP");
    CHECK(json_integer(s.json, "flow_summary_omitted_frames") == 1, "flow overflow explicitly counted");
    CHECK(strlen(s.json) < 65536, "maximum flow metadata fits fixed JSON bound");
    release_snapshot(&s);
}

typedef struct Producer { uint8_t frame[1024]; size_t length; unsigned count; } Producer;

static void *produce(void *opaque) {
    Producer *producer = opaque;
    for (unsigned i = 0; i < producer->count; i++) hv_net_capture_record(HV_NET_CAPTURE_TX, producer->frame, producer->length);
    return NULL;
}

static void test_concurrent_snapshot(void) {
    begin();
    Producer producer = {.count = 1200};
    producer.length = ipv4(producer.frame, 0, 0, 0);
    pthread_t writers[4];
    for (unsigned i = 0; i < 4; i++) CHECK(pthread_create(&writers[i], NULL, produce, &producer) == 0, "concurrent writer starts");
    for (unsigned i = 0; i < 12; i++) {
        Snapshot s = snapshot();
        (void)pcap_count(&s);
        release_snapshot(&s);
    }
    for (unsigned i = 0; i < 4; i++) CHECK(pthread_join(writers[i], NULL) == 0, "concurrent writer joins");
    Snapshot s = snapshot();
    CHECK(pcap_count(&s) == 4800, "concurrent record/snapshot loses no packet or partial record");
    release_snapshot(&s);
}

static void write_synthetic_export(const char *directory) {
    uint8_t frame[1024];
    begin();
    size_t length = ipv4(frame, 0, 0, 0);
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length); /* local bridge HTTP */
    length = ipv4(frame, 1, 0, 0);
    frame[33] = 3;
    hv_net_capture_record(HV_NET_CAPTURE_RX, frame, length); /* UDP header */
    length = ipv6(frame, 0, 2);
    hv_net_capture_record(HV_NET_CAPTURE_TX, frame, length); /* IPv6 TLS-like flow */
    hv_net_capture_stop(HV_NET_CAPTURE_STOP_USER);
    Snapshot s = snapshot();
    char path[4096];
    snprintf(path, sizeof path, "%s/synthetic-headers.pcap", directory);
    FILE *file = fopen(path, "wb");
    CHECK(file != NULL, "synthetic PCAP export opens");
    if (file) { CHECK(fwrite(s.bytes, 1, s.length, file) == s.length, "synthetic PCAP bytes exported"); fclose(file); }
    snprintf(path, sizeof path, "%s/synthetic-metadata.json", directory);
    file = fopen(path, "wb");
    CHECK(file != NULL, "synthetic metadata export opens");
    if (file) { size_t n = strlen(s.json); CHECK(fwrite(s.json, 1, n, file) == n, "synthetic metadata exported"); fclose(file); }
    release_snapshot(&s);
}

int main(int argc, char **argv) {
    test_no_start();
    test_headers();
    test_fragments();
    test_malformed();
    test_lifecycle_and_time();
    test_byte_and_flow_limits();
    test_concurrent_snapshot();
    if (argc == 2) write_synthetic_export(argv[1]);
    printf("net_capture: %u checks, %u failures; real production parser/capture, synthetic frames only\n", checks, failures);
    fflush(stdout);
    return failures ? 1 : 0;
}
