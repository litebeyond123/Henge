#ifndef HENGEVM_NET_CAPTURE_H
#define HENGEVM_NET_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A single current capture, retained in memory after it stops. These are hard
   limits, including the PCAP global/record headers. No packet payload is saved. */
#define HV_NET_CAPTURE_MAX_BYTES (2u * 1024u * 1024u)
#define HV_NET_CAPTURE_MAX_SECONDS 120u
#define HV_NET_CAPTURE_MAX_FLOWS 64u
#define HV_NET_CAPTURE_MAX_HEADER 512u

typedef enum HvNetCaptureStopReason {
    HV_NET_CAPTURE_STOP_USER = 1,
    HV_NET_CAPTURE_STOP_BACKGROUND,
    HV_NET_CAPTURE_STOP_VM_STOP,
    HV_NET_CAPTURE_STOP_TIME_LIMIT,
    HV_NET_CAPTURE_STOP_BYTE_LIMIT,
    HV_NET_CAPTURE_STOP_CLOCK_ERROR
} HvNetCaptureStopReason;

typedef enum HvNetCaptureDirection {
    HV_NET_CAPTURE_TX = 1, /* guest Ethernet transmit, before the DNS/NAT path */
    HV_NET_CAPTURE_RX      /* actually delivered to a guest receive buffer */
} HvNetCaptureDirection;

/* 0 on success, otherwise an errno value. Both identifiers must be UUIDs.
   Repeating the same pair (even after stop) is a no-op. A different pair
   replaces the previous capture; snapshot it before starting another one if
   it must be retained. This API does not itself authorize authentication. */
int hv_net_capture_start(const char *session, const char *launch_id);
void hv_net_capture_stop(HvNetCaptureStopReason reason);

/* Packet-path operations: bounded parsing/copying only, no allocation, file
   I/O or logging. Truncated/malformed frames are omitted and counted. Unknown
   protocols retain only the preceding verified headers. All IP fragments
   stop at the IP (or IPv6 fragment) header; no fragment body is retained.
   Direction is metadata, not a process attribution or an HTTP status. */
void hv_net_capture_record(HvNetCaptureDirection direction, const uint8_t *frame, size_t length);
void hv_net_capture_note_rx_drop(void);
void hv_net_capture_tick(void);

/* malloc-owned JSON, freed by the caller. NULL means allocation failure.
   Use the paired snapshot for export, so JSON and PCAP describe one state. */
char *hv_net_capture_metadata_json(void);

/* Atomic pair, 0 or errno. Outputs are initialized to NULL/0 on failure.
   On success the caller frees both pointers. A capture that has never started
   returns status=not_started metadata, NULL PCAP and length=0. An active
   snapshot is a valid PCAP prefix; exporting it does not stop capture.
   Call off the UI thread: it may copy up to 2 MiB while holding a short lock. */
int hv_net_capture_snapshot(char **metadata_json, uint8_t **pcap, size_t *pcap_length);

#ifdef __cplusplus
}
#endif

#endif
