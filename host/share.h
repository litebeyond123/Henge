#ifndef HENGEVM_SHARE_H
#define HENGEVM_SHARE_H

#include <stddef.h>

/* What the Mac and the device share: a folder and the clipboard (see share.c). The guest reaches this
   at HV_SHARE_ADDR, port 80, which the network hands to the Unix socket. Returns 0, or -1 if the socket
   can't be made. agent is the gzipped helper that runs inside macOS, served to the guest; it may be NULL. */
#define HV_SHARE_ADDR "10.0.2.4"
int hv_share_start(const char *folder, const char *socket_path, const char *agent);

/* The device's clipboard, for the guest to pick up. */
void hv_share_set_clipboard(const char *text);
/* What the guest last copied, once: a malloc'd string, or NULL if nothing is new. */
char *hv_share_take_clipboard(void);
/* Seconds since the helper in macOS was last heard from, or -1 if it never has been. */
long hv_share_agent_seen(void);
/* Malloc-owned, fixed-schema helper liveness/install receipt. Ages use the host monotonic clock. */
char *hv_share_helper_health(void);

/* Version 1 host services, on the same guest-only HTTP transport. A fresh UUID is supplied for each VM
   session; it separates sessions, not processes inside the same guest. No host account/radio APIs live here.
   The owner publishes snapshots from its UI thread. Writes are disabled unless that session is running,
   foreground, opted in, and its snapshot is fresh. Ending a session cancels outstanding requests. */
void hv_share_host_begin(const char *session);
void hv_share_host_end(void);
void hv_share_host_publish(int running, int foreground, int brightness_control, double brightness, double output_volume);
/* Called on the host UI thread. apply must be synchronous, must not call this service recursively, and must
   not run a UI/event loop. It returns the actual brightness, or a negative value if it could not apply it.
   The request is revalidated and completed under one lock, so an expired request cannot execute later.
   Returns 1 after a successful apply, -1 if the callback refused it, or 0 when nothing was applied. */
int hv_share_host_process_brightness(double (*apply)(double));

#endif
