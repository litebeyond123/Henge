#ifndef HENGE_HELPER_VERSION_H
#define HENGE_HELPER_VERSION_H

/* The executable and its live heartbeat must describe the same running build.
 * The standalone installer and bundle metadata are checked against these values
 * by tests/test_helper_install.py. The health wire stays compatible with Helper 4. */
#define HENGE_HELPER_VERSION 11
/* Capability 4 binds a normal or explicitly requested forced quit to each
 * launch and verifies the target's kernel process identity and observes a bounded
 * kernel exit transition before restarting. */
#define HENGE_HELPER_AUTH_EXPERIMENT_PROTOCOL 4
#define HENGE_HELPER_HEALTH_PROTOCOL 4

#define HENGE_HELPER_STRINGIFY_INNER(value) #value
#define HENGE_HELPER_STRINGIFY(value) HENGE_HELPER_STRINGIFY_INNER(value)
#define HENGE_HELPER_VERSION_TEXT "henge-agent " HENGE_HELPER_STRINGIFY(HENGE_HELPER_VERSION)

#endif
