/*
 * based on evldns.h by Ray Bellis
 */

#ifndef APEVLDNS_H
#define APEVLDNS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ap versions of Rays miscellaneous utility functions */
extern int ap_bind_to_port(char *host, int port, int family, int type, int backlog);
extern int ap_bind_to_udp4_port(char *host, int port);
extern int ap_bind_to_udp6_port(char *host, int port);
extern int ap_bind_to_tcp4_port(char *host, int port, int backlog);
extern int ap_bind_to_tcp6_port(char *host, int port, int backlog);

#ifdef __cplusplus
}
#endif

#endif /* APEVLDNS_H */
