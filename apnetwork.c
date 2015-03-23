/*
 * modifed from network.c by Ray Bellis
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/in.h>

int ap_bind_to_port(char *host, int port, int family, int type, int backlog)
{
	extern int bind_to_address(struct sockaddr* addr, socklen_t addrlen, int type, int backlog);
	extern int inet_pton(int af, const char * restrict src, void * restrict dst);

	/* set up the local address (protocol specific) */
	if (family == AF_INET) {
		struct sockaddr_in		addr;
		memset(&addr, 0, sizeof(addr));

		addr.sin_family = family;
		(void) inet_pton(AF_INET, host, &(addr.sin_addr));
		addr.sin_port = htons(port);
		return bind_to_address((struct sockaddr *)&addr, sizeof(addr), type, backlog);
	} else if (family == AF_INET6) {
		struct sockaddr_in6		addr;
		memset(&addr, 0, sizeof(addr));

		addr.sin6_family = AF_INET6;
		(void) inet_pton(AF_INET6, host, &(addr.sin6_addr));
		addr.sin6_port = htons(port);
		return bind_to_address((struct sockaddr *)&addr, sizeof(addr), type, backlog);
	} else {
		fprintf(stderr, "address family not recognized\n");
		return -1;
	}
}

/*--------------------------------------------------------------------*/

int ap_bind_to_udp4_port(char *host, int port)
{
	return ap_bind_to_port(host, port, AF_INET, SOCK_DGRAM, 0);
}

int ap_bind_to_tcp4_port(char *host, int port, int backlog)
{
	return ap_bind_to_port(host, port, AF_INET, SOCK_STREAM, backlog);
}

/*--------------------------------------------------------------------*/

int ap_bind_to_udp6_port(char *host, int port)
{
	return ap_bind_to_port(host, port, AF_INET6, SOCK_DGRAM, 0);
}

int ap_bind_to_tcp6_port(char *host, int port, int backlog)
{
	return ap_bind_to_port(host, port, AF_INET6, SOCK_STREAM, backlog);
}
