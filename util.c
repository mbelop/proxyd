/*
 * Copyright (c) 2011 Mike Belopuhov
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

extern int verbose;

void
log_debug(const char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
log_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
fatalx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void
fatal(const char *msg)
{

	syslog(LOG_ERR, "%s: %m", msg);
	exit(1);
}

in_port_t
pick_port(void)
{
	/* Random should be good enough for avoiding port collisions. */
	return (IPPORT_HIFIRSTAUTO +
	    arc4random_uniform(IPPORT_HILASTAUTO - IPPORT_HIFIRSTAUTO));
}

int
nread(int fd, void *buf, ssize_t len, ssize_t *total, int flags)
{
	ssize_t n;

	*total = 0;
	while (*total < len) {
#if 0
		n = recvfrom(fd, (char *)buf + *total, len - *total, flags,
		    NULL, NULL);
#else
		n = recv(fd, (char *)buf + *total, len - *total, flags);
#endif
		if (n == -1 && errno == EINTR)	/* read was interrupted */
			continue;
		else if (n == -1 && errno == EAGAIN) /* no more data to read */
			return (1);
		else if (n == 0)		/* connection was closed */
			return (0);
		else if (n == -1)		/* error */
			return (-1);
		*total += n;
	}
	return (1);
}

int
nwrite(int fd, void *buf, ssize_t len, ssize_t *total)
{
	ssize_t n;
	int tries = 3;

	*total = 0;
	while (*total < len) {
		n = write(fd, (char *)buf + *total, len - *total);
		if (n == -1 && errno == EINTR)	/* write was interrupted */
			continue;
		if ((n == -1 && errno == EAGAIN) ||
		    (n == 0 && errno == 0)) {	/* undefined behavior */
			if (tries-- > 0)
				continue;
			return (-1);
		}
		if (n <= 0)			/* error */
			return (-1);
		*total += n;
	}
	return (1);
}

int
nwritev(int fd, const struct iovec *iov, int iovcnt)
{
	size_t n;
	int tries = 3;

	while (tries > 0) {
		n = writev(fd, iov, iovcnt);
		if (n == -1 && errno == EINTR)	/* write was interrupted */
			continue;
		if ((n == -1 && errno == EAGAIN) ||
		    (n == 0 && errno == 0))	/* undefined behavior */
			continue;
		if (n <= 0)			/* error */
			return (-1);
		return (1);
	}
	return (-1);
}

int
toread(int fd)
{
	int n = -1;

	if (ioctl(fd, FIONREAD, &n) == -1)
		return (-1);
	return (n);
}

const char *
print_host(struct sockaddr_storage *ss, int printport)
{
	static char sbuf[8][NI_MAXHOST + 7];
	static int idx = 0;
	char pbuf[7], *buf;
	in_port_t port = 0;
	size_t len;

	buf = sbuf[idx];
	len = sizeof(sbuf[idx]);
	if (++idx >= 8)
		idx = 0;

	if (ss->ss_family == AF_UNSPEC) {
		strlcpy(buf, "any", len);
		return (buf);
	}

	if (getnameinfo((struct sockaddr *)ss, ss->ss_len,
	    buf, len, NULL, 0, NI_NUMERICHOST) != 0) {
		buf[0] = '\0';
		return (NULL);
	}

	if (!printport)
		return (buf);

	switch (ss->ss_family) {
	case AF_INET:
		port = ntohs(((struct sockaddr_in *)ss)->sin_port);
	case AF_INET6:
		port = ntohs(((struct sockaddr_in6 *)ss)->sin6_port);
	}

	if (port != 0) {
		snprintf(pbuf, sizeof(pbuf), ":%d", port);
		(void)strlcat(buf, pbuf, len);
	}

	return (buf);
}

int
sock_pton(struct sockaddr_storage *ss, char *addr)
{
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	if (getaddrinfo(addr, NULL, &hints, &res) == 0) {
		bcopy(res->ai_addr, ss, res->ai_addrlen);
		freeaddrinfo(res);
		return (0);
	}

	return (-1);
}

int
sockaddr_cmp(struct sockaddr *a, struct sockaddr *b, int checkport)
{
	struct sockaddr_in	*a4, *b4;
	struct sockaddr_in6	*a6, *b6;

	if (a->sa_family == AF_UNSPEC || b->sa_family == AF_UNSPEC)
		return (0);
	else if (a->sa_family > b->sa_family)
		return (1);
	else if (a->sa_family < b->sa_family)
		return (-1);

	switch (a->sa_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)a;
		b4 = (struct sockaddr_in *)b;

		if (checkport && a4->sin_port != b4->sin_port)
			return (a4->sin_port - b4->sin_port);

		return (a4->sin_addr.s_addr - b4->sin_addr.s_addr);

	case AF_INET6:
		a6 = (struct sockaddr_in6 *)a;
		b6 = (struct sockaddr_in6 *)b;

		if (checkport && a6->sin6_port != b6->sin6_port)
			return (a6->sin6_port - b6->sin6_port);

		return (bcmp(&a6->sin6_addr, &b6->sin6_addr, a6->sin6_len));
	}

	return (0);
}
