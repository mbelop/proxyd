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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <login_cap.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "proxy.h"

struct bindreq {
	struct sockaddr_storage	 addr;
	int			 family;
	int			 proto;
	uint			 id;
};

TAILQ_HEAD(, session) bindq = TAILQ_HEAD_INITIALIZER(bindq);

struct backend backends[] = {
	{
		BF_TCP | BF_IPV6 | BF_TRANSP,
		8521,
		tns_connect,
		tns_header_size,
		tns_packet_size,
		tns_client,
		tns_server,
		tns_disconnect
	},
	{
		BF_TCP | BF_UDP | BF_IPV6 | BF_TRANSP | BF_SAFEBUF,
		8111,
		sunrpc_connect,
		sunrpc_header_size,
		sunrpc_packet_size,
		sunrpc_client,
		sunrpc_server,
		sunrpc_disconnect
	},
	{
		BF_TCP | BF_TRANSP | BF_SAFEBUF,
		8135,
		msrpc_connect,
		msrpc_header_size,
		msrpc_packet_size,
		msrpc_client,
		msrpc_server,
		msrpc_disconnect
	},
};

struct conf 	conf = {
		.transparent =	1,
		.connect_tv =	{ .tv_sec = 10 },
		.idle_tv =	{ .tv_sec = 600 }
};

uint		session_id;
int		binder_socket, verbose;
char		inbuf[PROXY_BUFSIZE], outbuf[PROXY_BUFSIZE];

void		dispatch_client_tcp(struct bufferevent *, void *);
void		dispatch_server_tcp(struct bufferevent *, void *);
void		dispatch_error(struct bufferevent *, short, void *);
void		dispatch_client_udp(int, short, void *);
void		dispatch_server_udp(int, short, void *);

void		dispatch_tcp(int, short, void *);
void		tcp_setup_serverfd(struct session *, int);

void		dispatch_udp(int, short, void *);
void		udp_setup_clientfd(struct session *, int);
void		udp_setup_serverfd(struct session *, int);

void		complete_connect(int, short, void *);

void		binder_done(int, short, void *);
void		binder_dispatch(int, short, void *);
void		binder_init(int);

int		map_address(struct proxy *, struct sockaddr *,
		    struct sockaddr *);
const char *	print_peer(struct session *, int);

void		setup_listener(struct listener *, struct proxy *);
void		setup_listener_do(struct sockaddr *, int, void *);


static __inline int
session_cmp(struct session *a, struct session *b)
{
	int diff;

	diff = a->client_rd - b->client_rd;
	if (!diff)
		diff = a->proto - b->proto;
	if (!diff)
		diff = sockaddr_cmp(sstosa(&a->client_ss),
		    sstosa(&b->client_ss), 1);
	if (!diff)
		diff = sockaddr_cmp(sstosa(&a->oserver_ss),
		    sstosa(&b->oserver_ss), 1);
	return (diff);
}

SPLAY_HEAD(proxy_sessions, session) sessions = SPLAY_INITIALIZER();
SPLAY_PROTOTYPE(proxy_sessions, session, entry, session_cmp);
SPLAY_GENERATE(proxy_sessions, session, entry, session_cmp);

void
dispatch_client_tcp(struct bufferevent *bev, void *arg)
{
	struct session *s = arg;
	ssize_t hdrlen, pktlen, outlen;
	char *ibp = inbuf, *obp = outbuf;
	int n, ret;

	if (s->flags & SF_FORWARD) {
		n = BEV_LENGTH(bev);
		if ((n = proxy_write_server(s, BEV_DATA(bev), n)) <= 0)
			goto errout;
		evbuffer_drain(EVBUFFER_INPUT(bev), n);
		return;
	}

	hdrlen = backend_header_size(s);
	pktlen = backend_packet_size(s, BEV_DATA(bev), hdrlen);
	if (pktlen <= 0 || pktlen >= PROXY_BUFSIZE) {
		log_debug("#%u invalid packet length %d", s->id, pktlen);
		goto errout;
	}

	if (BEV_LENGTH(bev) < pktlen) {
		bufferevent_setwatermark(bev, EV_READ, pktlen, PROXY_BUFSIZE);
		return;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		ibp = BEV_DATA(bev);
		obp = ibp;
	} else {
		if (bufferevent_read(bev, inbuf, pktlen) != pktlen)
			goto errout;
	}

	ret = backend_client(s, ibp, pktlen, &obp, &outlen);
	switch (ret) {
	case B_ERROR:
		log_debug("#%u protocol handling failed", s->id);
		goto errout;
	case B_UNKNOWN:
		s->flags |= SF_FORWARD;
		break;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		n = BEV_LENGTH(bev);
		if ((n = proxy_write_server(s, BEV_DATA(bev), n)) <= 0)
			goto errout;
		evbuffer_drain(EVBUFFER_INPUT(bev), n);
	} else {
		if (proxy_write_server(s, obp, outlen) <= 0)
			goto errout;
	}

	if (BEV_LENGTH(bev) > 0)
		return (dispatch_client_tcp(bev, s));

	return;

 errout:
	proxy_end_session(s);
}

void
dispatch_server_tcp(struct bufferevent *bev, void *arg)
{
	struct session *s = arg;
	ssize_t hdrlen, pktlen, outlen;
	char *ibp = inbuf, *obp = outbuf;
	int n, ret;

	if (s->flags & SF_FORWARD) {
		n = BEV_LENGTH(bev);
		if ((n = proxy_write_client(s, BEV_DATA(bev), n)) <= 0)
			goto errout;
		evbuffer_drain(EVBUFFER_INPUT(bev), n);
		return;
	}

	hdrlen = backend_header_size(s);
	pktlen = backend_packet_size(s, BEV_DATA(bev), hdrlen);
	if (pktlen <= 0 || pktlen >= PROXY_BUFSIZE) {
		log_debug("#%u invalid packet length %d", s->id, pktlen);
		goto errout;
	}

	if (BEV_LENGTH(bev) < pktlen) {
		bufferevent_setwatermark(bev, EV_READ, pktlen, PROXY_BUFSIZE);
		return;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		ibp = BEV_DATA(bev);
		obp = ibp;
	} else {
		if (bufferevent_read(bev, inbuf, pktlen) != pktlen)
			goto errout;
	}

	ret = backend_server(s, ibp, pktlen, &obp, &outlen);
	switch (ret) {
	case B_ERROR:
		log_debug("#%u protocol handling failed", s->id);
		goto errout;
	case B_UNKNOWN:
		s->flags |= SF_FORWARD;
		break;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		n = BEV_LENGTH(bev);
		if ((n = proxy_write_client(s, BEV_DATA(bev), n)) <= 0)
			goto errout;
		evbuffer_drain(EVBUFFER_INPUT(bev), n);
	} else {
		if (proxy_write_client(s, obp, outlen) <= 0)
			goto errout;
	}

	if (BEV_LENGTH(bev) > 0)
		return (dispatch_server_tcp(bev, s));

	return;

 errout:
	proxy_end_session(s);
}

struct map {
	uint	bit;
	char *	name;
} evb_flags[] = {
	{ EVBUFFER_READ,	"READ" },
	{ EVBUFFER_WRITE,	"WRITE" },
	{ EVBUFFER_EOF,		"EOF" },
	{ EVBUFFER_ERROR,	"ERROR" },
	{ EVBUFFER_TIMEOUT,	"TIMEOUT" },
	{ 0,			"" },
}, ev_flags[] = {
	{ EV_TIMEOUT,		"TIMEOUT" },
	{ EV_READ,		"READ" },
	{ EV_WRITE,		"WRITE" },
	{ EV_SIGNAL,		"SIGNAL" },
	{ EV_PERSIST,		"PERSIST" },
	{ 0,			""},
};

char *
print_flags(uint mask, struct map *map)
{
	static char buf[80];
	int i;

	bzero(buf, sizeof(buf));
	for (i = 0; map[i].bit; i++) {
		if (mask & map[i].bit) {
			if (strlen(buf) > 0)
				strlcat(buf, ",", sizeof(buf));
			strlcat(buf, map[i].name, sizeof(buf));
		}
	}
	return (buf);
}

void
dispatch_error(struct bufferevent *bev, short event, void *arg)
{
	struct session *s = arg;

	if (verbose > 1)
		log_debug("#%u error event %#x<%s>", s->id, event,
		    print_flags(event, evb_flags));

	if (event & EVBUFFER_EOF)
		log_debug("#%u %s closed connection", s->id,
		    print_peer(s, BEV_FD(bev)));
	else if (event == (EVBUFFER_ERROR | EVBUFFER_READ))
		log_debug("#%u connection reset", s->id);
	else if (event & EVBUFFER_TIMEOUT)
		log_debug("#%u connection timed out", s->id);
	else if (event & EVBUFFER_WRITE)
		log_debug("#%u %s write error", s->id,
		    print_peer(s, BEV_FD(bev)));
	else
		log_debug("#%u unknown connection error", s->id);

	proxy_end_session(s);
}

void
dispatch_client_udp(int fd, short event, void *arg)
{
	struct session *s = arg;
	ssize_t pktlen, outlen;
	char *obp = outbuf;
	int ret;

	if (fd == -1 && s->datalen) {
		log_debug("#%u processing %d bytes of data", s->id, s->datalen);
		ret = backend_client(s, s->data, s->datalen, &obp, &outlen);
		switch (ret) {
		case B_ERROR:
			log_debug("#%u protocol handling failed", s->id);
			goto errout;
		case B_UNKNOWN:
			s->flags |= SF_FORWARD;
			break;
		}
		if (BFLAGS(s) & BF_SAFEBUF)
			ret = proxy_write_server(s, s->data, s->datalen);
		else
			ret = proxy_write_server(s, obp, outlen);
		free(s->data);
		s->data = NULL;
		s->datalen = 0;
		if (ret <= 0)
			goto errout;
		log_debug("ret=%d", ret);
		return;
	}

	if (verbose > 1)
		log_debug("#%u udp client event=%#x<%s>", s->id, event,
		    print_flags(event, ev_flags));

	if (event & EV_TIMEOUT) {
		log_debug("#%u connection timed out", s->id);
		goto errout;
	}

	if (s->flags & SF_FORWARD) {
		if (proxy_drain_client(s, inbuf, PROXY_BUFSIZE) < 0)
			goto errout;
		/* update server timeout */
		event_add(&s->server_ev, TIMEOUT_IDLE(s));
		return;
	}

	pktlen = toread(fd);
	if (pktlen <= 0 || (pktlen = proxy_read_client(s, inbuf, pktlen)) <= 0)
		goto errout;

	ret = backend_client(s, inbuf, pktlen, &obp, &outlen);
	switch (ret) {
	case B_ERROR:
		log_debug("#%u protocol handling failed", s->id);
		goto errout;
	case B_UNKNOWN:
		s->flags |= SF_FORWARD;
		break;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		if (proxy_write_server(s, inbuf, pktlen) <= 0)
			goto errout;
	} else {
		if (proxy_write_server(s, obp, outlen) <= 0)
			goto errout;
	}

	/* update server timeout */
	event_add(&s->server_ev, TIMEOUT_IDLE(s));
	return;

 errout:
	proxy_end_session(s);
}

void
dispatch_server_udp(int fd, short event, void *arg)
{
	struct session *s = arg;
	ssize_t pktlen, outlen;
	char *obp = outbuf;
	int ret;

	if (verbose > 1)
		log_debug("#%u udp server event=%#x<%s>", s->id, event,
		    print_flags(event, ev_flags));

	if (event & EV_TIMEOUT) {
		log_debug("#%u connection timed out", s->id);
		goto errout;
	}

	if (s->flags & SF_FORWARD) {
		if (proxy_drain_server(s, inbuf, PROXY_BUFSIZE) < 0)
			goto errout;
		/* update client timeout */
		event_add(&s->client_ev, TIMEOUT_IDLE(s));
		return;
	}

	pktlen = toread(fd);
	if (pktlen <= 0 || (pktlen = proxy_read_server(s, inbuf, pktlen)) <= 0)
		goto errout;

	ret = backend_server(s, inbuf, pktlen, &obp, &outlen);
	switch (ret) {
	case B_ERROR:
		log_debug("#%u protocol handling failed", s->id);
		goto errout;
	case B_UNKNOWN:
		s->flags |= SF_FORWARD;
		break;
	}

	if (BFLAGS(s) & BF_SAFEBUF) {
		if (proxy_write_client(s, inbuf, pktlen) <= 0)
			goto errout;
	} else {
		if (proxy_write_server(s, obp, outlen) <= 0)
			goto errout;
	}

	/* update client timeout */
	event_add(&s->client_ev, TIMEOUT_IDLE(s));
	return;

 errout:
	proxy_end_session(s);
}

int
proxy_detectloop(struct sockaddr_storage *peer, int proto)
{
	struct sockaddr_storage ss;
	int sock, loop = 0;

	bcopy(peer, &ss, peer->ss_len);
	satosin(&ss)->sin_port = 0;

	/* logic is simple: if we can bind to this address then it's ours */

	if ((sock = socket(ss.ss_family, proto == IPPROTO_TCP ?
	    SOCK_STREAM : SOCK_DGRAM, proto)) == -1)
		return (-1);
	if (bind(sock, sstosa(&ss), ss.ss_len) != -1)
		loop = 1;
	close(sock);

	return (loop);
}

void
dispatch_tcp(int fd, short event, void *arg)
{
	struct proxy *p = arg;
	struct session *s;
	struct bindreq req;
	socklen_t len;

	if ((s = calloc(1, sizeof(*s))) == NULL) {
		log_warn("failed to allocate memory");
		return;
	}
	s->proto = IPPROTO_TCP;
	s->id = session_id++;
	s->client_fd = s->server_fd = -1;

	s->proxy = p;
	if (p->transparent && (BFLAGS(s) & BF_TRANSP) != 0)
		s->flags |= SF_TRANSPARENT;
	if (backend_connect(s)) {
		free(s);
		return;
	}

	len = sizeof(s->client_ss);
	if ((s->client_fd =
	    accept(fd, sstosa(&s->client_ss), &len)) < 0) {
		log_warn("#%u accept failed: %m", s->id);
		free(s);
		errno = 0;
		return;
	}

	len = sizeof(s->client_rd);
	if (getsockopt(s->client_fd, SOL_SOCKET, SO_RTABLE, &s->client_rd,
	    &len) && errno != ENOPROTOOPT) {
		log_warn("#%u getsockopt SO_RTABLE: %m", s->id);
		close(s->client_fd);
		free(s);
		errno = 0;
		return;
	}

	len = sizeof(s->oserver_ss);
	if (getsockname(s->client_fd, sstosa(&s->oserver_ss), &len)) {
		log_warn("#%u getsockname: %m", s->id);
		close(s->client_fd);
		free(s);
		errno = 0;
		return;
	}

	if (map_address(s->proxy, sstosa(&s->oserver_ss),
	    sstosa(&s->server_ss)) > 0) {
		log_debug("#%u connection from %s to %s (%s)", s->id,
		    print_host(&s->client_ss, 1), print_host(&s->server_ss, 1),
		    print_host(&s->oserver_ss, 1));
		s->flags |= SF_REDIRECT;
		s->port = pick_port();
	} else {
		log_debug("#%u connection from %s to %s", s->id,
		    print_host(&s->client_ss, 1), print_host(&s->oserver_ss, 1));

		/*
		 * verify that we're not asked to connect to ourselves;
		 * with transparent proxies this will lead to a divert loop
		 */
		if ((s->flags & SF_TRANSPARENT) &&
		    proxy_detectloop(&s->oserver_ss, IPPROTO_TCP)) {
			log_warn("#%u refused connection to ourselves", s->id);
			close(s->client_fd);
			free(s);
			errno = 0;
			return;
		}

		bcopy(&s->oserver_ss, &s->server_ss, s->oserver_ss.ss_len);
	}

	if (!(s->flags & SF_TRANSPARENT))
		return (tcp_setup_serverfd(s, -1));

	/* call binder to get a bindany socket */
	bzero(&req, sizeof(req));
	bcopy(&s->client_ss, &req.addr, s->client_ss.ss_len); /* XXX: !af-to */
	req.family = s->client_ss.ss_family;
	req.proto = IPPROTO_TCP;
	req.id = s->id;
	if (write(binder_socket, &req, sizeof(req)) != sizeof(req))
		fatal("binder write");
	TAILQ_INSERT_TAIL(&bindq, s, bindq);

	s->binder_done_cb = tcp_setup_serverfd;

	/* processing continues in tcp_setup_serverfd */
}

void
tcp_setup_serverfd(struct session *s, int sock)
{
	int on;

	if (!(s->flags & SF_TRANSPARENT) &&
	    (sock = socket(s->server_ss.ss_family, SOCK_STREAM,
	     IPPROTO_TCP)) < 0) {
		log_warn("failed to allocate new socket: %m");
		goto errout;
	}

	if (sock < 0)
		goto errout;

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
	    sizeof(on))) {
		log_warn("#%u setsockopt SO_REUSEADDR: %m", s->id);
		goto errout;
	}

	if ((on = fcntl(sock, F_GETFL)) == -1 ||
	    fcntl(sock, F_SETFL, on | O_NONBLOCK)) {
		log_warn("#%u fcntl O_NONBLOCK: %m", s->id);
		goto errout;
	}

	s->server_fd = sock;

	if (connect(sock, sstosa(&s->server_ss), s->server_ss.ss_len) != -1 &&
	    errno != EINPROGRESS) {
		log_warn("#%u connect failed: %m", s->id);
		goto errout;
	}

	errno = 0;
	event_set(&s->server_ev, sock, EV_WRITE | EV_TIMEOUT,
	    complete_connect, s);
	event_add(&s->server_ev, TIMEOUT_CONNECT(s));

	return;

 errout:
	if (sock >= 0)
		close(sock);
	close(s->client_fd);
	free(s);
	errno = 0;
}

void
dispatch_udp(int fd, short event, void *arg)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(struct sockaddr_storage)) +
		    CMSG_SPACE(sizeof(in_port_t)) + CMSG_SPACE(sizeof(uint))];
	} cmsgbuf;
	struct proxy *p = arg;
	struct sockaddr_storage src, dst;
	struct sockaddr_in *sin;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct session key, *s;
	struct bindreq req;
	uint rdomain;
	in_port_t port;
	//char dummy[1];
	int len;

	if ((len = toread(fd)) < 0) {
		log_warn("nothing to read");
		goto discard;
	}

	bzero(&msg, sizeof(msg));
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if (recvmsg(fd, &msg, MSG_PEEK) < 0) {
		log_warn("recvmsg failed");
		goto discard;
	}

	sin = satosin(&dst);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP)
			continue;
		if (cmsg->cmsg_type == IP_RECVDSTADDR) {
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			bcopy(CMSG_DATA(cmsg), &sin->sin_addr,
			    sizeof(sin->sin_addr));
		}
		if (cmsg->cmsg_type == IP_RECVDSTPORT) {
			bcopy(CMSG_DATA(cmsg), &port, sizeof(port));
			sin->sin_port = port;
		}
		if (cmsg->cmsg_type == IP_RECVRTABLE)
			bcopy(CMSG_DATA(cmsg), &rdomain, sizeof(rdomain));
	}

	bcopy(&src, &key.client_ss, src.ss_len);
	bcopy(&dst, &key.oserver_ss, dst.ss_len);
	key.client_rd = rdomain;
	key.proto = IPPROTO_UDP;
	if ((s = SPLAY_FIND(proxy_sessions, &sessions, &key)) != NULL) {
		log_warn("duplicate session from %s to %s rdomain %d, id %u",
		    print_host(&src, 1), print_host(&dst, 1), rdomain, s->id);
		goto discard;
	}

	if ((s = calloc(1, sizeof(*s))) == NULL) {
		log_warn("failed to allocate memory for a datagram");
		goto discard;
	}

	/* if chunk is too big, discard it */
	if (len >= PROXY_BUFSIZE || (s->data = malloc(len + 1)) == NULL) {
		log_warn("datagram is too big");
		goto discard;
	}

	if (nread(fd, s->data, len, &s->datalen, 0) < 0) {
		log_warn("failed to read a datagram");
		free(s);
		errno = 0;
		return;
	}

	bcopy(&src, &s->client_ss, src.ss_len);
	bcopy(&dst, &s->oserver_ss, dst.ss_len);
	s->proto = IPPROTO_UDP;
	s->id = session_id++;
	s->client_rd = rdomain;
	s->client_fd = s->server_fd = -1;

	s->proxy = p;
	if (p->transparent && (BFLAGS(s) & BF_TRANSP) != 0)
		s->flags |= SF_TRANSPARENT;
	if (backend_connect(s)) {
		free(s);
		return;
	}

	if (map_address(s->proxy, sstosa(&s->oserver_ss),
	    sstosa(&s->server_ss)) > 0) {
		log_debug("#%u datagram from %s to %s (%s)", s->id,
		    print_host(&s->client_ss, 1), print_host(&s->server_ss, 1),
		    print_host(&s->oserver_ss, 1));
		s->flags |= SF_REDIRECT;
		s->port = pick_port();
	} else {
		log_debug("#%u datagram from %s to %s", s->id,
		    print_host(&s->client_ss, 1),
		    print_host(&s->oserver_ss, 1));

		/*
		 * verify that we're not asked to connect to ourselves;
		 * with transparent proxies this will lead to a divert loop
		 */
		if (proxy_detectloop(&s->oserver_ss, IPPROTO_UDP)) {
			log_warn("#%u refused connection to ourselves", s->id);
			free(s);
			errno = 0;
			return;
		}

		bcopy(&s->oserver_ss, &s->server_ss, s->oserver_ss.ss_len);
	}

	/*
	 * set up a socket that will be used to talk to client.  it has to be
	 * bound to the server address and port so that the packets will look
	 * like valid replies from the server.
	 */

	/* call binder to get a bindany socket */
	bzero(&req, sizeof(req));
	bcopy(&s->oserver_ss, &req.addr, s->oserver_ss.ss_len);
	req.family = s->oserver_ss.ss_family;
	req.proto = IPPROTO_UDP;
	req.id = s->id;
	if (write(binder_socket, &req, sizeof(req)) != sizeof(req))
		fatal("binder write");
	TAILQ_INSERT_TAIL(&bindq, s, bindq);

	s->binder_done_cb = &udp_setup_clientfd;

	/* processing continues in udp_setup_clientfd */

	return;

 discard:
	/* discard the data */
	//(void)recvfrom(fd, dummy, sizeof(dummy), 0, NULL, NULL);
	(void)recv(fd, NULL, 0, 0);
	errno = 0;
}

void
udp_setup_clientfd(struct session *s, int sock)
{
	struct bindreq req;
	int on = 1;

	if (sock < 0)
		goto errout;

	if (connect(sock, sstosa(&s->client_ss), s->client_ss.ss_len) < 0) {
		log_warn("#%u connect failed: %m", s->id);
		goto errout;
	}

	if ((on = fcntl(sock, F_GETFL)) == -1 ||
	    fcntl(sock, F_SETFL, on | O_NONBLOCK)) {
		log_warn("#%u fcntl O_NONBLOCK: %m", s->id);
		goto errout;
	}

	s->client_fd = sock;

	if (!(s->flags & SF_TRANSPARENT))
		return (udp_setup_serverfd(s, -1));

	/* call binder to get a bindany socket */
	bzero(&req, sizeof(req));
	bcopy(&s->client_ss, &req.addr, s->client_ss.ss_len); /* XXX: !af-to */
	req.family = s->server_ss.ss_family;
	req.proto = IPPROTO_UDP;
	req.id = s->id;
	if (write(binder_socket, &req, sizeof(req)) != sizeof(req))
		fatal("binder write");
	TAILQ_INSERT_TAIL(&bindq, s, bindq);

	s->binder_done_cb = &udp_setup_serverfd;

	return;

 errout:
	if (sock >= 0)
		close(sock);
	free(s);
	errno = 0;
}

void
udp_setup_serverfd(struct session *s, int sock)
{
	int on = 1;

	if (!(s->flags & SF_TRANSPARENT) &&
	    (sock = socket(s->server_ss.ss_family, SOCK_DGRAM,
	     IPPROTO_UDP)) < 0) {
		log_warn("failed to allocate new socket: %m");
		goto errout;
	}

	if (sock < 0)
		goto errout;

	if (connect(sock, sstosa(&s->server_ss), s->server_ss.ss_len) < 0) {
		log_warn("#%u connect failed: %m", s->id);
		goto errout;
	}

	if ((on = fcntl(sock, F_GETFL)) == -1 ||
	    fcntl(sock, F_SETFL, on | O_NONBLOCK)) {
		log_warn("#%u fcntl O_NONBLOCK: %m", s->id);
		goto errout;
	}

	s->server_fd = sock;

	return (complete_connect(s->server_fd, EV_READ, s));

 errout:
	if (sock >= 0)
		close(sock);
	close(s->client_fd);
	free(s);
	errno = 0;
}

void
complete_connect(int fd, short event, void *arg)
{
	struct session *dup, *s = arg;
	socklen_t len;
	size_t n;
	int error = 0, on = 1;

	if (event == EV_TIMEOUT) {
		log_warn("#%u connection to %s timed out", s->id,
		    print_host(&s->server_ss, 1));
		goto errout;
	}

	len = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
		log_warn("#%u getsockopt SO_ERROR: %m", s->id);
		goto errout;
	}
	if (error) {
		log_warn("#%u %s is not available", s->id,
		    print_host(&s->server_ss, 1));
		goto errout;
	}

	len = sizeof(s->proxy_ss);
	if (getsockname(fd, sstosa(&s->proxy_ss), &len)) {
		log_warn("#%u getsockname: %m", s->id);
		goto errout;
	}

	if (s->proto == IPPROTO_TCP) {
		setsockopt(s->client_fd, SOL_SOCKET, SO_KEEPALIVE, &on,
		    sizeof(on));
		setsockopt(s->server_fd, SOL_SOCKET, SO_KEEPALIVE, &on,
		    sizeof(on));

		if ((s->client_bev = bufferevent_new(s->client_fd,
		    dispatch_client_tcp, NULL, dispatch_error, s)) == NULL) {
			log_warn("#%u bufferevent_new: %m", s->id);
			goto errout;
		}
		if ((s->server_bev = bufferevent_new(s->server_fd,
		    dispatch_server_tcp, NULL, dispatch_error, s)) == NULL) {
			log_warn("#%u bufferevent_new: %m", s->id);
			goto errout;
		}

		n = backend_header_size(s);

		bufferevent_settimeout(s->client_bev,
		    TIMEOUT_IDLE(s)->tv_sec, 0);
		bufferevent_setwatermark(s->client_bev, EV_READ, n,
		    PROXY_BUFSIZE);
		bufferevent_enable(s->client_bev, EV_READ | EV_TIMEOUT);

		bufferevent_settimeout(s->server_bev,
		    TIMEOUT_IDLE(s)->tv_sec, 0);
		bufferevent_setwatermark(s->server_bev, EV_READ, n,
		    PROXY_BUFSIZE);
		bufferevent_enable(s->server_bev, EV_READ | EV_TIMEOUT);
	} else {
		event_set(&s->client_ev, s->client_fd, EV_READ | EV_PERSIST,
		    dispatch_client_udp, s);
		event_add(&s->client_ev, TIMEOUT_IDLE(s));

		event_set(&s->server_ev, s->server_fd, EV_READ | EV_PERSIST,
		    dispatch_server_udp, s);
		event_add(&s->server_ev, TIMEOUT_IDLE(s));
	}

	if ((dup = SPLAY_INSERT(proxy_sessions, &sessions, s)) != NULL) {
		log_warn("#%u session exists, id %u", s->id, dup->id);
		goto errout;
	}

	log_debug("#%u connected to %s", s->id, print_host(&s->server_ss, 1));

	/* process s->data */
	if (s->proto == IPPROTO_UDP)
		return (dispatch_client_udp(-1, EV_READ, s));

	return;

 errout:
	proxy_end_session(s);
}

void
binder_done(int fd, short event, void *arg)
{
	struct session *s;
	uint id;
	int sock = -1;

	if ((sock = receive_fd(fd, &id)) == -1) {
		errno = 0;
		return;
	}

	TAILQ_FOREACH(s, &bindq, bindq) {
		if (s->id == id)
			break;
	}
	if (!s) {
		log_warn("binder_done: %u is not on the queue", id);
		close(sock);
		return;
	}
	TAILQ_REMOVE(&bindq, s, bindq);

	if (s->binder_done_cb)
		s->binder_done_cb(s, sock);
	else {
		log_warn("binder_done: callback is not set");
		if (s->client_fd >= 0)
			close(s->client_fd);
		if (s->server_fd >= 0)
			close(s->server_fd);
		free(s);
		errno = 0;
	}
}

void
binder_dispatch(int fd, short event, void *arg)
{
	struct bindreq req;
	size_t n;
	int ret, on = 1, sock = -1;

	if ((ret = nread(fd, &req, sizeof(req), &n, 0)) < 0)
		fatal("read");
	if (ret == 0)
		fatalx("parent died");
	if (n != sizeof(req))
		fatal("short read");

	if ((sock = socket(req.family, req.proto == IPPROTO_TCP ?
	    SOCK_STREAM : SOCK_DGRAM, req.proto)) < 0) {
		log_warn("failed to allocate new socket: %m");
		goto errout;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &on, sizeof(on))) {
		log_warn("setsockopt SO_BINDANY: %m");
		goto errout;
	}

	if (req.addr.ss_len > 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof(on))) {
			log_warn("setsockopt SO_REUSEADDR: %m");
			goto errout;
		}
		if (bind(sock, sstosa(&req.addr), req.addr.ss_len)) {
			log_warn("bind failed: %m");
			goto errout;
		}
	}

	if (send_fd(fd, sock, req.id))
		fatalx("send_fd");

	close(sock);
	return;

 errout:
	if (sock >= 0)
		close(sock);
	send_fd(fd, -1, req.id);
}

void
binder_init(int nodaemon)
{
	struct passwd *pw;
	struct event ev;
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1)
		err(1, "socketpair");

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		close(sp[0]);
		break;
	default:
		binder_socket = sp[0];
		close(sp[1]);
		return;
	}

	setproctitle("binder");

	openlog("proxyd-binder",
	    LOG_NDELAY | (nodaemon ? LOG_PERROR : LOG_PID), LOG_DAEMON);

	if ((pw = getpwnam(PROXYD_USER)) == NULL)
		fatalx("%s: no such user", PROXYD_USER);
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid))
		fatal("failed to drop group privileges");

	event_init();

	event_set(&ev, sp[1], EV_READ | EV_PERSIST, binder_dispatch, NULL);
	event_add(&ev, NULL);

	event_dispatch();

	exit(0);
}

ssize_t
proxy_read(struct session *s, int fd, void *buf, ssize_t len)
{
	ssize_t n;

	if (nread(fd, buf, len, &n, 0) <= 0) {
		log_debug("#%u %s hung up", s->id, print_peer(s, fd));
		return (-1);
	}

	if (n != len) {
		log_debug("#%u short read", s->id);
		return (-1);
	}

	return (n);
}
#if 0
ssize_t
proxy_peek(struct session *s, int fd, void *buf, ssize_t len)
{
	ssize_t n;

	if (nread(fd, buf, len, &n, MSG_PEEK) < 0) {
		log_debug("#%u %s hung up", s->id, print_peer(s, fd));
		proxy_end_session(s);
		return (-1);
	}
	if (n != len) {
		log_debug("#%u short peek", s->id);
		proxy_end_session(s);
		return (-1);
	}

	return (n);
}
#endif
ssize_t
proxy_write(struct session *s, int fd, void *buf, ssize_t len)
{
	ssize_t n;

	if (nwrite(fd, buf, len, &n) < 0) {
		log_debug("#%u %s hung up", s->id, print_peer(s, fd));
		return (-1);
	}
	if (n < len) {
		log_debug("#%u write failed", s->id);
		return (-1);
	}

	return (n);
}

ssize_t
proxy_writev(struct session *s, int fd, const struct iovec *iov, int iovcnt)
{

	if (nwritev(fd, iov, iovcnt) < 0) {
		log_debug("#%u scatter gather write failed for %s", s->id,
		    print_peer(s, fd));
		return (-1);
	}

	return (1);
}

ssize_t
proxy_drain(struct session *s, int from, int to, char *buf, size_t bufsz)
{
	ssize_t nr, nw, len = 0;
	int ret;

	do {
		if ((ret = nread(from, buf, bufsz, &nr, 0)) <= 0) {
			log_debug("#%u %s hung up", s->id,
			    print_peer(s, from));
			return (-1);
		}
		if (nr > 0) {
			if (nwrite(to, buf, nr, &nw) < 0) {
				log_debug("#%u %s hung up", s->id,
				    print_peer(s, to));
				return (-1);
			}
			if (nw != nr) {
				log_debug("#%u write failed", s->id);
				return (-1);
			}
		} else
			return (len);
		len += nr;
	} while (ret > 0);

	return (len);
}

int
proxy_filter(struct session *s, int proto, struct sockaddr *addr,
    in_port_t port, int timeout)
{
	const char *protocol;
	uint rdomain = getrtable();
	int rdr = s->flags & SF_REDIRECT ? 1 : 0;

	if (!addr)
		addr = sstosa(&s->server_ss);
	else if (sockaddr_cmp(addr, sstosa(&s->server_ss), 0) != 0)
		rdr = 1;

	if (!proto)
		proto = s->proto;

	protocol = proto == IPPROTO_TCP ? "tcp" : "udp";

	if (filter_start(s->id, &s->proxy->filter)) {
		log_warn("#%u starting an anchor failed: %m", s->id);
		return (-1);
	}

	if (rdr) {
		if (filter_rdr(timeout, proto, sstosa(&s->client_ss),
		    s->client_rd, sstosa(&s->oserver_ss), s->port, addr,
		    port, rdomain)) {
			log_warn("#%u adding redirect rule failed: %m", s->id);
			return (-1);
		}
		if (verbose > 1)
			log_debug("#%u pass in on rdomain %d proto %s from %s "
			    "to %s port %d rdr-to %s port %d once rtable %d",
			    s->id, s->client_rd, protocol,
			    print_host(&s->client_ss, 0),
			    print_host(&s->oserver_ss, 0), s->port,
			    print_host(satoss(addr), 0), port, rdomain);
	} else {
		if (filter_pass(FILTER_IN, timeout, proto,
		    sstosa(&s->client_ss), s->client_rd, addr, port,
		    rdomain)) {
			log_warn("#%u adding pass in rule failed: %m", s->id);
			return (-1);
		}
		if (verbose > 1)
			log_debug("#%u pass in on rdomain %d proto %s from %s "
			    "to %s port %d once rtable %d", s->id, s->client_rd,
			    protocol, print_host(&s->client_ss, 0),
			    print_host(satoss(addr), 0), port, rdomain);
	}
	if (!(s->flags & SF_TRANSPARENT)) {
		if (filter_nat(timeout, proto, sstosa(&s->client_ss),
		    rdomain, addr, port, sstosa(&s->proxy_ss),
		    PF_NAT_PROXY_PORT_LOW, PF_NAT_PROXY_PORT_HIGH)) {
			log_warn("#%u adding nat rule failed: %m", s->id);
			return (-1);
		}
		if (verbose > 1)
			log_debug("#%u pass out on rdomain %d proto %s from %s"
			    " to %s port %d nat-to %s once", s->id, rdomain,
			    protocol, print_host(&s->client_ss, 0),
			    print_host(satoss(addr), 0), port,
			    print_host(&s->proxy_ss, 0));
	} else {
		if (filter_pass(FILTER_OUT, timeout, proto,
		    sstosa(&s->client_ss), rdomain, s->flags & SF_REDIRECT ?
		    sstosa(&s->server_ss) : addr, port, rdomain)) {
			log_warn("#%u adding pass out rule failed: %m", s->id);
			return (-1);
		}
		if (verbose > 1)
			log_debug("#%u pass out on rdomain %d proto %s from %s "
			    "to %s port %d once", s->id, rdomain, protocol,
			    print_host(&s->client_ss, 0),
			    print_host(satoss(addr), 0), port);
	}

	if (filter_commit()) {
		log_warn("#%u commiting an anchor failed: %m", s->id);
		return (-1);
	}

	return (0);
}

void
proxy_end_session(struct session *s)
{
#ifdef PFDEBUG
	int error = 0;
#endif

	log_debug("#%u ending session", s->id);

	if (s->proto == IPPROTO_TCP) {
		if (s->client_bev)
			bufferevent_free(s->client_bev);
		if (s->server_bev)
			bufferevent_free(s->server_bev);
	} else {
		event_del(&s->client_ev);
		event_del(&s->server_ev);
	}
	close(s->client_fd);
	close(s->server_fd);

	if (s->proxy->backend)
		backend_disconnect(s);
#ifdef PFDEBUG
	if ((error = filter_cleanup(s->id)) != 0)
		log_warn("#%u pf rule removal failed: %s", s->id,
		    strerror(error));
#endif
	SPLAY_REMOVE(proxy_sessions, &sessions, s);
	if (s->datalen > 0)
		free(s->data);
	free(s);

	errno = 0;
}

int
map_address(struct proxy *p, struct sockaddr *sa, struct sockaddr *res)
{
	struct host *h = NULL;
	struct tableptr *tp;
	struct sockaddr_in *sina, *sinb;
	struct sockaddr_in6 *sin6a, *sin6b;

	TAILQ_FOREACH(tp, &p->maps, entry) {
		TAILQ_FOREACH(h, &tp->table->hosts, entry) {
			if (!sockaddr_cmp(sa, sstosa(&h->addr->ss), 0))
				break;
		}
		if (h)
			break;
	}
	if (!h)
		return (0);

	bcopy(&h->map->ss, res, h->map->ss.ss_len);
	/* preserve port number */
	switch (sa->sa_family) {
	case AF_INET:
		sina = (struct sockaddr_in *)res;
		sinb = (struct sockaddr_in *)sa;
		sina->sin_port = sinb->sin_port;
		break;
	case AF_INET6:
		sin6a = (struct sockaddr_in6 *)res;
		sin6b = (struct sockaddr_in6 *)sa;
		sin6a->sin6_port = sin6b->sin6_port;
		break;
	}

	return (1);
}

const char *
print_peer(struct session *s, int fd)
{
	if (fd == s->server_fd)
		return ("server");
	else
		return ("client");
}

void
process_restrict(void)
{
	struct passwd *pw;

	if ((pw = getpwnam(PROXYD_USER)) == NULL)
		fatalx("%s: no such user", PROXYD_USER);
	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~(LOGIN_SETUSER | LOGIN_SETRESOURCES)))
		fatalx("setusercontext");
	if (chroot(PROXYD_CHROOT) || chdir("/"))
		fatal("failed to chroot");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("failed to drop privileges");
}

void
setup_listener_do(struct sockaddr *sa, int proto, void *arg)
{
	struct event *ev;
	int fd, on = 1;

	if ((fd = socket(sa->sa_family, proto == IPPROTO_TCP ?
	    SOCK_STREAM : SOCK_DGRAM, proto)) == -1)
		fatal("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
	    sizeof(on)))
		fatal("setsockopt SO_REUSEADDR");
	if (proto == IPPROTO_UDP) {
		if (setsockopt(fd, IPPROTO_IP,  IP_RECVDSTADDR,
		    &on, sizeof(on)))
			fatal("setsockopt IP_RECVDSTADDR");
		if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTPORT,
		    &on, sizeof(on)))
			fatal("setsockopt IP_RECVDSTPORT");
		if (setsockopt(fd, IPPROTO_IP, IP_RECVRTABLE,
		    &on, sizeof(on)))
			fatal("setsockopt IP_RECVRTABLE");
	}
	if (bind(fd, sa, sa->sa_len))
		fatal("bind");
	if (proto == IPPROTO_TCP && listen(fd, 10))
		fatal("listen");
	if ((on = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, on | O_NONBLOCK))
		fatal("fcntl O_NONBLOCK");
	if ((ev = malloc(sizeof(*ev))) == NULL)
		fatal("malloc");
	event_set(ev, fd, EV_READ | EV_PERSIST, proto == IPPROTO_TCP ?
	    dispatch_tcp : dispatch_udp, arg);
	event_add(ev, NULL);
}

void
setup_listener(struct listener *l, struct proxy *p)
{
	struct sockaddr_storage ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct addrinfo hints, *res, *res0 = NULL;
	struct backend *be = p->backend;
	char port[32];
	int error;

	if (l) {
		bcopy(&l->addr->ss, &ss, l->addr->ss.ss_len);
		switch (ss.ss_family) {
		case AF_INET:
			sin = satosin(&ss);
			sin->sin_port = htons(l->port);
			break;
		case AF_INET6:
			sin6 = satosin6(&ss);
			sin6->sin6_port = htons(l->port);
			break;
		}
		if ((be->flags & BF_TCP) &&
		    (l->proto == IPPROTO_TCP || l->proto == -1))
			setup_listener_do(sstosa(&ss), IPPROTO_TCP, p);
		if ((be->flags & BF_UDP) &&
		    (l->proto == IPPROTO_UDP || l->proto == -1))
			setup_listener_do(sstosa(&ss), IPPROTO_UDP, p);
		return;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	hints.ai_family = AF_INET;
	if ((be->flags & (BF_TCP | BF_UDP)) == BF_TCP)
		hints.ai_protocol = IPPROTO_TCP;
	else if ((be->flags & (BF_TCP | BF_UDP)) == BF_UDP)
		hints.ai_protocol = IPPROTO_UDP;
	snprintf(port, sizeof(port), "%d", be->port);
	error = getaddrinfo("127.0.0.1", port, &hints, &res0);
	if (error)
		fatalx("getaddrinfo: %s", gai_strerror(error));
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_protocol == IPPROTO_UDP &&
		    res->ai_family != AF_INET)
			continue; /* XXX ipv6/udp is not supported */
		if (res->ai_family == AF_INET6 &&
		    (be->flags & BF_IPV6) == 0)
			continue;
		setup_listener_do(sstosa(res->ai_addr),
		    res->ai_protocol, p);
	}
	freeaddrinfo(res0);
}

void
signal_handler(int sig, short event, void *p)
{
	pid_t pid;
	int status;

	switch (sig) {
	case SIGPIPE:
		return;
	case SIGINT:
	case SIGTERM:
	case SIGCHLD:
		do {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid <= 0)
				continue;

			if (WIFSIGNALED(status) || WIFEXITED(status))
				log_warn("binder died");
			else
				log_warn("unexpected cause of SIGCHLD");
		} while (pid > 0 || (pid == -1 && errno == EINTR));

		event_loopbreak();
	}
}

void
usage(void)
{

	fprintf(stderr, "usage: proxyd [-dnv] [-f file]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct event ev_binder, ev_sigchld, ev_sigint, ev_sigterm, ev_sigpipe;
	struct rlimit rlp;
	struct listener *l;
	struct proxy *p;
	struct session *s, *next;
	int ch, conftest = 0, nodaemon = 0;
	char *conffile, *qname, *tag;

	qname = tag = NULL;
	conffile = PROXYD_CONF;

	while ((ch = getopt(argc, argv, "c:df:nq:t:v")) != -1)
		switch (ch) {
		case 'd':
			nodaemon++;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			conftest = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (!nodaemon && !conftest)
		daemon(0, 0);

	tzset();

	/* setup bind helper */
	if (!conftest)
		binder_init(nodaemon);

	if (parse_config(conffile, verbose))
		errx(1, "errors in config %s", PROXYD_CONF);
	if (conftest)
		return (0);

	openlog("proxyd", LOG_NDELAY | (nodaemon ? LOG_PERROR : LOG_PID),
	    LOG_DAEMON);

	if (conf.rdomain >= 0 && setrtable(conf.rdomain))
		fatal("setrtable");

	if (getrlimit(RLIMIT_NOFILE, &rlp))
		fatal("getrlimit");
	rlp.rlim_cur = rlp.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlp))
		fatal("setrlimit");

	filter_init("proxyd");

#ifndef DEBUG
	process_restrict();
#endif

	event_init();

	event_set(&ev_binder, binder_socket, EV_READ | EV_PERSIST,
	    binder_done, NULL);
	event_add(&ev_binder, NULL);

	signal_set(&ev_sigchld, SIGCHLD, signal_handler, NULL);
	signal_set(&ev_sigint, SIGINT,  signal_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, signal_handler, NULL);
	signal_set(&ev_sigpipe, SIGPIPE, signal_handler, NULL);
	signal_add(&ev_sigchld, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	/* setup listeners */
	TAILQ_FOREACH(p, &conf.proxies, entry) {
		if (TAILQ_EMPTY(&p->listeners))
			setup_listener(NULL, p);
		TAILQ_FOREACH(l, &p->listeners, entry) {
			setup_listener(l, p);
		}
	}

	event_dispatch();

	for (s = SPLAY_MIN(proxy_sessions, &sessions); s != NULL; s = next) {
		next = SPLAY_NEXT(proxy_sessions, &sessions, s);
		proxy_end_session(s);
	}

	if (!nodaemon)
		closelog();

	return (0);
}
