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

#include <sys/tree.h>

#define PROXYD_USER	"proxy"
#define PROXYD_CHROOT	"/var/empty/"
#define PROXYD_CONF	"/etc/proxyd.conf"

#define PROXY_BUFSIZE	4096

/* pfctl standard NAT range. */
#define PF_NAT_PROXY_PORT_LOW	50001
#define PF_NAT_PROXY_PORT_HIGH	65535

struct backend;
struct session;

enum proxy_type {
	PROXY_TNS,
	PROXY_SUNRPC,
	PROXY_MSRPC
};

#define TABLE_NAME_SIZE		64
#define PROXY_NAME_SIZE		64

struct address {
	TAILQ_ENTRY(address)	entry;
	struct sockaddr_storage	ss;
};
TAILQ_HEAD(addresslist, address);

struct host {
	TAILQ_ENTRY(host)	entry;
	struct address *	addr;
	struct address *	map;
};

struct table {
	TAILQ_ENTRY(table)	entry;
	char			name[TABLE_NAME_SIZE];
	uint			entries;
	uint			flags;
#define  TABLE_USED		 0x01
#define  TABLE_MAP		 0x02
	TAILQ_HEAD(, host)	hosts;
};

struct tableptr {
	TAILQ_ENTRY(tableptr)	entry;
	struct table *		table;
};

struct listener {
	TAILQ_ENTRY(listener)	entry;
	struct address *	addr;
	int			proto;
	int			port;
};

struct filter {
	char 			tag[64];
	char 			queue[64];
	int			log;
};

struct proxy {
	TAILQ_ENTRY(proxy)	entry;
	struct backend *	backend;
	char			name[PROXY_NAME_SIZE];
	enum proxy_type		type;
	TAILQ_HEAD(, listener)	listeners;
	TAILQ_HEAD(, tableptr)	maps;
	int			transparent;
	struct filter		filter;
	struct timeval		connect_tv;
	struct timeval		idle_tv;
};

struct conf {
	TAILQ_HEAD(, proxy)	proxies;
	TAILQ_HEAD(, table)	tables;
	uint			rdomain;
	int			transparent;
	struct filter		filter;
	struct timeval		connect_tv;
	struct timeval		idle_tv;
};

struct backend {
	int			flags;
#define  BF_TCP			  0x0001
#define  BF_UDP			  0x0002
#define  BF_IPV6		  0x0004
#define  BF_TRANSP		  0x0010
#define  BF_LINEBUF		  0x0100
#define  BF_SAFEBUF		  0x0200
	int			port;
	int			(*connect)(struct session *);
	ssize_t			(*header_size)(void);
	ssize_t			(*packet_size)(struct session *, char *, size_t);
	int			(*client)(struct session *, char *, size_t,
				    char **, size_t *);
	int			(*server)(struct session *, char *, size_t,
				    char **, size_t *);
	void			(*disconnect)(struct session *);
};

enum { B_OK, B_UNKNOWN, B_ERROR };

struct session {
	struct sockaddr_storage	client_ss;
	struct sockaddr_storage oserver_ss;
	struct sockaddr_storage server_ss;
	struct sockaddr_storage	proxy_ss;

	struct bufferevent *	client_bev;
	struct bufferevent *	server_bev;
	struct event		client_ev;
	struct event		server_ev;

	int			client_fd;
	int			server_fd;

	uint			client_rd;

	ushort			proto;
	ushort			port;

	uint			id;

	uint			flags;
#define SF_TRANSPARENT		  0x0001	/* transparent session */
#define SF_REDIRECT		  0x0002	/* redirect server->oserver */
#define SF_FORWARD		  0x0010	/* forward, don't process */

	char *			data;
	ssize_t			datalen;

	struct proxy *		proxy;
	void *			ctx;

	void			(*binder_done_cb)(struct session *, int);
	SPLAY_ENTRY(session)	entry;
	TAILQ_ENTRY(session)	bindq;
};

#define BFLAGS(s)		((s)->proxy->backend->flags)

#define TIMEOUT_CONNECT(s)	(&(s)->proxy->connect_tv)
#define TIMEOUT_IDLE(s)		(&(s)->proxy->idle_tv)

#define BEV_FD(x)		(EVENT_FD(&(x)->ev_read))
#define BEV_LENGTH(x)		(EVBUFFER_LENGTH(EVBUFFER_INPUT(x)))
#define BEV_DATA(x)		(EVBUFFER_DATA(EVBUFFER_INPUT(x)))

#define satosin(sa)		((struct sockaddr_in *)(sa))
#define satosin6(sa)		((struct sockaddr_in6 *)(sa))
#define satoss(sa)		((struct sockaddr_storage *)(sa))
#define sstosa(ss)		((struct sockaddr *)(ss))

/* proxy.c */
ssize_t		proxy_read(struct session *, int, void *, ssize_t);
ssize_t		proxy_peek(struct session *, int, void *, ssize_t);
ssize_t		proxy_write(struct session *, int, void *, ssize_t);
ssize_t		proxy_writev(struct session *, int, const struct iovec *, int);
ssize_t		proxy_drain(struct session *, int, int, char *, size_t);
int		proxy_filter(struct session *, int, struct sockaddr *,
		    in_port_t, int);
void		proxy_cleanup(int, short, void *);
void		proxy_end_session(struct session *);
int		sock_pton(struct sockaddr_storage *, char *);
const char *	print_host(struct sockaddr_storage *, int);
void		log_debug(const char *, ...);
void		log_warn(const char *, ...);
void		fatalx(const char *, ...);
void		fatal(const char *);

#define		proxy_read_client(s, buf, len)	\
			proxy_read(s, s->client_fd, buf, len)
#define		proxy_read_server(s, buf, len)	\
			proxy_read(s, s->server_fd, buf, len)
#define		proxy_peek_client(s, buf, len)	\
			proxy_peek(s, s->client_fd, buf, len)
#define		proxy_peek_server(s, buf, len)	\
			proxy_peek(s, s->server_fd, buf, len)
#define		proxy_write_client(s, buf, len)	\
			proxy_write(s, s->client_fd, buf, len)
#define		proxy_write_server(s, buf, len)	\
			proxy_write(s, s->server_fd, buf, len)
#define		proxy_writev_client(s, iov, iovcnt)	\
			proxy_writev(s, s->client_fd, iov, iovcnt)
#define		proxy_writev_server(s, iov, iovcnt)	\
			proxy_writev(s, s->server_fd, iov, iovcnt)
#define		proxy_drain_client(s, buf, bufsz)	\
			proxy_drain(s, s->client_fd, s->server_fd, buf, bufsz)
#define		proxy_drain_server(s, buf, bufsz)	\
			proxy_drain(s, s->server_fd, s->client_fd, buf, bufsz)

#define		backend_connect(s) \
			(s)->proxy->backend->connect(s)
#define		backend_header_size(s) \
			(s)->proxy->backend->header_size()
#define		backend_packet_size(s, a, b)			\
			(s)->proxy->backend->packet_size(s, a, b)
#define		backend_client(s, a, b, c, d) \
			(s)->proxy->backend->client(s, a, b, c, d)
#define		backend_server(s, a, b, c, d) \
			(s)->proxy->backend->server(s, a, b, c, d)
#define		backend_disconnect(s) \
			(s)->proxy->backend->disconnect(s)

/* conf.y */
int		parse_config(const char *, int);

/* fdpass.c */
int		send_fd(int, int, uint);
int		receive_fd(int, uint *);

/* filter.c */
void		filter_init(char *);
int		filter_start(uint, struct filter *);
int		filter_nat(int, int, struct sockaddr *, int,
		    struct sockaddr *, u_int16_t, struct sockaddr *,
		    u_int16_t, u_int16_t);
int		filter_rdr(int, int, struct sockaddr *, int,
		    struct sockaddr *, u_int16_t, struct sockaddr *,
		    u_int16_t, int);
int		filter_pass(int, int, int, struct sockaddr *, int,
		    struct sockaddr *, u_int16_t, int);
int		filter_commit(void);
int		filter_cleanup(uint);

enum		{ FILTER_INOUT, FILTER_IN, FILTER_OUT };

/* util.c */
void		log_debug(const char *, ...);
void		log_warn(const char *, ...);
void		fatalx(const char *, ...);
void		fatal(const char *);
in_port_t	pick_port(void);
int		nread(int, void *, ssize_t, ssize_t *, int);
int		nwrite(int, void *, ssize_t, ssize_t *);
int		nwritev(int, const struct iovec *, int);
int		toread(int);
const char *	print_host(struct sockaddr_storage *, int);
int		sockaddr_cmp(struct sockaddr *, struct sockaddr *, int);

/* msrpc.c */
int		msrpc_connect(struct session *);
ssize_t		msrpc_header_size(void);
ssize_t		msrpc_packet_size(struct session *, char *, size_t);
int		msrpc_client(struct session *, char *, size_t, char **,
		    size_t *);
int		msrpc_server(struct session *, char *, size_t, char **,
		    size_t *);
void		msrpc_disconnect(struct session *);

/* sunrpc.c */
int		sunrpc_connect(struct session *);
ssize_t		sunrpc_header_size(void);
ssize_t		sunrpc_packet_size(struct session *, char *, size_t);
int		sunrpc_client(struct session *, char *, size_t, char **,
		    size_t *);
int		sunrpc_server(struct session *, char *, size_t, char **,
		    size_t *);
void		sunrpc_disconnect(struct session *);

/* tns.c */
int		tns_connect(struct session *);
ssize_t		tns_header_size(void);
ssize_t		tns_packet_size(struct session *, char *, size_t);
int		tns_client(struct session *, char *, size_t, char **,
		    size_t *);
int		tns_server(struct session *, char *, size_t, char **,
		    size_t *);
void		tns_disconnect(struct session *);
