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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "proxy.h"

#define RPC_UDPTIMEOUT	12*60*60	/* 12 hours */
#define RPC_RECMARK	0x80000000
#define RPC_LSIZE	sizeof(uint32_t)
#define RPC_ROUNDUP(x)	((((x) + RPC_LSIZE - 1) / RPC_LSIZE) * RPC_LSIZE)

struct rpc_auth {
	uint32_t	ra_type;
#define  AUTH_NONE	 0
#define  AUTH_UNIX	 1
#define  AUTH_SHORT	 2
#define  AUTH_DH	 3
#define  AUTH_KERB	 4
#define  AUTH_GSS	 6
	uint32_t	ra_length;
#define  AUTH_MAXLEN	 400
};

struct rpc_call {
	uint32_t	rc_xid;
	uint32_t	rc_dir;
#define  DIR_CALL	 0
	uint32_t	rc_rpcvers;
#define  RPC_V2		 2
	uint32_t	rc_prog;
#define  PROG_PMAP	 100000
	uint32_t	rc_vers;
	uint32_t	rc_proc;
#define  PROC_GETPORT	 3
	/* followed by the auth data and struct pmap_call */
} __packed;

struct pmap_call {
	uint32_t	pc_prog;
	uint32_t	pc_vers;
	uint32_t	pc_prot;
	uint32_t	pc_port;
} __packed;

struct rpc_reply {
	uint32_t	rr_xid;
	uint32_t	rr_dir;
#define  DIR_REPLY	 1
	uint32_t	rr_stat;
#define  STAT_ACCEPTED	 0
#define  STAT_DENIED	 1
	/* followed by the auth data and struct pmap_reply */
} __packed;

struct pmap_reply {
	uint32_t	pr_stat;
#define  STAT_SUCCESS	 0
	uint32_t	pr_port;
} __packed;

struct sunrpc_ctx {
	short		state;
	short		tcp;
	uint32_t	xid;
	int		proto;
};

enum { ST_CONNECTED, ST_CALL, ST_DONE, ST_ERROR };

/*
 * void *
 * sunrpc_connect(void *ctxp, uint id, int proto)
 */

int
sunrpc_connect(struct session *s)
{
	struct sunrpc_ctx *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (B_ERROR);

	if (s->proto == IPPROTO_TCP)
		ctx->tcp = 1;
	ctx->state = ST_CONNECTED;

	s->ctx = ctx;

	return (0);
}

ssize_t
sunrpc_header_size(void)
{
	return (sizeof(uint32_t));
}

ssize_t
sunrpc_packet_size(struct session *s, char *hdr, size_t hdrlen)
{
	uint32_t mark;

	if (hdrlen < sizeof(uint32_t))
		return (-1);

	mark = ntohl(*(uint32_t *)hdr);
	if ((mark & RPC_RECMARK) != RPC_RECMARK)
		return (-1);

	return (mark & ~RPC_RECMARK);
}

#define CHECK_BUFLEN(offset)					\
	if (buflen < off + (offset)) {				\
		log_debug("#%u request is too small", s->id);	\
		goto errout;					\
	}

int
sunrpc_client(struct session *s, char *buf, size_t buflen, char **obuf,
    size_t *outlen)
{
	struct sunrpc_ctx *ctx = s->ctx;
	struct rpc_call *rc;
	struct rpc_auth *ra;
	struct pmap_call *pc;
	size_t off = 0;
	int i;

	if (ctx->state == ST_ERROR)
		return (B_ERROR);

	/* TCP packet includes a 32 bit record mark */
	if (ctx->tcp)
		off += sizeof(uint32_t);

	CHECK_BUFLEN(sizeof(*rc));
	rc = (struct rpc_call *)(buf + off);
	off += sizeof(*rc);

	log_debug("#%u call: xid %#x dir %d rpcvers %d prog %d vers %d proc %d",
	    s->id, ntohl(rc->rc_xid), ntohl(rc->rc_dir), ntohl(rc->rc_rpcvers),
	    ntohl(rc->rc_prog), ntohl(rc->rc_vers), ntohl(rc->rc_proc));

	if (ntohl(rc->rc_dir) != DIR_CALL || ntohl(rc->rc_prog) != PROG_PMAP ||
	    ntohl(rc->rc_proc) != PROC_GETPORT) {
		log_debug("#%u program %d procedure %d is not supported",
		    s->id, ntohl(rc->rc_prog), ntohl(rc->rc_proc));
		goto unknown;
	}

	/* two chunks of auth data */
	for (i = 0; i < 2; i++) {
		CHECK_BUFLEN(sizeof(*ra));
		ra = (struct rpc_auth *)(buf + off);
		if (ntohl(ra->ra_type) == AUTH_NONE)
			ra->ra_length = 0;
		if (ntohl(ra->ra_length) > AUTH_MAXLEN) {
			log_debug("#%u invalid auth length (type %d len %d)",
			    s->id, ntohl(ra->ra_type),
			    ntohl(ra->ra_length));
			goto errout;
		}
		off += sizeof(*ra) + RPC_ROUNDUP(ntohl(ra->ra_length));
	}

	CHECK_BUFLEN(sizeof(*pc));
	pc = (struct pmap_call *)(buf + off);
	off += sizeof(*pc);

	log_debug("#%u pmap: prog %d vers %d prot %d port %d", s->id,
	    ntohl(pc->pc_prog), ntohl(pc->pc_vers), ntohl(pc->pc_prot),
	    ntohl(pc->pc_port));

	ctx->xid = rc->rc_xid;
	ctx->proto = ntohl(pc->pc_prot);
	ctx->state = ST_CALL;
	return (B_OK);

 unknown:
	ctx->state = ST_ERROR;
	return (B_UNKNOWN);

 errout:
	ctx->state = ST_ERROR;
	return (B_ERROR);
}

int
sunrpc_server(struct session *s, char *buf, size_t buflen, char **obuf,
    size_t *outlen)
{
	struct sunrpc_ctx *ctx = s->ctx;
	struct rpc_reply *rr;
	struct rpc_auth *ra;
	struct pmap_reply *pr;
	size_t off = 0;
	in_port_t port;

	if (ctx->state != ST_CALL)
		return (B_ERROR);

	/* TCP packet includes a 32 bit record mark */
	if (ctx->tcp)
		off += sizeof(uint32_t);

	CHECK_BUFLEN(sizeof(*rr));
	rr = (struct rpc_reply *)(buf + off);
	off += sizeof(*rr);

	log_debug("#%u reply: xid %#x dir %d stat %d", s->id,
	    ntohl(rr->rr_xid), ntohl(rr->rr_dir), ntohl(rr->rr_stat));

	if (ntohl(rr->rr_dir) != DIR_REPLY || ctx->xid != rr->rr_xid) {
		log_debug("#%u bad reply", s->id);
		goto errout;
	}
	if (ntohl(rr->rr_stat) != STAT_ACCEPTED) {
		log_debug("#%u server denied access", s->id);
		goto errout;
	}

	/* one chunk of auth data */
	CHECK_BUFLEN(sizeof(*ra));
	ra = (struct rpc_auth *)(buf + off);
	if (ntohl(ra->ra_type) == AUTH_NONE)
		ra->ra_length = 0;
	if (ntohl(ra->ra_length) > AUTH_MAXLEN) {
		log_debug("#%u invalid auth length (type %d len %d)", s->id,
		    ntohl(ra->ra_type), ntohl(ra->ra_length));
		goto errout;
	}
	off += sizeof(*ra) + RPC_ROUNDUP(ntohl(ra->ra_length));

	CHECK_BUFLEN(sizeof(*pr));
	pr = (struct pmap_reply *)(buf + off);
	off += sizeof(*pr);

	log_debug("#%u pmap: stat %d port %d", s->id, ntohl(pr->pr_stat),
	    ntohl(pr->pr_port));

	if (ntohl(pr->pr_stat) != STAT_SUCCESS) {
		log_debug("#%u unsuccessful reply (%d)", s->id,
		    ntohl(pr->pr_stat));
		goto errout;
	}

	port = (in_port_t)ntohl(pr->pr_port);
	if (port > 0 && proxy_filter(s, ctx->proto, NULL, port,
	    ctx->proto == IPPROTO_UDP ? RPC_UDPTIMEOUT : 0)) {
		log_warn("#%u failed to setup pf", s->id);
		goto errout;
	}
	if (s->port)
		pr->pr_port = htonl(s->port);

	ctx->state = ST_DONE;
	return (B_OK);

 errout:
	ctx->state = ST_ERROR;
	return (B_ERROR);
}

void
sunrpc_disconnect(struct session *s)
{
	free(s->ctx);
	s->ctx = NULL;
}
