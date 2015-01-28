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

typedef struct {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint8_t		clock_seq_hi_and_reserved;
	uint8_t		clock_seq_low;
	uint8_t		node[6];
} uuid_t;

struct rpc_header {
	uint8_t		rh_version;
	uint8_t		rh_minor;
	uint8_t		rh_type;
#define  TYPE_REQUEST	 0x00
#define  TYPE_RESPONSE	 0x02
	uint8_t		rh_flags;
#define  PFC_FIRST_FRAG	 0x01
#define  PFC_LAST_FRAG	 0x02
#define  PFC_CANCEL	 0x04
#define  PFC_DIDNT_EXEC	 0x20
	uint8_t		rh_drep[4];
	uint16_t	rh_frag_len;
	uint16_t	rh_auth_len;
	uint32_t	rh_callid;
} __packed;

struct rpc_request {
	uint32_t	rr_alloc_hint;
	uint16_t	rr_ctxid;
	uint16_t	rr_opnum;
#define  OP_MAP		 3
} __packed;

struct rpc_response {
	uint32_t	rr_alloc_hint;
	uint16_t	rr_ctxid;
	uint8_t		rr_ncancel;
	uint8_t		rr_reserved;
} __packed;

struct tower {
	uint32_t	referenceid;
	uint32_t	length;
	uint32_t	length2;
	uint16_t	nfloors;
} __packed;

struct floor {
	uint16_t	lhslen;
	uint8_t		proto;
#define  DOD_TCP	 0x07
#define  DOD_UDP	 0x08
#define  DOD_IP		 0x09
} __packed;

struct protofloor {
	uint16_t	lhslen;
	uint8_t		proto;
	uint16_t	rhslen;
	uint16_t	port;
} __packed;

struct ipfloor {
	uint16_t	lhslen;
	uint8_t		proto;
	uint16_t	rhslen;
	uint32_t	addr;
} __packed;

struct epm_request {
	uint32_t	er_handle;
	uuid_t		er_uuid;
	struct tower	er_tower;
} __packed;

struct towers {
	uint32_t	max;
	uint32_t	offset;
	uint32_t	count;
} __packed;

struct epm_response {
	uint32_t	er_handle;
	uuid_t		er_uuid;
	uint32_t	er_ntowers;
	struct towers	er_towers;
} __packed;

struct msrpc_ctx {
	short		state;
	short		tcp;
	int		proto;
};

enum { ST_CONNECTED, ST_CALL, ST_DONE, ST_ERROR };

extern int		 verbose;

char *
next_floor(struct tower *twr, char *cur, int *cnt)
{
	char *firstfloor;
	int maxlen, floors;
	uint16_t len;

	/*
	 * Each tower floor contains the following:
	 *
	 * |<-    left hand side    ->|<-  right hand side   ->|
	 * +------------+-------------+------------+-----------+
	 * |  LHS byte  |  protocol   |  RHS byte  |  related  |
	 * |   count    |    data     |   count    |   data    |
	 * +------------+-------------+------------+-----------+
	 */

	floors = letoh16(twr->nfloors);
	if (!floors)
		return (NULL);
	if (cnt && *cnt + 1 > floors)
		return (NULL);
	maxlen = letoh16(twr->length);
	if (!maxlen)
		return (NULL);
	firstfloor = (char *)(twr + 1);
	if (!cur)
		return (firstfloor);
	if (cur && cur >= firstfloor + maxlen)
		return (NULL);
	bcopy(cur, &len, sizeof(len));
	cur += letoh16(len) + sizeof(len);
	bcopy(cur, &len, sizeof(len));
	cur += letoh16(len) + sizeof(len);

	*cnt = (*cnt)++;
	return (cur);
}

struct floor *
find_floor(struct tower *twr, int proto)
{
	struct floor *floor;
	char *ptr = NULL;
	int floorcnt = 0;

	while ((ptr = next_floor(twr, ptr, &floorcnt)) != NULL) {
		floor = (struct floor *)ptr;
		if (floor->proto == proto)
			return (floor);
	}

	return (NULL);
}

/*
 * void *
 * msrpc_connect(void *ctxp, uint id, int proto)
 */

int
msrpc_connect(struct session *s)
{
	struct msrpc_ctx *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (B_ERROR);

	if (s->proto == IPPROTO_TCP)
		ctx->tcp = 1;
	ctx->state = ST_CONNECTED;

	s->ctx = ctx;

	return (0);
}

ssize_t
msrpc_header_size(void)
{
	return (sizeof(struct rpc_header));
}

ssize_t
msrpc_packet_size(struct session *s, char *hdr, size_t hdrlen)
{
	struct rpc_header *rh;

	if (hdrlen < sizeof(struct rpc_header))
		return (-1);

	rh = (struct rpc_header *)hdr;
	return (letoh16(rh->rh_frag_len));
}

#define CHECK_BUFLEN(offset)					\
	if (buflen < off + (offset)) {				\
		log_debug("#%u request is too small", s->id);	\
		goto errout;					\
	}

int
msrpc_client(struct session *s, char *buf, size_t buflen, char **obuf,
    size_t *outlen)
{
	struct msrpc_ctx *ctx = s->ctx;
	struct rpc_header *rh;
	struct rpc_request *rr;
	struct epm_request *er;
	struct floor *fl = NULL;
	struct protofloor *pf;
	struct ipfloor *ip;
	size_t off = 0;

	if (ctx->state == ST_ERROR)
		return (B_ERROR);

	CHECK_BUFLEN(sizeof(*rh));
	rh = (struct rpc_header *)(buf + off);
	off += sizeof(*rh);

	if (verbose > 1)
		log_debug("#%u -> ver %d.%d type %#x flags %#x", s->id,
		    rh->rh_version, rh->rh_minor, rh->rh_type, rh->rh_flags);

	if (rh->rh_type != TYPE_REQUEST)
		return (B_OK);

	CHECK_BUFLEN(sizeof(*rr));
	rr = (struct rpc_request *)(buf + off);
	off += sizeof(*rr);

	log_debug("#%u request: flags %#x drep[0] %#x op %d", s->id,
	    rh->rh_flags, rh->rh_drep[0], letoh16(rr->rr_opnum));

	if (letoh16(rr->rr_opnum) != OP_MAP)
		return (B_OK);

	CHECK_BUFLEN(sizeof(*er));
	er = (struct epm_request *)(buf + off);
	off += sizeof(*er);

	if ((fl = find_floor(&er->er_tower, DOD_TCP)) == NULL &&
	    (fl = find_floor(&er->er_tower, DOD_UDP)) == NULL) {
		log_debug("#%u can't find TCP or UDP floor", s->id);
		goto unknown;
	}
	if ((ip = (struct ipfloor *)
	    find_floor(&er->er_tower, DOD_IP)) == NULL) {
		log_debug("#%u can't find IP floor", s->id);
		goto unknown;
	}

	pf = (struct protofloor *)fl;

	log_debug("#%u EPM %s request", s->id, pf->proto == DOD_TCP ?
	    "tcp" : "udp");

	if (s->flags & SF_REDIRECT)
		ip->addr = satosin(&s->server_ss)->sin_addr.s_addr;

	ctx->proto = pf->proto == DOD_TCP ? IPPROTO_TCP : IPPROTO_UDP;
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
msrpc_server(struct session *s, char *buf, size_t buflen, char **obuf,
    size_t *outlen)
{
	struct sockaddr_in sin;
	struct msrpc_ctx *ctx = s->ctx;
	struct rpc_header *rh;
	struct rpc_response *rr;
	struct epm_response *er;
	struct floor *fl = NULL;
	struct protofloor *pf;
	struct ipfloor *ip;
	struct tower *twr = NULL;
	size_t off = 0;
	int tower, ntowers, maxtowers;
	in_port_t port;

	CHECK_BUFLEN(sizeof(*rh));
	rh = (struct rpc_header *)(buf + off);
	off += sizeof(*rh);

	if (verbose > 1)
		log_debug("#%u <- ver %d.%d type %#x flags %#x", s->id,
		    rh->rh_version, rh->rh_minor, rh->rh_type, rh->rh_flags);

	if (ctx->state == ST_CALL && rh->rh_type != TYPE_RESPONSE)
		goto unknown;
	if (rh->rh_type != TYPE_RESPONSE)
		return (B_OK);

	if ((rh->rh_flags & PFC_CANCEL) != 0 ||
	    (rh->rh_flags & PFC_DIDNT_EXEC) != 0) {
		log_debug("#%u RPC request execution failed", s->id);
		goto errout;
	}

	CHECK_BUFLEN(sizeof(*rr));
	rr = (struct rpc_response *)(buf + off);
	off += sizeof(*rr);

	log_debug("#%u response: flags %#x drep[0] %#x canceled %d",
	    s->id, rh->rh_flags, rh->rh_drep[0], rr->rr_ncancel);

	CHECK_BUFLEN(sizeof(*er));
	er = (struct epm_response *)(buf + off);
	off += sizeof(*er);

	ntowers = letoh32(er->er_towers.count);
	maxtowers = letoh32(er->er_towers.max);
	if (ntowers == 0) {
		log_debug("#%u no towers (likely an error)", s->id);
		return (B_OK);
	}
	if (ntowers > 10 || (maxtowers > 0 && ntowers > maxtowers)) {
		log_debug("#%u bad tower array %d/%d", s->id, ntowers,
		    maxtowers);
		goto errout;
	}

	for (tower = 0; tower < ntowers; tower++) {
		if (twr)
			off += letoh32(twr->length);

		CHECK_BUFLEN(sizeof(*twr));
		twr = (struct tower *)(buf + off);
		off += sizeof(*twr);

		if ((fl = find_floor(twr, DOD_TCP)) == NULL &&
		    (fl = find_floor(twr, DOD_UDP)) == NULL)
			continue;
		if ((ip = (struct ipfloor *)find_floor(twr, DOD_IP)) == NULL)
			continue;
	}
	if (!fl || !ip) {
		log_debug("#%u can't find TCP, UDP or IP floor", s->id);
		goto unknown;
	}
	pf = (struct protofloor *)fl;

	port = ntohs(pf->port);

	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = ip->addr;

	log_debug("#%u EPM %s response, port %d", s->id, pf->proto == DOD_TCP ?
	    "tcp" : "udp", port);

	if (port > 0 && proxy_filter(s, ctx->proto, sstosa(&sin), port,
	    ctx->proto == IPPROTO_UDP ? RPC_UDPTIMEOUT : 0)) {
		log_warn("#%u failed to setup pf", s->id);
		goto errout;
	}
	if (s->port)
		pf->port = htons(s->port);
	if (s->flags & SF_REDIRECT)
		ip->addr = satosin(&s->oserver_ss)->sin_addr.s_addr;

	ctx->state = ST_DONE;
	return (B_OK);

 unknown:
	ctx->state = ST_ERROR;
	return (B_UNKNOWN);

 errout:
	ctx->state = ST_ERROR;
	return (B_ERROR);
}

void
msrpc_disconnect(struct session *s)
{
	free(s->ctx);
	s->ctx = NULL;
}
