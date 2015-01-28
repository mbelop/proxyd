/*	$OpenBSD: filter.c,v 1.14 2011/03/25 14:51:31 claudio Exp $ */

/*
 * Copyright (c) 2011 Mike Belopuhov
 * Copyright (c) 2004, 2005 Camiel Dobbelaar, <cd@sentia.nl>
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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define satosin(sa)		((struct sockaddr_in *)(sa))
#define satosin6(sa)		((struct sockaddr_in6 *)(sa))

// XXX
struct filter {
	char 			tag[64];
	char 			queue[64];
	int			log;
};

extern void			fatalx(const char *, ...);
extern void			fatal(const char *);
extern void			log_debug(const char *, ...);

int				pf_begin(uint);
int				pf_commit(void);
int				pf_rollback(void);
int				pf_rule(int, int, struct sockaddr *,
				    u_int16_t, struct sockaddr *, u_int16_t);
int				add_addr(struct sockaddr *, struct pf_pool *);

static struct pfioc_rule	pfr;
static struct pfioc_trans	pft;
static struct pfioc_trans_e	pfte;
static struct filter *		curfilter;
static uint			curid;
static int			dev, pid;
static char *			anchor;

void
filter_init(char *opt_anchor)
{
	struct pf_status status;

	anchor = opt_anchor;
	pid = getpid();

	dev = open("/dev/pf", O_RDWR);
	if (dev == -1)
		fatal("/dev/pf");
	if (ioctl(dev, DIOCGETSTATUS, &status) == -1)
		fatal("DIOCGETSTATUS");
	if (!status.running)
		fatalx("pf is disabled");
}

int
filter_cleanup(uint id)
{
	int error = 0;

	/* Remove rulesets by commiting empty ones. */
	if (pf_begin(id) == -1)
		error = errno;
	else if (pf_commit() == -1) {
		error = errno;
		pf_rollback();
	}

	return (error);
}

int
filter_start(uint id, struct filter *filter)
{
	if (pf_begin(id))
		return (-1);
	curfilter = filter;
	curid = id;
	return (0);
}

int
filter_commit(void)
{
	if (pf_commit())
		return (-1);
	return (0);
}

int
filter_nat(int timeout, int proto, struct sockaddr *src,
    int s_rd, struct sockaddr *dst, u_int16_t d_port, struct sockaddr *nat,
    u_int16_t nat_range_low, u_int16_t nat_range_high)
{
	if (!src || !dst || !d_port || !nat || !nat_range_low ||
	    (src->sa_family != nat->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

	if (pf_rule(timeout, proto, src, 0, dst, d_port) == -1)
		return (-1);

	if (add_addr(nat, &pfr.rule.nat) == -1)
		return (-1);

	pfr.rule.direction = PF_OUT;
	pfr.rule.rtableid = -1;
	pfr.rule.nat.proxy_port[0] = nat_range_low;
	pfr.rule.nat.proxy_port[1] = nat_range_high;

	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
filter_rdr(int timeout, int proto, struct sockaddr *src,
    int s_rd, struct sockaddr *dst, u_int16_t d_port, struct sockaddr *rdr,
    u_int16_t rdr_port, int d_rd)
{
	if (!src || !dst || !d_port || !rdr || !rdr_port ||
	    (src->sa_family != rdr->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

	if (pf_rule(timeout, proto, src, 0, dst, d_port) == -1)
		return (-1);

	if (add_addr(rdr, &pfr.rule.rdr) == -1)
		return (-1);

	pfr.rule.direction = PF_IN;
	pfr.rule.rtableid = d_rd;
	pfr.rule.rdr.proxy_port[0] = rdr_port;

	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
filter_pass(int dir, int timeout, int proto, struct sockaddr *src,
    int s_rd, struct sockaddr *dst, u_int16_t d_port, int d_rd)
{
	if (!src || !dst || !d_port ||
	    (src->sa_family != dst->sa_family)) {
		errno = EINVAL;
		return (-1);
	}

	if (pf_rule(timeout, proto, src, 0, dst, d_port) == -1)
		return (-1);

	pfr.rule.direction = dir;
	pfr.rule.rtableid = d_rd;

	if (ioctl(dev, DIOCADDRULE, &pfr) == -1)
		return (-1);

	return (0);
}

int
pf_begin(uint id)
{
	char an[PF_ANCHOR_NAME_SIZE];

	memset(&pft, 0, sizeof pft);
	pft.size = 1;
	pft.esize = sizeof pfte;
	pft.array = &pfte;

	snprintf(an, PF_ANCHOR_NAME_SIZE, "%s/%d.%u", anchor,
	    pid, id);

	memset(&pfte, 0, sizeof pfte);
	strlcpy(pfte.anchor, an, PF_ANCHOR_NAME_SIZE);
	pfte.type = PF_TRANS_RULESET;

	if (ioctl(dev, DIOCXBEGIN, &pft) == -1)
		return (-1);

	return (0);
}

int
pf_commit(void)
{
	if (ioctl(dev, DIOCXCOMMIT, &pft) == -1)
		return (-1);

	return (0);
}

int
pf_rollback(void)
{
	if (ioctl(dev, DIOCXROLLBACK, &pft) == -1)
		return (-1);

	return (0);
}

int
pf_rule(int timeout, int proto, struct sockaddr *src,
    u_int16_t s_port, struct sockaddr *dst, u_int16_t d_port)
{
	char an[PF_ANCHOR_NAME_SIZE];
	int ttype;

	if ((src->sa_family != AF_INET && src->sa_family != AF_INET6) ||
	    (src->sa_family != dst->sa_family)) {
	    	errno = EPROTONOSUPPORT;
		return (-1);
	}

	memset(&pfr, 0, sizeof pfr);
	snprintf(an, PF_ANCHOR_NAME_SIZE, "%s/%d.%u", anchor, pid, curid);
	strlcpy(pfr.anchor, an, PF_ANCHOR_NAME_SIZE);

	pfr.ticket = pfte.ticket;

	/* Generic for all rule types. */
	pfr.rule.af = src->sa_family;
	pfr.rule.proto = proto;
	pfr.rule.src.addr.type = PF_ADDR_ADDRMASK;
	pfr.rule.dst.addr.type = PF_ADDR_ADDRMASK;
	pfr.rule.nat.addr.type = PF_ADDR_NONE;
	pfr.rule.rdr.addr.type = PF_ADDR_NONE;

	if (src->sa_family == AF_INET) {
		memcpy(&pfr.rule.src.addr.v.a.addr.v4,
		    &satosin(src)->sin_addr.s_addr, 4);
		memset(&pfr.rule.src.addr.v.a.mask.addr8, 255, 4);
		memcpy(&pfr.rule.dst.addr.v.a.addr.v4,
		    &satosin(dst)->sin_addr.s_addr, 4);
		memset(&pfr.rule.dst.addr.v.a.mask.addr8, 255, 4);
	} else {
		memcpy(&pfr.rule.src.addr.v.a.addr.v6,
		    &satosin6(src)->sin6_addr.s6_addr, 16);
		memset(&pfr.rule.src.addr.v.a.mask.addr8, 255, 16);
		memcpy(&pfr.rule.dst.addr.v.a.addr.v6,
		    &satosin6(dst)->sin6_addr.s6_addr, 16);
		memset(&pfr.rule.dst.addr.v.a.mask.addr8, 255, 16);
	}
	if (s_port) {
		pfr.rule.src.port_op = PF_OP_EQ;
		pfr.rule.src.port[0] = htons(s_port);
	}
	pfr.rule.dst.port_op = PF_OP_EQ;
	pfr.rule.dst.port[0] = htons(d_port);

	/*
	 * pass [quick] [log] inet[6] proto tcp \
	 *     from $src to $dst port = $d_port flags S/SA keep state
	 *     (max 1) [queue qname] [tag tagname]
	 */
	if (strlen(curfilter->tag))
		pfr.rule.action = PF_MATCH;
	else
		pfr.rule.action = PF_PASS;
	pfr.rule.quick = 1;
	pfr.rule.keep_state = 1;
	if (curfilter->log)
		pfr.rule.log = PF_LOG;

	if (timeout) {
		ttype = (proto == IPPROTO_TCP) ? PFTM_TCP_ESTABLISHED :
		    PFTM_UDP_MULTIPLE;
		pfr.rule.timeout[ttype] = timeout;
	}

#ifdef PFDEBUG
	pfr.rule.max_states = 1;
#else
	pfr.rule.rule_flag |= PFRULE_ONCE;
#endif

	if (proto == IPPROTO_TCP) {
		pfr.rule.flags = TH_SYN;
		pfr.rule.flagset = (TH_SYN|TH_ACK);
	}
	if (strlen(curfilter->queue))
		strlcpy(pfr.rule.qname, curfilter->queue,
		    sizeof pfr.rule.qname);
	if (strlen(curfilter->tag)) {
		pfr.rule.quick = 0;
		strlcpy(pfr.rule.tagname, curfilter->tag,
		    sizeof pfr.rule.tagname);
	}

	return (0);
}

int
add_addr(struct sockaddr *addr, struct pf_pool *pfp)
{
	if (addr->sa_family == AF_INET) {
		memcpy(&pfp->addr.v.a.addr.v4,
		    &satosin(addr)->sin_addr.s_addr, 4);
		memset(&pfp->addr.v.a.mask.addr8, 255, 4);
	} else {
		memcpy(&pfp->addr.v.a.addr.v6,
		    &satosin6(addr)->sin6_addr.s6_addr, 16);
		memset(&pfp->addr.v.a.mask.addr8, 255, 16);
	}
	pfp->addr.type = PF_ADDR_ADDRMASK;
	return (0);
}
