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
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
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

struct tns_header {
	uint16_t	th_length;
	uint16_t	th_pcksum;
	uint8_t		th_type;
#define	 TNS_CONNECT	 1
#define  TNS_ACCEPT	 2
#define  TNS_ACK	 3
#define  TNS_REFUSE	 4
#define  TNS_REDIRECT	 5
#define  TNS_DATA	 6
#define  TNS_NULL	 7
#define  TNS_ABORT	 9
#define	 TNS_RESEND	 11
#define  TNS_MARKER	 12
#define  TNS_ATTENTION	 13
#define  TNS_CONTROL	 14
#define  TNS_HIGH	 19
	uint8_t		th_reserved;
	uint16_t	th_hcksum;
} __packed;

struct tns_connect {
	uint16_t	tc_version;
	uint16_t	tc_compat;
	uint16_t	tc_options;
	uint16_t	tc_ssize;
	uint16_t	tc_tsize;
	uint16_t	tc_ntproto;
	uint16_t	tc_lineturn;
	uint16_t	tc_one;
	uint16_t	tc_length;
	uint16_t	tc_offset;
	uint16_t	tc_maxdata;
	uint8_t		tc_flags0;
	uint8_t		tc_flags1;
	uint64_t	tc_cfitem;
	uint8_t		tc_connid[16];
} __packed;

struct tns_redirect {
	uint16_t	tr_length;
} __packed;

struct tns_data {
	uint16_t	td_flag;
} __packed;

#define TNS_TOKSIZE	128

extern int verbose;

ssize_t tns_find_token(char *, char *);
ssize_t tns_get_vpair(char *str, char *, char *);
//int tns_parse(struct session *, char *, size_t, char **, size_t *, int);

ssize_t
tns_find_token(char *str, char *token)
{
	char *cp = str;

	while (*cp != '\0') {
		/* if first symbol matches check others */
		if (*cp == *token && strncmp(cp, token, strlen(token)) == 0) {
			cp += strlen(token);
			if (*cp != '=' && *++cp != '(')
				return (-1);
			return ((size_t)(++cp - str));
		}
		cp++;
	}

	return (-1);
}

ssize_t
tns_get_vpair(char *str, char *var, char *val)
{
	char *cp = str;
	int len;

	if (*cp++ != '(')
		return (-1);

	/* copy variable name */
	for (len = TNS_TOKSIZE; len > 0 && *cp != '='; len--) {
		if (*cp == '\0')
			return (-1);
		*var++ = *cp++;
	}
	*var = '\0';
	cp++;

	/* copy its value */
	for (len = TNS_TOKSIZE; len > 0 && *cp != ')'; len--) {
		if (*cp == '\0')
			return (-1);
		*val++ = *cp++;
	}
	*val = '\0';

	return ((size_t)(++cp - str));
}

int
tns_redirect(struct session *s, char *ibuf, size_t ilen, char **obuf,
    size_t *olen, int redirect)
{
	char var[TNS_TOKSIZE], val[TNS_TOKSIZE], *ibp = ibuf, *obp = *obuf;
	char addr[MAXHOSTNAMELEN], portstr[8];
	struct sockaddr_storage rss;
	struct tns_header *th;
	struct tns_redirect *tr;
	size_t len, left = PROXY_BUFSIZE;
	ssize_t off;
	ushort port;
	const char *errstr, *cause = NULL;

	ibuf[ilen] = '\0';

	th = (struct tns_header *)ibuf;
	tr = (struct tns_redirect *)(th + 1);
	len = sizeof(*th) + sizeof(*tr);
	if (s->flags & SF_REDIRECT) {
		bcopy(ibp, obp, len);
		obp += len;
		left -= len;
	}
	ibp += len;

	if (left <= ntohs(tr->tr_length)) {
		cause = "bad data length";
		goto parse_error;
	}

	if (verbose > 1)
		log_debug("#%d <- \"%s\" (%d)", s->id, ibuf + len, ilen);

	if ((off = tns_find_token(ibp, "ADDRESS")) <= 0) {
		cause = "ADDRESS not found";
		goto parse_error;
	}

	if (s->flags & SF_REDIRECT) {
		bcopy(ibp, obp, off);
		obp += off;
		left -= off;
	}
	ibp += off;

	while ((off = tns_get_vpair(ibp, var, val)) > 0) {
		if (off == -1) {
			cause = "bad offset";
			goto parse_error;
		}
		len = 0;
		if (strcmp(var, "HOST") == 0) {
			if (redirect)
				strlcpy(addr, val, sizeof(addr));
			if (s->flags & SF_REDIRECT) {
				len = snprintf(obp, left, "(%s=%s)", var,
				    print_host(redirect ? &s->oserver_ss :
				    &s->server_ss, 0));
				if (len <= 0) {
					cause = "snprintf1";
					goto parse_error;
				}
				obp += len;
				left -= len;
			}
		} else if (strcmp(var, "PORT") == 0) {
			if (redirect)
				strlcpy(portstr, val, sizeof(portstr));
			if (redirect && (s->flags & SF_REDIRECT)) {
				len = snprintf(obp, left, "(%s=%d)", var,
				    s->port);
				if (len <= 0) {
					cause = "snprintf2";
					goto parse_error;
				}
				obp += len;
				left -= len;
			}
		}
		if ((s->flags & SF_REDIRECT) && len == 0) {
			bcopy(ibp, obp, off);
			obp += off;
			left -= off;
		}
		ibp += off;
	}

	if (redirect) {
		if (verbose > 1)
			log_debug("#%d parsed host %s port %s", s->id, addr,
			    portstr);
		if (sock_pton(&rss, addr)) {
			cause = "sock_pton";
			goto parse_error;
		}
		port = (ushort)strtonum(portstr, 1, 65535, &errstr);
		if (errstr) {
			cause = "strtonum";
			goto parse_error;
		}
		if (proxy_filter(s, 0, sstosa(&rss), port, 0)) {
			log_warn("#%u failed to setup pf", s->id);
			return (-1);
		}
	}

	if (!(s->flags & SF_REDIRECT)) {
		*obuf = ibuf;
		*olen = ilen;
		return (0);
	}

	bcopy(ibp, obp, ilen - (size_t)(ibp - ibuf));
	left -= ilen - (size_t)(ibp - ibuf);

	th = (struct tns_header *)(*obuf);
	tr = (struct tns_redirect *)(th + 1);
	len = sizeof(*th) + sizeof(*tr);
	*olen = PROXY_BUFSIZE - left;
	if (redirect)
		tr->tr_length = htons(*olen - len);
	th->th_length = htons(*olen);

	if (verbose > 1) {
		(*obuf)[*olen] = '\0';
		log_debug("#%d -> \"%s\" (%d)", s->id, *obuf + len, *olen);
	}

	return (0);

 parse_error:
	log_warn("#%d failed to parse TNS Redirect%s%s", s->id,
	    cause ? ":" : "", cause ? cause : "");
	return (-1);
}

int
tns_connect(struct session *s)
{
	return (0);
}

ssize_t
tns_header_size(void)
{
	return (sizeof(struct tns_header));
}

ssize_t
tns_packet_size(struct session *s, char *hdr, size_t hdrlen)
{
	struct tns_header *th;

	th = (struct tns_header *)hdr;

	return (ntohs(th->th_length));
}

int
tns_client(struct session *s, char *ibuf, size_t buflen, char **obuf,
    size_t *outlen)
{
	struct tns_header *th;
	size_t ilen;

	th = (struct tns_header *)ibuf;

	ilen = ntohs(th->th_length);
	if (ilen > buflen)
		return (B_ERROR);

	switch (th->th_type) {
	case TNS_CONNECT:
		if (verbose > 1)
			log_debug("#%u -> TNS_CONNECT", s->id);
		break;
	case TNS_DATA:
		if (verbose > 1)
			log_debug("#%u -> TNS_DATA", s->id);
		break;
	default:
		if (verbose > 1)
			log_debug("#%u message type %d from the client",
			    s->id, th->th_type);
		break;
	}

	*obuf = ibuf;
	*outlen = buflen;

	return (B_OK);
}

int
tns_server(struct session *s, char *ibuf, size_t buflen, char **obuf, size_t *outlen)
{
	struct tns_header *th;
	size_t ilen;

	th = (struct tns_header *)ibuf;

	ilen = ntohs(th->th_length);
	if (ilen > buflen)
		return (B_ERROR);

	switch (th->th_type) {
	case TNS_REDIRECT:
		if (verbose > 1)
			log_debug("#%u <- TNS_REDIRECT", s->id);
		if (tns_redirect(s, ibuf, ilen, obuf, outlen, 1)) {
			log_warn("#%d TNS processing failed", s->id);
			return (B_ERROR);
		}
		break;
	case TNS_RESEND:
		if (verbose > 1)
			log_debug("#%u <- TNS_RESEND", s->id);
		break;
	default:
		if (verbose > 1)
			log_debug("#%u message type %d from the server",
			    s->id, th->th_type);
		break;
	}

	if (th->th_type != TNS_REDIRECT) {
		*obuf = ibuf;
		*outlen = buflen;
	}

	return (B_OK);
}

void
tns_disconnect(struct session *s)
{
}
