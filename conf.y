/*
 * Copyright (c) 2011 Mike Belopuhov
 * Copyright (c) 2002-2006 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "proxy.h"

extern struct backend backends[];

struct {
	int	type;
	char *	name;
} proxy_type_map[] = {
	{ PROXY_TNS,	"oracle-tns" },
	{ PROXY_SUNRPC,	"sun-rpc" },
	{ PROXY_MSRPC,	"ms-rpc" }
};

TAILQ_HEAD(files, file)		files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	entry;
	FILE *			stream;
	char *			name;
	int			lineno;
	int			errors;
} *file, *topfile;
struct file *	pushfile(const char *);
int		popfile(void);
int		yyparse(void);
int		yylex(void);
int		yyerror(const char *, ...);
int		kw_cmp(const void *, const void *);
int		kw_lookup(const char *);
int		lgetc(int);
int		lungetc(int);
int		findeol(void);

void		print_config(void);
const char *	print_addr(struct address *);
const char *	print_proto(int);
int		gethost(struct addresslist *, const char *);

extern struct conf 		conf;
static struct table *		table = NULL;
static struct proxy *		proxy = NULL;

typedef struct {
	union {
		int		number;
		char *		string;
		struct address *addr;
		struct host *	host;
		struct table *	table;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	ARROW ERROR INCLUDE PROXY SET TABLE
%token	CONNECT IDLE LISTEN LOGGING MAP NO OFF ON PF PORT RDOMAIN QUEUE
%token	TAG TIMEOUT TRANSPARENT TYPE USE YES
%token	<v.number>	NUMBER
%token	<v.string>	STRING

%type	<v.addr>	address
%type	<v.host>	host map
%type	<v.number>	onoff no port proto timeout type
%type	<v.string>	optstring table

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar include '\n'
		| grammar set '\n'
		| grammar tabledef '\n'
		| grammar proxy '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING {
			struct file *nfile;

			if ((nfile = pushfile($2)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);
			file = nfile;
			lungetc('\n');
		}
		;

set		: SET PF LOGGING onoff {
			conf.filter.log = $4;
		}
		| SET PF QUEUE STRING {
			if (strlen(conf.filter.queue)) {
				yyerror("queue redefined");
				free($4);
				YYERROR;
			}
			strlcpy(conf.filter.queue, $4,
			    sizeof(conf.filter.queue));
			free($4);
		}
		| SET PF TAG STRING {
			if (strlen(conf.filter.tag)) {
				yyerror("tag redefined");
				free($4);
				YYERROR;
			}
			strlcpy(conf.filter.tag, $4,
			    sizeof(conf.filter.tag));
			free($4);
		}
		| SET RDOMAIN NUMBER {
			if ($3 < 0 || $3 > 2048) {
				yyerror("invalid routing domain %d", $3);
				YYERROR;
			}
			conf.rdomain = $3;
		}
		| SET TIMEOUT CONNECT timeout {
			conf.connect_tv.tv_sec = $4;
		}
		| SET TIMEOUT IDLE timeout {
			conf.idle_tv.tv_sec = $4;
		}
		| SET TRANSPARENT onoff {
			conf.transparent = $3;
		}
		;

onoff		: ON  { $$ = 1; }
		| OFF { $$ = 0; }
		;

tabledef	: TABLE table {
			struct table *t;

			TAILQ_FOREACH(t, &conf.tables, entry) {
				if (!strcmp(t->name, $2))
					break;
			}
			if (t != NULL) {
				yyerror("table %s defined twice", $2);
				free($2);
				YYERROR;
			}

			if ((t = calloc(1, sizeof(*t))) == NULL)
				errx(1, "out of memory");
			strlcpy(t->name, $2, sizeof(t->name));
			free($2);
			TAILQ_INIT(&t->hosts);
			table = t;
		} '{' optnl hostlist_l '}' {
			if (TAILQ_EMPTY(&table->hosts)) {
				yyerror("empty table %s", table->name);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&conf.tables, table, entry);
			table = NULL;
		}
		;

table		: '<' STRING '>' {
			if (strlen($2) >= TABLE_NAME_SIZE) {
				yyerror("invalid table name");
				free($2);
				YYERROR;
			}
			$$ = $2;
		}
		;

hostlist_l	: hostlist comma hostlist_l
		| hostlist optnl
		;

hostlist	: host {
			TAILQ_INSERT_TAIL(&table->hosts, $1, entry);
			table->entries++;
		}
		;

host		: map {
			if (table->entries &&
			    (table->flags & TABLE_MAP) == 0) {
				yyerror("map entry in the regular table");
				free($1->addr);
				free($1->map);
				free($1);
				YYERROR;
			}

			table->flags |= TABLE_MAP;
			$$ = $1;
		}
		| address {
			struct host *h;

			if (table->entries && (table->flags & TABLE_MAP)) {
				yyerror("host entry in the map");
				free($1);
				YYERROR;
			}

			if ((h = calloc(1, sizeof(*h))) == NULL)
				errx(1, "out of memory");
			h->addr = $1;
			$$ = h;
		}
		;

map		: address ARROW address {
			struct host *h;

			if ((h = calloc(1, sizeof(*h))) == NULL)
				errx(1, "out of memory");
			h->addr = $1;
			h->map = $3;
			$$ = h;
		}
		;

address		: STRING {
			struct addresslist al;
			struct address *a;

			TAILQ_INIT(&al);
			if (gethost(&al, $1) || TAILQ_EMPTY(&al)) {
				yyerror("invalid host %s", $1);
				free($1);
				YYERROR;
			}
			a = TAILQ_FIRST(&al);
			TAILQ_REMOVE(&al, a, entry);
			$$ = a;
			while ((a = TAILQ_FIRST(&al)) != NULL) {
				TAILQ_REMOVE(&al, a, entry);
				free(a);
			}
			free($1);
		}
		;

proxy		: PROXY STRING {
			struct proxy *p;

			TAILQ_FOREACH(p, &conf.proxies, entry) {
				if (!strcmp(p->name, $2))
					break;
			}
			if (p != NULL) {
				yyerror("proxy %s defined twice", $2);
				free($2);
				YYERROR;
			}

			if ((p = calloc(1, sizeof(*p))) == NULL)
				err(1, "out of memory");
			strlcpy(p->name, $2, sizeof(p->name));
			free($2);
			TAILQ_INIT(&p->listeners);
			TAILQ_INIT(&p->maps);
			p->type = -1;
			p->transparent = conf.transparent;
			p->filter = conf.filter;
			p->connect_tv = conf.connect_tv;
			p->idle_tv = conf.idle_tv;
			proxy = p;
		} optnl '{' optnl proxyopts_l '}' {
			if (proxy->type == -1) {
				yyerror("proxy %s doesn't specify its type",
				    proxy->name);
				free(proxy);
				YYERROR;
			}
			proxy->backend = &backends[proxy->type];
			TAILQ_INSERT_TAIL(&conf.proxies, proxy, entry);
			proxy = NULL;
		}
		;

proxyopts_l	: proxyopts_l proxyopts nl
		| proxyopts optnl
		;

proxyopts	: TYPE type {
			proxy->type = $2;
		}
		| LISTEN ON STRING proto port {
			struct addresslist al;
			struct address *a;
			struct listener *l;

			TAILQ_INIT(&al);
			if (gethost(&al, $3)) {
				yyerror("invalid host specification: %s", $3);
				free($3);
				YYERROR;
			}

			TAILQ_FOREACH(a, &al, entry) {
				if ((l = calloc(1, sizeof(*l))) == NULL)
					err(1, "out of memory");
				l->addr = a;
				l->proto = $4;
				l->port = $5;
				TAILQ_INSERT_TAIL(&proxy->listeners, l, entry);
			}
			free($3);
		}
		| SET PF LOGGING onoff {
			proxy->filter.log = $4;
		}
		| SET PF no QUEUE optstring {
			if (!$3) {
				strlcpy(proxy->filter.queue, $5,
				    sizeof(proxy->filter.queue));
				free($5);
			} else
				proxy->filter.queue[0] = '\0';
		}
		| SET PF no TAG optstring {
			if (!$3) {
				strlcpy(proxy->filter.tag, $5,
				    sizeof(proxy->filter.tag));
				free($5);
			} else
				proxy->filter.tag[0] = '\0';
		}
		| SET TIMEOUT CONNECT timeout {
			proxy->connect_tv.tv_sec = $4;
		}
		| SET TIMEOUT IDLE timeout {
			proxy->idle_tv.tv_sec = $4;
		}
		| SET TRANSPARENT onoff {
			proxy->transparent = $3;
		}
		| USE MAP table {
			struct table *t;
			struct tableptr *tp;

			TAILQ_FOREACH(t, &conf.tables, entry) {
				if (!strcmp(t->name, $3))
					break;
			}
			if (!t) {
				yyerror("table %s doesn't exist", $3);
				free($3);
				YYERROR;
			}
			if ((t->flags & TABLE_MAP) == 0) {
				yyerror("table %s is not a map", $3);
				free($3);
				YYERROR;
			}
			TAILQ_FOREACH(tp, &proxy->maps, entry) {
				if (tp->table == t)
					break;
			}
			if (tp) {
				yyerror("map %s was already specified", $3);
				free($3);
				YYERROR;
			}

			if ((tp = calloc(1, sizeof(*tp))) == NULL)
				err(1, "out of memory");
			tp->table = t;
			tp->table->flags |= TABLE_USED;
			TAILQ_INSERT_TAIL(&proxy->maps, tp, entry);
		}
		;

no		: /* empty */	{ $$ = 0; }
		| NO		{ $$ = 1; }

optstring	: /* empty */	{ $$ = NULL; }
		| STRING	{ $$ = $1; }

type		: STRING {
			int i, type = -1;

			for (i = 0; i < sizeof(proxy_type_map) /
			    sizeof(proxy_type_map[0]); i++) {
				if (!strcmp($1, proxy_type_map[i].name)) {
					type = proxy_type_map[i].type;
					break;
				}
			}
			if (type == -1) {
				yyerror("invalid proxy type: %s", $1);
				free($1);
				YYERROR;
			}
			free($1);
			$$ = type;
		}
		;

proto		: /* empty */ { $$ = -1; }
		| STRING {
			struct protoent *p;

			if (((p = getprotobyname($1)) == NULL) &&
			    (p->p_proto != IPPROTO_TCP &&
			     p->p_proto != IPPROTO_UDP)) {
				yyerror("invalid protocol: %s", $1);
				free($1);
				YYERROR;
			}
			free($1);
			$$ = p->p_proto;
		}
		;

port		: /* empty */ {
			$$ = -1;
		}
		| PORT NUMBER {
			if ($2 <= 0 || $2 >= (int)USHRT_MAX) {
				yyerror("invalid port: %d", $2);
				YYERROR;
			}
			$$ = $2;
		}
		;

timeout		: NUMBER {
			if ($1 <= 0 || $1 >= INT_MAX) {
				yyerror("invalid timeout %s", $1);
				YYERROR;
			}
			$$ = $1;
		}
		;

optnl		: '\n' optnl
		| /* empty */
		;

nl		: '\n' optnl
		;

comma		: ','
		| nl
		| /* empty */
		;

%%

int
yyerror(const char *fmt, ...)
{
	va_list ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

struct keywords {
	const char *	name;
	int		val;
};

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->name));
}

int
kw_lookup(const char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "connect",		CONNECT },
		{ "idle",		IDLE },
		{ "include",		INCLUDE },
		{ "listen",		LISTEN },
		{ "logging",		LOGGING },
		{ "map",		MAP },
		{ "no",			NO },
		{ "off",		OFF },
		{ "on",			ON },
		{ "pf",			PF },
		{ "port",		PORT },
		{ "proxy",		PROXY },
		{ "queue",		QUEUE },
		{ "rdomain",		RDOMAIN },
		{ "set",		SET },
		{ "table",		TABLE },
		{ "tag",		TAG },
		{ "timeout",		TIMEOUT },
		{ "transparent",	TRANSPARENT },
		{ "type",		TYPE },
		{ "use",		USE },
		{ "yes",		YES },
	};
	const struct keywords *k;

	k = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	return (k ? k->val : STRING);
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char buf[8096];
	char *p;
	int quotec, next, c;
	int token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n')
					continue;
				else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	case '-':
		next = lgetc(0);
		if (next == '>')
			return (ARROW);
		lungetc(next);
		break;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = kw_lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

struct file *
pushfile(const char *name)
{
	struct file *nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL)
		return (NULL);
	if ((nfile->name = strdup(name)) == NULL) {
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file *prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse_config(const char *filename, int verbose)
{
	struct table *t;

	if ((file = pushfile(filename)) == NULL)
		errx(1, "cannot open file %s", filename);
	topfile = file;

	TAILQ_INIT(&conf.proxies);
	TAILQ_INIT(&conf.tables);

	yyparse();
	if (file->errors)
		return (-1);

	popfile();

	if (TAILQ_EMPTY(&conf.proxies)) {
		errx(1, "no proxies defined");
	}

	TAILQ_FOREACH(t, &conf.tables, entry) {
		if ((t->flags & TABLE_USED) == 0)
			errx(1, "table %s is not used", t->name);
	}

	if (verbose > 1)
		print_config();

	return (0);
}

void
print_config(void)
{
	struct host *h;
	struct listener *l;
	struct proxy *p;
	struct table *t;
	struct tableptr *tp;

	/* print global settings */
	if (conf.filter.log)
		printf("set pf logging %s\n", conf.filter.log ?
		    "on" : "off");
	if (strlen(conf.filter.queue))
		printf("set pf queue \"%s\"\n", conf.filter.queue);
	if (strlen(conf.filter.tag))
		printf("set pf tag \"%s\"\n", conf.filter.tag);
	if (conf.rdomain)
		printf("set rdomain %d\n", conf.rdomain);
	if (!conf.transparent)
		printf("set transparent off\n");

	/* print tables */
	TAILQ_FOREACH(t, &conf.tables, entry) {
		printf("table <%s> {\n", t->name);
		TAILQ_FOREACH(h, &t->hosts, entry) {
			printf("\t%s", print_addr(h->addr));
			if (h->map)
				printf(" -> %s", print_addr(h->map));
			if (TAILQ_NEXT(h, entry))
				printf(",");
			printf("\n");
		}
		printf("}\n");
	}

	/* print proxies */
	TAILQ_FOREACH(p, &conf.proxies, entry) {
		printf("proxy \"%s\" {\n", p->name);
		printf("\ttype %s\n", proxy_type_map[p->type].name);
		TAILQ_FOREACH(l, &p->listeners, entry) {
			printf("\tlisten on %s %s%sport %d\n",
			    print_addr(l->addr), print_proto(l->proto),
			    l->proto == -1 ? "" : " ", l->port);
		}
		TAILQ_FOREACH(tp, &p->maps, entry) {
			printf("\tuse map <%s>\n", tp->table->name);
		}
		if (p->filter.log != conf.filter.log)
			printf("\tset pf logging %s\n", p->filter.log ?
			    "on" : "off");
		if (strcmp(p->filter.queue, conf.filter.queue)) {
			if (strlen(p->filter.queue))
				printf("\tset pf queue \"%s\"\n",
				    p->filter.queue);
			else
				printf("\tset pf no queue\n");
		}
		if (strcmp(p->filter.tag, conf.filter.tag)) {
			if (strlen(p->filter.tag))
				printf("\tset pf tag \"%s\"\n", p->filter.tag);
			else
				printf("\tset pf no tag\n");
		}
		if (p->connect_tv.tv_sec != conf.connect_tv.tv_sec)
			printf("\tset timeout connect %lld\n",
			    p->connect_tv.tv_sec);
		if (p->idle_tv.tv_sec != conf.idle_tv.tv_sec)
			printf("\tset timeout idle %lld\n", p->idle_tv.tv_sec);
		if (p->transparent != conf.transparent)
			printf("\tset transparent %s\n", p->transparent ?
			    "on" : "off");
		printf("}\n");
	}
}

const char *
print_addr(struct address *a)
{

	return (print_host(&a->ss, 0));
}

const char *
print_proto(int proto)
{
	struct protoent *p;

	if ((p = getprotobynumber(proto)) == NULL)
		return ("");
	else
		return (p->p_name);
}


int
gethost(struct addresslist *al, const char *s)
{
	struct addrinfo hints, *res, *res0;
	struct address *a = NULL;

	bzero(&hints, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM; /* dummy */
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, NULL, &hints, &res0) != 0)
		return (-1);
	for (res = res0; res; res = res->ai_next) {
		if ((a = calloc(1, sizeof(*a))) == NULL)
			err(1, NULL);
		bcopy(res->ai_addr, &a->ss, res->ai_addrlen);
		TAILQ_INSERT_TAIL(al, a, entry);
	}
	freeaddrinfo(res0);
	return (0);

}
