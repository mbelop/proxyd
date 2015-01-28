PROG=	proxyd
SRCS=	conf.y proxy.c filter.c fdpass.c util.c msrpc.c sunrpc.c tns.c
MAN=	proxyd.8 proxyd.conf.5

DEBUG?=	-O0 -g -DDEBUG

CFLAGS+=-Wall -Werror -I${.CURDIR}

YFLAGS=

LDADD+=	-levent
LDDEP+=	${LIBEVENT}

.include <bsd.prog.mk>
