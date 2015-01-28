/*	$OpenBSD: privsep_fdpass.c,v 1.7 2008/03/24 16:11:06 deraadt Exp $	*/

/*
 * Copyright (c) 2002 Matthieu Herrb
 * Copyright (c) 2001 Niels Provos <provos@citi.umich.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

int
send_fd(int sock, int fd, uint ticket)
{
	struct msghdr msg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec vec[2];
	ssize_t n;
	int result = 0;

	memset(&msg, 0, sizeof(msg));

	if (fd >= 0) {
		msg.msg_control = (caddr_t)&cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = fd;
	} else
		result = errno;

	vec[0].iov_base = &result;
	vec[0].iov_len = sizeof(int);
	vec[1].iov_base = &ticket;
	vec[1].iov_len = sizeof(uint);
	msg.msg_iov = vec;
	msg.msg_iovlen = 2;

	if ((n = sendmsg(sock, &msg, 0)) == -1) {
		syslog(LOG_ERR, "send_fd: %m");
		return (-1);
	}

	return (0);
}

int
receive_fd(int sock, uint *ticket)
{
	struct msghdr msg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct iovec vec[2];
	ssize_t n;
	int result = 0;
	int fd;

	memset(&msg, 0, sizeof(msg));
	vec[0].iov_base = &result;
	vec[0].iov_len = sizeof(int);
	vec[1].iov_base = ticket;
	vec[1].iov_len = sizeof(uint);
	msg.msg_iov = vec;
	msg.msg_iovlen = 2;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((n = recvmsg(sock, &msg, 0)) == -1) {
		syslog(LOG_ERR, "receive_fd: %m");
		return (-1);
	}
	if (n == 0) {
		syslog(LOG_ERR, "receive_fd: zero length");
		return (-1);
	}
	if (result == 0) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL) {
			syslog(LOG_ERR, "receive_fd: no message header");
			return (-1);
		}
		if (cmsg->cmsg_type != SCM_RIGHTS) {
			syslog(LOG_ERR, "receive_fd: expected type %d got %d",
			    SCM_RIGHTS, cmsg->cmsg_type);
			return (-1);
		}
		fd = (*(int *)CMSG_DATA(cmsg));
		return (fd);
	} else {
		errno = result;
		syslog(LOG_ERR, "receive_fd: result: %m");
		return (-1);
	}
}
