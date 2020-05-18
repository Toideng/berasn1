#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "berasn1.hpp"
#include "xtypes.hpp"










int
berasn1_bind_listen(
	struct berasn1_conn *conn,
	char *port
	)
{
	int res;

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *servinfo;
	res = getaddrinfo(0, port, &hints, &servinfo);
	if (res)
	{
		fprintf(stderr, "getaddrinfo: %s\xa", gai_strerror(res));
		return -1;
	}

	int listenfd;
	struct addrinfo *p;
	for (p = servinfo;  p;  p = p->ai_next)
	{
		listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listenfd == -1)
		{
			perror("socket");
			continue;
		}

		int yes = 1;
		if (setsockopt(listenfd,
		               SOL_SOCKET,
		               SO_REUSEADDR,
		               &yes,
		               sizeof(int)) == -1)
		{
			perror("setsockopt");
			return -1;
		}

		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(listenfd);
			perror("bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (!p)
	{
		fprintf(stderr, "failed to bind\xa");
		return -1;
	}

	if (listen(listenfd, 10) == -1)
	{
		perror("listen");
		return -1;
	}

	memset(conn, 0, sizeof *conn);
	conn->fd = listenfd;

	return 0;
}










int
berasn1_accept(
	struct berasn1_conn *new_conn,
	struct berasn1_conn *listen_conn
	)
{
	struct sockaddr_storage inbound_addr;
	socklen_t sin_size;
	int inbound_fd;

	sin_size = sizeof inbound_addr;
	inbound_fd = accept(listen_conn->fd,
	                    (struct sockaddr *)&inbound_addr,
	                    &sin_size);
	if (inbound_fd == -1)
	{
		perror("accept");
		return -1;
	}

	memset(new_conn, 0, sizeof *new_conn);
	new_conn->fd = inbound_fd;

	return 0;
}










int
berasn1_connect(
	struct berasn1_conn *conn,
	char *host,
	char *port
	)
{
	int res;
	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *servinfo;
	res = getaddrinfo(host, port, &hints, &servinfo);
	if (res)
	{
		fprintf(stderr, "getaddrinfo: %s\xa", gai_strerror(res));
		return -1;
	}

	int outbound_fd;
	struct addrinfo *p;
	for(p = servinfo;  p;  p = p->ai_next)
	{
		outbound_fd = socket(p->ai_family,
		                     p->ai_socktype,
		                     p->ai_protocol);
		if (outbound_fd == -1)
		{
			perror("socket");
			continue;
		}

		res = connect(outbound_fd, p->ai_addr, p->ai_addrlen);
		if (res == -1)
		{
			close(outbound_fd);
			perror("connect");
			continue;
		}

		break;
	}

	if (!p)
	{
		fprintf(stderr, "failed to connect\xa");
		return -1;
	}

	memset(conn, 0, sizeof *conn);
	conn->fd = outbound_fd;

	return 0;
}










int
recv_berasn1_len(
	struct berasn1_conn *conn
	)
{
	ssize_t res;
	memset(conn->len, 0, BIGLEN_LEN);
	byte hdr;

	res = recv(conn->fd, &hdr, 1, 0);
	if (res == 0)
	{
		// blocking call to recv only returns 0 when connection was
		// reset by peer
		//berasn1_close(conn);
		return 0;
	}
	else if (res < 0)
	{
		perror("recv");
		return -1;
	}

	if (!(hdr & 0x80))
	{
		conn->len[BIGLEN_LEN - 1] = hdr;
		return 1;
	}

	size_t left = (size_t)(hdr & 0x7f);

	byte *p = conn->len;
	p += (BIGLEN_LEN - left);

	while (left)
	{
		res = recv(conn->fd, p, left, 0);
		if (res == 0)
		{
			// Abrupt connection reset
			return -1;
		}
		if (res < 0)
			return -1;

		left -= (size_t)res;
		p += (size_t)res;
	}

	return 1;
}


// Generate biglen from size_t
void
biglen_from_size_t(
	byte out[BIGLEN_LEN],
	size_t in
	)
{
	memset(out, 0, BIGLEN_LEN);
	for (size_t i = 0;  i < sizeof i;  i++)
		out[BIGLEN_LEN - i - 1] = ((in >> (i * 8))) & 0xff;
	return;
}

// Generate size_t from biglen
// If [in] cannot fit in size_t, returns 0
size_t
biglen_to_size_t(
	byte in[BIGLEN_LEN]
	)
{
	for (size_t i = sizeof i;  i < BIGLEN_LEN;  i++)
		if (in[BIGLEN_LEN - i - 1])
			return 0;
	size_t result = 0;
	for (size_t i = 0;  i < sizeof i;  i++)
		result |= ((size_t)(in[BIGLEN_LEN - i - 1])) << (i * 8);
	return result;
}

// Select and return the minimum of two values.
size_t
biglen_min_size_t(
	byte biglen[BIGLEN_LEN],
	size_t len
	)
{
	byte len_be[BIGLEN_LEN];
	biglen_from_size_t(len_be, len);

	if (memcmp(len_be, biglen, BIGLEN_LEN) <= 0)
		return len;
	else
		return biglen_to_size_t(biglen);
}

// Decrease [biglen] by no more than [decr]
// Returns 0 if [biglen] was reduced to zero, 1 otherwise
int
biglen_decrease(
	byte biglen[BIGLEN_LEN],
	size_t decr
	)
{
	if (biglen_min_size_t(biglen, decr) < decr)
	{
		memset(biglen, 0, BIGLEN_LEN);
		return 0;
	}

	byte bigdecr[BIGLEN_LEN];
	biglen_from_size_t(bigdecr, decr);
	int res_zero = 1;
	size_t carry = 0;

	for (ssize_t i = BIGLEN_LEN - 1;  i >= 0;  i--)
	{
		if (biglen[i] < carry + bigdecr[i])
		{
			carry = 1;
			biglen[i] = (0x100 + (size_t)biglen[i]) - (carry + (size_t)bigdecr[i]);
			if (biglen[i])
				res_zero = 0;
		}
		else
		{
			carry = 0;
			biglen[i] = ((size_t)biglen[i]) - (carry + (size_t)bigdecr[i]);
			if (biglen[i])
				res_zero = 0;
		}
	}

	if (res_zero)
		return 0;
	return 1;
}



ssize_t
berasn1_recv(
	struct berasn1_conn *conn,
	void *pdst,
	size_t len
	)
{
	if (!len)
		return -1;
	byte *dst = (byte*)pdst;
	size_t recved = 0;

	if (!conn->is_receiving)
	{
		int res = recv_berasn1_len(conn);
		if (res == -1)
			return -1;
		if (res == 0)
			return 0;
		conn->is_receiving = 1;
	}

	len = biglen_min_size_t(conn->len, len);
	
	while (len)
	{
		ssize_t res = recv(conn->fd, dst, len, 0);
		if (res <= 0)
		{
			perror("recv");
			return -1;
		}

		recved += (size_t)res;
		len -= (size_t)res;
		dst += (size_t)res;

		if (biglen_decrease(conn->len, (size_t)res) == 0)
		{
			conn->is_receiving = 0;
			break;
		}
	}

	return (ssize_t)recved;
}










int
send_berasn1_len(
	struct berasn1_conn *conn,
	size_t len
	)
{
	byte hdr;

	if (len <= 0x7f)
	{
		hdr = (byte)len;
		ssize_t res = send(conn->fd, &hdr, 1, 0);
		if (res == 0)
			return 0;
		if (res < 0)
			return -1;

		return 1;
	}

	byte preamble[0x10];
	hdr = 0x80;

	size_t x = len;
	while (x)
	{
		hdr++;
		x >>= 8;
	}
	x = hdr & 0x7f;

	preamble[0] = hdr;
	for (size_t i = 1;  i <= x;  i++)
		preamble[i] = (len >> ((x - i) * 8)) & 0xff;

	byte *src = preamble;
	byte *end = src + x + 1;
	while (src < end)
	{
		ssize_t res = send(conn->fd, src, end - src, 0);
		if (res == 0)
			return 0;
		if (res < 0)
			return -1;

		src += (size_t)res;
	}

	return 1;
}



ssize_t
berasn1_send(
	struct berasn1_conn *conn,
	void *psrc,
	size_t len
	)
{
	if (conn->is_receiving)
		return -1;
	if (!len)
		return -1;

	byte *src = (byte*)psrc;

	int res = send_berasn1_len(conn, len);
	if (res == 0)
		return 0;
	if (res < 0)
		return -1;

	size_t sent = 0;
	while (len)
	{
		ssize_t res = send(conn->fd, src, len, 0);
		if (res <= 0)
			return -1;

		sent += (size_t)res;
		len -= (size_t)res;
		src += (size_t)res;
	}

	return (ssize_t)sent;
}










int
berasn1_close(
	struct berasn1_conn *conn
	)
{
	int res = 0;
	if (conn->fd)
		res = close(conn->fd);
	memset(conn, 0, sizeof *conn);
	return res;
}
