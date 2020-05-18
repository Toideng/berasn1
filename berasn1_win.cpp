#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "berasn1.hpp"
#include "xtypes.hpp"



// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")










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
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *servinfo;
	res = getaddrinfo(0, port, &hints, &servinfo);
	if (res)
	{
		fprintf(stderr, "getaddrinfo failed with error: %d\n", res);
		return 1;
	}

	SOCKET listenfd;
	listenfd = socket(
		servinfo->ai_family,
		servinfo->ai_socktype,
		servinfo->ai_protocol);

	if (listenfd == INVALID_SOCKET)
	{
		fprintf(stderr, "socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(servinfo);
		return 1;
	}

	// Setup the TCP listening socket
	res = bind(
		listenfd,
		servinfo->ai_addr,
		(int)servinfo->ai_addrlen);

	if (res == SOCKET_ERROR)
	{
		fprintf(stderr, "bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(servinfo);
		closesocket(listenfd);
		return 1;
	}

	freeaddrinfo(servinfo);

	res = listen(listenfd, SOMAXCONN);
	if (res == SOCKET_ERROR)
	{
		fprintf(stderr, "listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenfd);
		return 1;
	}

	memset(conn, 0, sizeof *conn);
	conn->sockfd = listenfd;

	return 0;
}










int
berasn1_accept(
	struct berasn1_conn *new_conn,
	struct berasn1_conn *listen_conn
	)
{
	SOCKET inbound_fd = accept(listen_conn->sockfd, 0, 0);
	if (inbound_fd == INVALID_SOCKET)
	{
		fprintf(stderr, "accept failed with error: %d\n", WSAGetLastError());
		return 1;
	}

	memset(new_conn, 0, sizeof *new_conn);
	new_conn->sockfd = inbound_fd;

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
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *servinfo;
	res = getaddrinfo(host, port, &hints, &servinfo);
	if (res)
	{
		fprintf(stderr, "getaddrinfo failed with error: %d\n", res);
		return 1;
	}

	SOCKET outbound_fd;
	struct addrinfo *p;
	for (p = servinfo;  p;  p = p->ai_next)
	{
		outbound_fd = socket(p->ai_family,
		                     p->ai_socktype,
		                     p->ai_protocol);
		if (outbound_fd == INVALID_SOCKET)
		{
			fprintf(stderr, "socket failed with error: %ld\n", WSAGetLastError());
			return -1;
		}

		res = connect(outbound_fd, p->ai_addr, (int)p->ai_addrlen);
		if (res == SOCKET_ERROR)
		{
			closesocket(outbound_fd);
			continue;
		}

		break;
	}

	if (!p)
	{
		fprintf(stderr, "failed to connect\xa");
		return -1;
	}

	freeaddrinfo(servinfo);

	memset(conn, 0, sizeof *conn);
	conn->sockfd = outbound_fd;

	return 0;
}










int
recv_berasn1_len(
	struct berasn1_conn *conn
	)
{
	int res;
	memset(conn->len, 0, BIGLEN_LEN);
	byte hdr;

	res = recv(conn->sockfd, &hdr, 1, 0);
	if (res == 0)
	{
		// blocking call to recv only returns 0 when connection was
		// reset by peer
		//berasn1_close(conn);
		return 0;
	}
	else if (res < 0)
	{
		fprintf(stderr, "failed to recv\xa");
		return -1;
	}

	if (!(hdr & 0x80))
	{
		conn->len[BIGLEN_LEN - 1] = hdr;
		return 1;
	}

	int left = (int)(hdr & 0x7f);

	byte *p = conn->len;
	p += (BIGLEN_LEN - left);

	while (left)
	{
		res = recv(conn->sockfd, p, left, 0);
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
		ssize_t res = recv(conn->sockfd, dst, (int)len, 0);
		if (res <= 0)
		{
			fprintf(stderr, "failed to recv\n");
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
		ssize_t res = send(conn->sockfd, &hdr, 1, 0);
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
		ssize_t res = send(conn->sockfd, src, (int)(end - src), 0);
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
		ssize_t res = send(conn->sockfd, src, (int)len, 0);
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
	if (conn->sockfd)
		closesocket(conn->sockfd);
	memset(conn, 0, sizeof *conn);
	return 0;
}
