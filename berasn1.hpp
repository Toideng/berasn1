#ifndef LEN_CODEC_H
#define LEN_CODEC_H

#include "xtypes.hpp"

#ifdef TARGET_WIN32
//#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif



#define BIGLEN_LEN 128



/*
 * This structure is analogous to file descriptor.
 */

struct berasn1_conn
{
	byte len[BIGLEN_LEN]; // big-endian
	int is_receiving;

#ifdef TARGET_WIN32
	SOCKET sockfd;
#endif

#ifdef TARGET_LINUX
	int fd;
#endif
};



int
berasn1_bind_listen(
	struct berasn1_conn *conn,
	char *port
);

int
berasn1_accept(
	struct berasn1_conn *new_conn,
	struct berasn1_conn *listen_conn
);



int
berasn1_connect(
	struct berasn1_conn *conn,
	char *host,
	char *port
);



/* NOTE(toideng):
 * This pair of function emulates a half-duplex channel. It is an error to send
 * data while there is still data to be received in the current frame.
 */

ssize_t
berasn1_recv(
	struct berasn1_conn *conn,
	void *dst,
	size_t len
);

ssize_t
berasn1_send(
	struct berasn1_conn *conn,
	void *src,
	size_t len
);



int
berasn1_close(
	struct berasn1_conn *conn
);



#endif /* LEN_CODEC_H */
