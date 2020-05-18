#ifndef LEN_CODEC_H
#define LEN_CODEC_H

#include "xtypes.hpp"



struct berasn1_conn
{
	byte len[128]; // big-endian
	int in_message; // set to 0 if connection is waiting for a new message.

#ifdef TARGET_WIN32
#error "Win32 is not supported yet"
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
	struct berasn1_conn *listen_conn,
	struct berasn1_conn *new_conn
);



int
berasn1_connect(
	struct berasn1_conn *conn,
	char *host,
	char *port
);



// NOTE(toideng): these functions can deadlock if used improperly

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
