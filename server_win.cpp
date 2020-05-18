#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>

#include "berasn1.hpp"
#include "xtypes.hpp"



#define BUFFER_SIZE 0x1000
byte buf[BUFFER_SIZE];



int
main(void)
{
	int res;
	std::cout << "Server started" << std::endl;

	WSADATA wsaData;

	res = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (res)
	{
		fprintf(stderr, "WSAStartup failed with error: %d\n", res);
		return 1;
	}

	struct berasn1_conn conn;
	struct berasn1_conn newconn;

	res = berasn1_bind_listen(&conn, (char*)"1234");
	if (res)
	{
		fprintf(stderr, "Failed to bind, stop\n");
		exit(EXIT_FAILURE);
	}

	while (1)
	{
		res = berasn1_accept(&newconn, &conn);
		if (res)
		{
			fprintf(stderr, "Failed to accept, stop\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stdout, "Accepted a connection.\n");
		while (1)
		{
			ssize_t res;
			res = berasn1_recv(&newconn, buf, BUFFER_SIZE);
			if (!res)
				break;
			if (res < 0)
			{
				berasn1_close(&newconn);
				exit(EXIT_FAILURE);
			}
			if (newconn.is_receiving)
			{
				fprintf(stderr, "Incoming message too large to handle, stop\n");
				berasn1_close(&newconn);
				exit(EXIT_FAILURE);
			}
			fprintf(stdout, "Got a %lu-byte long msg.\n", (size_t)res);

			res = berasn1_send(&newconn, buf, (size_t)res);
			if (!res)
				break;
			if (res < 0)
			{
				berasn1_close(&newconn);
				exit(EXIT_FAILURE);
			}
		}
		fprintf(stdout, "Dropped a connection.\n");

		berasn1_close(&newconn);
	}

	berasn1_close(&conn);

	WSACleanup();

	return 0;
}
