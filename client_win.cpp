#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "berasn1.hpp"
#include "xtypes.hpp"



#define BUFFER_SIZE 0x1000
byte buf[BUFFER_SIZE];



int
main(void)
{
	int res;
	std::cout << "Client started" << std::endl;

	WSADATA wsaData;

	res = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (res)
	{
		fprintf(stderr, "WSAStartup failed with error: %d\n", res);
		return 1;
	}

	struct berasn1_conn conn;

	res = berasn1_connect(&conn, (char*)"127.0.0.1", (char*)"1234");
	if (res)
	{
		fprintf(stderr, "Failed to connect to server\n");
		exit(EXIT_FAILURE);
	}

	while (!feof(stdin))
	{
		fgets((char*)buf, BUFFER_SIZE, stdin);
		size_t len = strlen((char*)buf);
		ssize_t res;
		size_t off = 0;
		while (off < len)
		{
			res = berasn1_send(&conn, buf + off, len - off);
			if (res < 0)
			{
				fprintf(stderr, "Failed to send\n");
				exit(EXIT_FAILURE);
			}
			if (res == 0)
				goto end;

			off += (size_t)res;
		}

		res = berasn1_recv(&conn, buf, BUFFER_SIZE);
		if (res < 0)
		{
			fprintf(stderr, "Failed to recv\n");
			exit(EXIT_FAILURE);
		}
		if (res == 0)
			break;
		fwrite(buf, 1, (size_t)res, stdout);
	}
end:

	berasn1_close(&conn);

	WSACleanup();

	return 0;
}
