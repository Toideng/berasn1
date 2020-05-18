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
	std::cout << "Client started" << std::endl;

	struct berasn1_conn conn;
	int res;

	res = berasn1_connect(&conn, (char*)"127.0.0.1", (char*)"1234");
	if (res)
	{
		fprintf(stderr, "Failed to connect to server\xa");
		exit(EXIT_FAILURE);
	}

	fgets((char*)buf, BUFFER_SIZE, stdin);
	size_t len;
	while ((len = strlen((char const*)buf)))
	{
		ssize_t res;
		size_t off = 0;
		while (off < len)
		{
			res = berasn1_send(&conn, buf + off, len - off);
			if (res < 0)
			{
				fprintf(stderr, "Failed to send\xa");
				exit(EXIT_FAILURE);
			}
			if (res == 0)
				goto end;

			off += (size_t)res;
		}

		res = berasn1_recv(&conn, buf, BUFFER_SIZE);
		if (res < 0)
		{
			fprintf(stderr, "Failed to recv\xa");
			exit(EXIT_FAILURE);
		}
		if (res == 0)
			break;
		fwrite(buf, 1, (size_t)res, stdout);
		printf("\xa");

		fgets((char*)buf, BUFFER_SIZE, stdin);
	}
end:

	berasn1_close(&conn);

	return 0;
}
