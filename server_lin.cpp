#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>

#include "berasn1.hpp"
#include "xtypes.hpp"



#define BUFFER_SIZE 0x1000
byte buf[BUFFER_SIZE];



void
sigchld_handler(
	int s)
{
	MAKEUSED(s);
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while (waitpid(-1, NULL, WNOHANG) > 0)
	{
	}

	errno = saved_errno;
}



int
main(void)
{
	std::cout << "Server started" << std::endl;

	struct berasn1_conn conn;
	int res;

	struct sigaction sa;
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, 0) == -1)
	{
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	res = berasn1_bind_listen(&conn, (char*)"1234");
	if (res)
	{
		fprintf(stderr, "Failed to bind, stop\xa");
		exit(EXIT_FAILURE);
	}

	while (1)
	{
		struct berasn1_conn newconn;
		res = berasn1_accept(&newconn, &conn);

		// NOTE(toideng): This approach is a humongous security hole and
		//                can easily be used to perform a variety of DOS
		//                attacks. But this is good enough for a test
		//                code
		if (!fork())
		{
			berasn1_close(&conn);

			while (1)
			{
				fprintf(stderr, "do recv\xa");
				ssize_t res;
				res = berasn1_recv(&newconn, buf, BUFFER_SIZE);
				if (!res)
				{
					fprintf(stderr, "recv == 0\xa");
					break;
				}
				if (res < 0)
				{
					fprintf(stderr, "recv < 0\xa");
					berasn1_close(&newconn);
					exit(EXIT_FAILURE);
				}

				res = berasn1_send(&newconn, buf, (size_t)res);
				if (!res)
					break;
				if (res < 0)
				{
					berasn1_close(&newconn);
					exit(EXIT_FAILURE);
				}
			}

			berasn1_close(&newconn);
			exit(EXIT_SUCCESS);
		}

		berasn1_close(&newconn);
	}

	berasn1_close(&conn);

	return 0;
}
