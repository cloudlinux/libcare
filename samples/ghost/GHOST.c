#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

#define CANARY "in_the_coal_mine"

struct canary {
  char buffer[1024];
  char canary[sizeof(CANARY)];
};

const struct canary orig = { "buffer", CANARY };

struct canary temp;

void *thread(void *data)
{
	struct hostent resbuf;
	struct hostent *result;
	int herrno;
	int retval;

	while (1) {
		/*** strlen (name) = size_needed - sizeof (*host_addr) - sizeof (*h_addr_ptrs) - 1; ***/
		size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;
		char name[sizeof(temp.buffer)];
		memset(name, '0', len);
		name[len] = '\0';

		memcpy(&temp, &orig, sizeof(temp));

		retval = gethostbyname_r(name, &resbuf, temp.buffer, sizeof(temp.buffer), &result, &herrno);

		if (strcmp(temp.canary, CANARY) != 0) {
			putc('.', stderr);
		}
		if (retval == ERANGE) {
			//puts("not vulnerable");
			return NULL;
		}
		sleep(1);
	}
}

#define NTHREADS	16

int main(void) 
{
	pthread_t threads[NTHREADS];
	int i;

	for (i = 0; i < NTHREADS; i++){
		pthread_create(&threads[i], NULL, thread, NULL);
	}

	for (i = 0; i < NTHREADS; i++){
		pthread_join(threads[i], NULL);
	}
}
