
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#define MAX_STACK	4

static pthread_t mainthr;
static const struct timespec short_sleep = {
	.tv_nsec = 200000000,
}, long_sleep = {
	.tv_nsec = 800000000,
};

static void *func(void *);

static int payload(pthread_t *thread)
{
	int rv;

	nanosleep(&short_sleep, NULL);
	rv = pthread_create(thread, NULL, func, (void *)1UL);
	printf("HELLO FROM UNPATCHED\n");
	if (rv == -1)
		abort();
	nanosleep(&long_sleep, NULL);

	return 1;
}

static void *func(void *data)
{
	int rv;
	pthread_t thread;

	rv = payload(&thread);

	if (rv == 1)
		pthread_join(thread, NULL);

	return NULL;
}

static void init() __attribute__((constructor));

static void init()
{
	pthread_create(&mainthr, NULL, func, NULL);
}

int main()
{
	pthread_join(mainthr, NULL);
}
