
#define	_GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <dlfcn.h>

static void init_sleeper(void) __attribute__((constructor));

#define NSEC_TO_SEC	1000000000
#define DENOMINATOR	NSEC_TO_SEC

static uint64_t mult = NSEC_TO_SEC / 10;
int (*real_nanosleep)(const struct timespec *req, struct timespec *rem);

void init_sleeper(void)
{
	const char *mult_str = getenv("SLEEP_MULT");
	if (mult_str) {
		uint64_t newmult;
		newmult = atol(mult_str);
		mult = newmult < (DENOMINATOR / 1000) ? mult : newmult;
	}

	real_nanosleep = dlsym(RTLD_NEXT, "nanosleep");
}

unsigned int sleep(unsigned int t)
{
	struct timespec ts = {
		.tv_sec = t * mult / DENOMINATOR,
		.tv_nsec = t * mult % DENOMINATOR
	};

	real_nanosleep(&ts, NULL);
	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	uint64_t tv_sec = req->tv_sec * mult / DENOMINATOR +
			  req->tv_nsec * mult / NSEC_TO_SEC / DENOMINATOR;
	uint64_t tv_nsec = req->tv_sec * NSEC_TO_SEC / DENOMINATOR * mult +
			   req->tv_nsec * mult / DENOMINATOR;
	const struct timespec nreq = {
		.tv_sec = tv_sec,
		.tv_nsec = tv_nsec % NSEC_TO_SEC,
	};

	return real_nanosleep(&nreq, rem);
}
