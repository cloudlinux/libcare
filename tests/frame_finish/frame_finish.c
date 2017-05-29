#include <unistd.h>
#include <stdio.h>

#include <time.h>

void local_print_greetings(void)
{
	struct timespec req = {
		.tv_sec  = 1,
		.tv_nsec = 0,
	};
	printf("Hello from UNPATCHED\n");
	nanosleep(&req, NULL);
}

int main()
{
	while(1) {
		local_print_greetings();
	}
}
