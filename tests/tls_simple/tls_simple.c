
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int *p;
int __thread v;

void print_greetings(void)
{
	printf("TLS UNPATCHED\n");
}

int main()
{
	v = 0xDEADBEAF;
	p = &v;

	while (1) {
		print_greetings();
		sleep(1);
	}
	return 0;
}
