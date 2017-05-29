#include <stdio.h>

static __thread int tls_abc = 10;

void print_second_greetings(void)
{
	tls_abc = 10;
	printf("Hello from UNPATCHED shared library\n");
}

void print_third_greetings(void)
{
	printf("Hello from PATCHED shared library!\n");
}

void print_greetings(void)
{
	print_second_greetings();
}
