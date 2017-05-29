#include <stdio.h>

void print_second_greetings(void)
{
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
