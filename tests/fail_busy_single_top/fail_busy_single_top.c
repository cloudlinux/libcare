#include <stdio.h>
#include <unistd.h>
#include <limits.h>

void print_greetings_patched(void)
{
	printf("Hello. This a PATCHED version!\n");
}

void print_greetings(void)
{
	printf("Hello. This is an UNPATCHED version!\n");
}

void do_work2() {
	volatile int i = 0;
	while (1) {
		print_greetings();
		for (i = 0; i < INT_MAX / 50; i++)
			asm ("pause");
	}
}

void do_work() {
	do_work2();
}

int main()
{
	do_work();

	return 0;
}
