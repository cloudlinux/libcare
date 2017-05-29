#include <stdio.h>
#include <unistd.h>

void print_greetings_patched(void)
{
	printf("Hello. This a PATCHED version!\n");
}

void print_greetings(void)
{
	printf("Hello. This is an UNPATCHED version!\n");
}

void do_work2() {
	while (1) {
		print_greetings();
		sleep(1);
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
