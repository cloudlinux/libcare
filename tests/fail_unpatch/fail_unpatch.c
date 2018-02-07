#include <stdio.h>
#include <unistd.h>

void print_greetings_patched(void)
{
	while (1) {
		printf("Hello. This a PATCHED version!\n");
		sleep(1);
	}
}

void print_greetings(void)
{
	printf("Hello. This is an UNPATCHED version!\n");
}

void do_work() {
	while (1) {
		print_greetings();
		sleep(1);
	}
}

int main()
{
	do_work();

	return 0;
}
