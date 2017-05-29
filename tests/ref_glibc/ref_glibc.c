#include <stdio.h>
#include <unistd.h>

void print_greetings(void)
{
	printf("Hello. This is an UNPATCHED version!\n");
}

int main()
{
	while (1) {
		print_greetings();
		sleep(1);
	}

	return 0;
}
