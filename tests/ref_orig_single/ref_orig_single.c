#include <stdio.h>
#include <unistd.h>

void print_second_greetings(void)
{
	printf("Hello from UNPATCHED binary\n");
}

void print_third_greetings(void)
{
	printf("Hello from PATCHED binary!\n");
}

void print_greetings(void)
{
	print_second_greetings();
}

int main()
{
	while (1) {
		print_greetings();
		sleep(1);
	}

	return 0;
}
