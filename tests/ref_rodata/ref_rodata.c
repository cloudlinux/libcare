#include <stdio.h>
#include <unistd.h>

static char *msg = "UNPATCHED binary!!!";

char *get_msg(void)
{
	return msg;
}

void print_greetings(void)
{
	printf("Hello. This is a '%s'\n", get_msg());
}

int main()
{
	while (1) {
		print_greetings();
		sleep(1);
	}

	return 0;
}
