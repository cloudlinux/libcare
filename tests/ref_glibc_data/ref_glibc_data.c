#include <unistd.h>
#include <stdio.h>

void local_print_greetings(void)
{
	printf("Hello from UNPATCHED\n");
}

int main()
{
	while(1) {
		local_print_greetings();
		sleep(1);
	}
}
