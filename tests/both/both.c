#include <unistd.h>
#include <stdio.h>

extern void print_greetings(void);

void local_print_greetings(void)
{
	print_greetings();
}

int main()
{
	while(1) {
		local_print_greetings();
		sleep(1);
	}
}
