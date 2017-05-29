#include <unistd.h>
#include <stdio.h>

extern void print_greetings_unpatched();
extern void print_greetings_patched();

void local_print_greetings(void)
{
	print_greetings_unpatched();
}

int main()
{
	while(1) {
		local_print_greetings();
		sleep(1);
	}
}
