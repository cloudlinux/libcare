#include <unistd.h>

extern void print_greetings(void);

int main()
{
	while(1) {
		print_greetings();
		sleep(1);
	}
}
