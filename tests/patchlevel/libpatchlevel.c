#include <stdio.h>

static const char *msg = "Hello from %s shared library\n";
void print_greetings(void)
{
	printf(msg, "UNPATCHED");
}
