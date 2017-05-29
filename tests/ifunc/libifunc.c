#include <stdio.h>

void print_greetings_unpatched()
{
	printf("Resolved IFUNC to UNPATCHED\n");
}

void _print_greetings_patched()
{
	printf("Resolved IFUNC to PATCHED\n");
}

static void (*resolve_print_greetings (void))(void)
{
	return (void *)_print_greetings_patched;
}

void print_greetings_patched(int)
	__attribute__ ((ifunc ("resolve_print_greetings")));
