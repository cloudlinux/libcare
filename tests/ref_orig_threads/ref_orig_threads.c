#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

void print_patch(void)
{
	printf("Hello from thread2 (PATCHED)\n");
}

void print_greetings1(void)
{
	printf("Hello from thread1 (UNPATCHED)\n");
}

void print_greetings2(void)
{
	printf("Hello from thread2 (UNPATCHED)\n");
}

void *thread1_func(void *unused)
{
	while (1) {
		print_greetings1();
		sleep(1);
	}
}

void *thread2_func(void *unused)
{
	while (1) {
		print_greetings2();
		sleep(1);
	}
}

int main()
{
	pthread_t thrs[3];
	pthread_create(&thrs[0], NULL, thread1_func, NULL);
	pthread_create(&thrs[1], NULL, thread2_func, NULL);
	pthread_create(&thrs[2], NULL, thread2_func, NULL);

	pthread_join(thrs[0], NULL);
	pthread_join(thrs[1], NULL);
	pthread_join(thrs[2], NULL);

	return 0;
}
