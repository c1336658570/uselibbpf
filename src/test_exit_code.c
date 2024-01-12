// gcc test_exit_code.c -o test_exit_code -g -gdwarf-2 -g3
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
	int count = 1;
	int pid;
	int status;

	pid = fork();
	printf("pid=%d\n", pid);

	if (pid < 0) {
		perror("fork error : ");
	} else if (pid == 0) {
		printf("This is son, his count is: %d (%p). and his pid is: %d\n", ++count, &count, getpid());
		// sleep(3);
		int *a = 0;
		// *a = 3;
		exit(9999);		// 测试进程退出码
	} else {
		pid = wait(&status);

		printf("This is father, his count is: %d (%p), his pid is: %d, son exit status: %d[%08x]\n", count, &count, getpid(), status, status);
		exit(9999);
	}

	return 0;
}
