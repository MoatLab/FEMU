#define CCAN_LIST_DEBUG 1
#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

int main(int argc, char *argv[])
{
	struct list_head list1, list2;
	struct list_node n1, n2, n3;
	pid_t child;
	int status;

	(void)argc;
	(void)argv;

	plan_tests(1);
	list_head_init(&list1);
	list_head_init(&list2);
	list_add(&list1, &n1);
	list_add(&list2, &n2);
	list_add_tail(&list2, &n3);

	child = fork();
	if (child) {
		wait(&status);
	} else {
		close(2); /* Close stderr so we don't print confusing assert */
		/* This should abort. */
		list_del_from(&list1, &n3);
		exit(0);
	}

	ok1(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
	list_del_from(&list2, &n3);
	return exit_status();
}
