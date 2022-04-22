/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "exec_parser.h"

static so_exec_t *exec;

static struct sigaction old_action;
static int executable_fd;
static int page_size;

int min(int a, int b) {
	return (a < b) ? a : b;
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	char *addr;
	int rc;

	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	uintptr_t fault_address = (uintptr_t) info->si_addr;
	so_seg_t *executable_segments = exec->segments;
	int no_executable_segments = exec->segments_no;
	int it = 0;

	// iterate through the segments and check the bounds
	// for each if they include the address that caused the seg fault
	for (it = 0; it < no_executable_segments; it++) {
		if ((executable_segments[it].vaddr <= fault_address) &&
		 (executable_segments[it].vaddr + executable_segments[it].mem_size > fault_address))
			break;
	}

	// address that caused SIGSEV is not
	// in any known segment
	if (it == no_executable_segments) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	// get page index in the segment
	int page_idx = (fault_address - executable_segments[it].vaddr) / page_size;

	// check if page is already mapped
	if (((int *)executable_segments[it].data)[page_idx] == 1) {
		// invalid access to memory
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	int flags = MAP_PRIVATE | MAP_FIXED;

	// check if crt page exceeds file size
	// if so, don't read anything from file
	if (page_idx * page_size >
			executable_segments[it].file_size)
		flags |= MAP_ANONYMOUS;

	// fault address is in segment[it] at page @page_idx
	addr = mmap((void *)executable_segments[it].vaddr + page_idx * page_size, page_size,
			PROT_READ | PROT_EXEC | PROT_WRITE, flags,
			executable_fd, executable_segments[it].offset + page_idx * page_size);

	if (addr == MAP_FAILED) {
		printf("Allocation of page %d in segment: %d failed\n", page_idx, it);
		printf("errno: %d\n", errno);
		return;
	}

	((int *) executable_segments[it].data)[page_idx] = 1;

	// check if there is space left from physical alloc
	// to virtual alloc
	int diff_virt_physical = (page_idx + 1) * page_size - executable_segments[it].file_size;

	if (diff_virt_physical > 0)
		memset(addr + page_size - diff_virt_physical, 0, diff_virt_physical);

	// restore the permissions for the current segment
	rc = mprotect(addr, page_size, executable_segments[it].perm);
	if (rc == -1) {
		printf("failed mprotect\n");
		return;
	}
}

int so_init_loader(void)
{
	struct sigaction action;
	int rc;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
	if (rc == -1) {
		fprintf(stderr, "sigaction failed\n");
		return rc;
	}

	return -1;
}

int so_execute(char *path, char *argv[])
{
	executable_fd = open(path, O_RDONLY);
	if (executable_fd == -1) {
		printf("Failed to open file named %s\n", path);
		return errno;
	}

	page_size = getpagesize();
	exec = so_parse_exec(path);

	if (!exec)
		return -1;

	for (int i = 0; i < exec->segments_no; i++) {
		int no_pages = exec->segments[i].mem_size / page_size;

		if (exec->segments[i].mem_size % page_size != 0)
			no_pages++;

		// data will now be an array holding information
		// about each page (if 0, then page is not allocated,
		// if 1, then pae is allocated)
		exec->segments[i].data = calloc(no_pages, sizeof(int));
		if (exec->segments[i].data == NULL) {
			printf("Failed to alloc data about pages\n");
			return errno;
		}
	}
	so_start_exec(exec, argv);

	return -1;
}
