/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Operating System Interface
 *
 * This provides access to useful OS routines for the sandbox architecture.
 * They are kept in a separate file so we can include system headers.
 *
 * Copyright (c) 2011 The Chromium OS Authors.
 */

#ifndef __OS_H__
#define __OS_H__

#include <linux/types.h>

struct rtc_time;
struct sandbox_state;

/**
 * Access to the OS read() system call
 *
 * @fd:		File descriptor as returned by os_open()
 * @buf:	Buffer to place data
 * @count:	Number of bytes to read
 * Return:	number of bytes read, or -1 on error
 */
ssize_t os_read(int fd, void *buf, size_t count);

/**
 * Access to the OS write() system call
 *
 * @fd:		File descriptor as returned by os_open()
 * @buf:	Buffer containing data to write
 * @count:	Number of bytes to write
 * Return:	number of bytes written, or -1 on error
 */
ssize_t os_write(int fd, const void *buf, size_t count);

/**
 * Access to the OS lseek() system call
 *
 * @fd:		File descriptor as returned by os_open()
 * @offset:	File offset (based on whence)
 * @whence:	Position offset is relative to (see below)
 * Return:	new file offset
 */
off_t os_lseek(int fd, off_t offset, int whence);

/* Defines for "whence" in os_lseek() */
#define OS_SEEK_SET	0
#define OS_SEEK_CUR	1
#define OS_SEEK_END	2

/**
 * Access to the OS open() system call
 *
 * @pathname:	Pathname of file to open
 * @flags:	Flags, like OS_O_RDONLY, OS_O_RDWR
 * Return:	file descriptor, or -1 on error
 */
int os_open(const char *pathname, int flags);

#define OS_O_RDONLY	0
#define OS_O_WRONLY	1
#define OS_O_RDWR	2
#define OS_O_MASK	3	/* Mask for read/write flags */
#define OS_O_CREAT	0100
#define OS_O_TRUNC	01000

/**
 * os_close() - access to the OS close() system call
 *
 * @fd:		File descriptor to close
 * Return:	0 on success, -1 on error
 */
int os_close(int fd);

/**
 * os_unlink() - access to the OS unlink() system call
 *
 * @pathname:	Path of file to delete
 * Return:	0 for success, other for error
 */
int os_unlink(const char *pathname);

/**
 * os_exit() - access to the OS exit() system call
 *
 * This exits with the supplied return code, which should be 0 to indicate
 * success.
 *
 * @exit_code:	exit code for U-Boot
 */
void os_exit(int exit_code) __attribute__((noreturn));

/**
 * os_tty_raw() - put tty into raw mode to mimic serial console better
 *
 * @fd:		File descriptor of stdin (normally 0)
 * @allow_sigs:	Allow Ctrl-C, Ctrl-Z to generate signals rather than
 *		be handled by U-Boot
 */
void os_tty_raw(int fd, bool allow_sigs);

/**
 * os_fs_restore() - restore the tty to its original mode
 *
 * Call this to restore the original terminal mode, after it has been changed
 * by os_tty_raw(). This is an internal function.
 */
void os_fd_restore(void);

/**
 * os_malloc() - aquires some memory from the underlying os.
 *
 * @length:	Number of bytes to be allocated
 * Return:	Pointer to length bytes or NULL if @length is 0 or on error
 */
void *os_malloc(size_t length);

/**
 * os_free() - free memory previous allocated with os_malloc()
 *
 * This returns the memory to the OS.
 *
 * @ptr:	Pointer to memory block to free. If this is NULL then this
 *		function does nothing
 */
void os_free(void *ptr);

/**
 * os_realloc() - reallocate memory
 *
 * This follows the semantics of realloc(), so can perform an os_malloc() or
 * os_free() depending on @ptr and @length.
 *
 * @ptr:	pointer to previously allocated memory of NULL
 * @length:	number of bytes to allocate
 * Return:	pointer to reallocated memory or NULL if @length is 0
 */
void *os_realloc(void *ptr, size_t length);

/**
 * os_usleep() - access to the usleep function of the os
 *
 * @usec:	time to sleep in micro seconds
 */
void os_usleep(unsigned long usec);

/**
 * Gets a monotonic increasing number of nano seconds from the OS
 *
 * Return:	a monotonic increasing time scaled in nano seconds
 */
uint64_t os_get_nsec(void);

/**
 * Parse arguments and update sandbox state.
 *
 * @state:	sandbox state to update
 * @argc:	argument count
 * @argv:	argument vector
 * Return:
 * *  0 if ok, and program should continue
 * *  1 if ok, but program should stop
 * * -1 on error: program should terminate
 */
int os_parse_args(struct sandbox_state *state, int argc, char *argv[]);

/*
 * enum os_dirent_t - type of directory entry
 *
 * Types of directory entry that we support. See also os_dirent_typename in
 * the C file.
 */
enum os_dirent_t {
	/**
	 * @OS_FILET_REG:	regular file
	 */
	OS_FILET_REG,
	/**
	 * @OS_FILET_LNK:	symbolic link
	 */
	OS_FILET_LNK,
	/**
	 * @OS_FILET_DIR:	directory
	 */
	OS_FILET_DIR,
	/**
	 * @OS_FILET_UNKNOWN:	something else
	 */
	OS_FILET_UNKNOWN,
	/**
	 * @OS_FILET_COUNT:	number of directory entry types
	 */
	OS_FILET_COUNT,
};

/**
 * struct os_dirent_node - directory node
 *
 * A directory entry node, containing information about a single dirent
 *
 */
struct os_dirent_node {
	/**
	 * @next:	pointer to next node, or NULL
	 */
	struct os_dirent_node *next;
	/**
	 * @size:	size of file in bytes
	 */
	ulong size;
	/**
	 * @type:	type of entry
	 */
	enum os_dirent_t type;
	/**
	 * @name:	name of entry
	 */
	char name[0];
};

/**
 * os_dirent_ls() - get a directory listing
 *
 * This allocates and returns a linked list containing the directory listing.
 *
 * @dirname:	directory to examine
 * @headp:	on return pointer to head of linked list, or NULL if none
 * Return:	0 if ok, -ve on error
 */
int os_dirent_ls(const char *dirname, struct os_dirent_node **headp);

/**
 * os_dirent_free() - free directory list
 *
 * This frees a linked list containing a directory listing.
 *
 * @node:	pointer to head of linked list
 */
void os_dirent_free(struct os_dirent_node *node);

/**
 * os_dirent_get_typename() - get the name of a directory entry type
 *
 * @type:	type to check
 * Return:
 * string containing the name of that type,
 * or "???" if none/invalid
 */
const char *os_dirent_get_typename(enum os_dirent_t type);

/**
 * os_get_filesize() - get the size of a file
 *
 * @fname:	filename to check
 * @size:	size of file is returned if no error
 * Return:	0 on success or -1 if an error ocurred
 */
int os_get_filesize(const char *fname, loff_t *size);

/**
 * os_putc() - write a character to the controlling OS terminal
 *
 * This bypasses the U-Boot console support and writes directly to the OS
 * stdout file descriptor.
 *
 * @ch:		haracter to write
 */
void os_putc(int ch);

/**
 * os_puts() - write a string to the controlling OS terminal
 *
 * This bypasses the U-Boot console support and writes directly to the OS
 * stdout file descriptor.
 *
 * @str:	string to write (note that \n is not appended)
 */
void os_puts(const char *str);

/**
 * os_write_ram_buf() - write the sandbox RAM buffer to a existing file
 *
 * @fname:	filename to write memory to (simple binary format)
 * Return:	0 if OK, -ve on error
 */
int os_write_ram_buf(const char *fname);

/**
 * os_read_ram_buf() - read the sandbox RAM buffer from an existing file
 *
 * @fname:	filename containing memory (simple binary format)
 * Return:	0 if OK, -ve on error
 */
int os_read_ram_buf(const char *fname);

/**
 * os_jump_to_image() - jump to a new executable image
 *
 * This uses exec() to run a new executable image, after putting it in a
 * temporary file. The same arguments and environment are passed to this
 * new image, with the addition of:
 *
 *	-j <filename>	Specifies the filename the image was written to. The
 *			calling image may want to delete this at some point.
 *	-m <filename>	Specifies the file containing the sandbox memory
 *			(ram_buf) from this image, so that the new image can
 *			have access to this. It also means that the original
 *			memory filename passed to U-Boot will be left intact.
 *
 * @dest:	buffer containing executable image
 * @size:	size of buffer
 * Return:	0 if OK, -ve on error
 */
int os_jump_to_image(const void *dest, int size);

/**
 * os_find_u_boot() - determine the path to U-Boot proper
 *
 * This function is intended to be called from within sandbox SPL. It uses
 * a few heuristics to find U-Boot proper. Normally it is either in the same
 * directory, or the directory above (since u-boot-spl is normally in an
 * spl/ subdirectory when built).
 *
 * @fname:	place to put full path to U-Boot
 * @maxlen:	maximum size of @fname
 * @use_img:	select the 'u-boot.img' file instead of the 'u-boot' ELF file
 * Return:	0 if OK, -NOSPC if the filename is too large, -ENOENT if not found
 */
int os_find_u_boot(char *fname, int maxlen, bool use_img);

/**
 * os_spl_to_uboot() - Run U-Boot proper
 *
 * When called from SPL, this runs U-Boot proper. The filename is obtained by
 * calling os_find_u_boot().
 *
 * @fname:	full pathname to U-Boot executable
 * Return:	0 if OK, -ve on error
 */
int os_spl_to_uboot(const char *fname);

/**
 * os_localtime() - read the current system time
 *
 * This reads the current Local Time and places it into the provided
 * structure.
 *
 * @rt:		place to put system time
 */
void os_localtime(struct rtc_time *rt);

/**
 * os_abort() - raise SIGABRT to exit sandbox (e.g. to debugger)
 */
void os_abort(void) __attribute__((noreturn));

/**
 * os_mprotect_allow() - Remove write-protection on a region of memory
 *
 * The start and length will be page-aligned before use.
 *
 * @start:	Region start
 * @len:	Region length in bytes
 * Return:	0 if OK, -1 on error from mprotect()
 */
int os_mprotect_allow(void *start, size_t len);

/**
 * os_write_file() - write a file to the host filesystem
 *
 * This can be useful when debugging for writing data out of sandbox for
 * inspection by external tools.
 *
 * @name:	File path to write to
 * @buf:	Data to write
 * @size:	Size of data to write
 * Return:	0 if OK, -ve on error
 */
int os_write_file(const char *name, const void *buf, int size);

/**
 * os_read_file() - Read a file from the host filesystem
 *
 * This can be useful when reading test data into sandbox for use by test
 * routines. The data is allocated using os_malloc() and should be freed by
 * the caller.
 *
 * @name:	File path to read from
 * @bufp:	Returns buffer containing data read
 * @sizep:	Returns size of data
 * Return:	0 if OK, -ve on error
 */
int os_read_file(const char *name, void **bufp, int *sizep);

/*
 * os_find_text_base() - Find the text section in this running process
 *
 * This tries to find the address of the text section in this running process.
 * It can be useful to map the address of functions to the address listed in
 * the u-boot.map file.
 *
 * Return:	address if found, else NULL
 */
void *os_find_text_base(void);

/**
 * os_relaunch() - restart the sandbox
 *
 * This functions is used to implement the cold reboot of the sand box.
 * @argv\[0] specifies the binary that is started while the calling process
 * stops immediately. If the new binary cannot be started, the process is
 * terminated and 1 is set as shell return code.
 *
 * The PID of the process stays the same. All file descriptors that have not
 * been opened with O_CLOEXEC stay open including stdin, stdout, stderr.
 *
 * @argv:	NULL terminated list of command line parameters
 */
void os_relaunch(char *argv[]);

/**
 * os_setup_signal_handlers() - setup signal handlers
 *
 * Install signal handlers for SIGBUS and SIGSEGV.
 *
 * Return:	0 for success
 */
int os_setup_signal_handlers(void);

/**
 * os_signal_action() - handle a signal
 *
 * @sig:	signal
 * @pc:		program counter
 */
void os_signal_action(int sig, unsigned long pc);

/**
 * os_get_time_offset() - get time offset
 *
 * Get the time offset from environment variable UBOOT_SB_TIME_OFFSET.
 *
 * Return:	offset in seconds
 */
long os_get_time_offset(void);

/**
 * os_set_time_offset() - set time offset
 *
 * Save the time offset in environment variable UBOOT_SB_TIME_OFFSET.
 *
 * @offset:	offset in seconds
 */
void os_set_time_offset(long offset);

#endif
