/*
 * QEMU I/O channel file test
 *
 * Copyright (c) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "io/channel-file.h"
#include "io/channel-util.h"
#include "io-channel-helpers.h"
#include "qapi/error.h"
#include "qemu/module.h"

#define TEST_FILE "tests/test-io-channel-file.txt"
#define TEST_MASK 0600

/*
 * On Windows the stat() function in the C library checks only
 * the FAT-style READONLY attribute and does not look at the ACL at all.
 */
#ifdef _WIN32
#define TEST_MASK_EXPECT 0700
#else
#define TEST_MASK_EXPECT 0777
#endif

static void test_io_channel_file_helper(int flags)
{
    QIOChannel *src, *dst;
    QIOChannelTest *test;
    struct stat st;
    mode_t mask;
    int ret;

    unlink(TEST_FILE);
    src = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          flags, TEST_MASK,
                          &error_abort));
    dst = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          O_RDONLY | O_BINARY, 0,
                          &error_abort));

    test = qio_channel_test_new();
    qio_channel_test_run_writer(test, src);
    qio_channel_test_run_reader(test, dst);
    qio_channel_test_validate(test);

    /* Check that the requested mode took effect. */
    mask = umask(0);
    umask(mask);
    ret = stat(TEST_FILE, &st);
    g_assert_cmpint(ret, >, -1);
    g_assert_cmpuint(TEST_MASK & ~mask, ==, st.st_mode & TEST_MASK_EXPECT);

    unlink(TEST_FILE);
    object_unref(OBJECT(src));
    object_unref(OBJECT(dst));
}

static void test_io_channel_file(void)
{
    test_io_channel_file_helper(O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
}

static void test_io_channel_file_rdwr(void)
{
    test_io_channel_file_helper(O_RDWR | O_CREAT | O_TRUNC | O_BINARY);
}

static void test_io_channel_fd(void)
{
    QIOChannel *ioc;
    int fd = -1;

    fd = open(TEST_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    g_assert_cmpint(fd, >, -1);

    ioc = qio_channel_new_fd(fd, &error_abort);

    g_assert_cmpstr(object_get_typename(OBJECT(ioc)),
                    ==,
                    TYPE_QIO_CHANNEL_FILE);

    unlink(TEST_FILE);
    object_unref(OBJECT(ioc));
}


#ifdef CONFIG_PREADV
static void test_io_channel_pread_all(void)
{
    QIOChannel *ioc;
    char write_buf[] = "Hello World, pread_all";
    char read_buf[sizeof(write_buf)] = {0};
    int ret;

    unlink(TEST_FILE);
    ioc = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                          TEST_MASK,
                          &error_abort));

    ret = qio_channel_pwrite_all(ioc, write_buf, sizeof(write_buf),
                                 0, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    /* Read back at offset 0 */
    ret = qio_channel_pread_all(ioc, read_buf, sizeof(read_buf),
                                0, &error_abort);
    g_assert_cmpint(ret, ==, 0);
    g_assert_cmpmem(write_buf, sizeof(write_buf),
                    read_buf, sizeof(read_buf));

    /* Read at a non-zero offset */
    memset(read_buf, 0, sizeof(read_buf));
    ret = qio_channel_pread_all(ioc, read_buf, sizeof(write_buf) - 7,
                                7, &error_abort);
    g_assert_cmpint(ret, ==, 0);
    g_assert_cmpmem(write_buf + 7, sizeof(write_buf) - 7,
                    read_buf, sizeof(write_buf) - 7);

    unlink(TEST_FILE);
    object_unref(OBJECT(ioc));
}

static void test_io_channel_preadv_all(void)
{
    QIOChannel *ioc;
    char write_buf[256];
    char read_buf[256] = {0};
    struct iovec write_iov[2];
    struct iovec read_iov[2];
    int ret;
    size_t i;

    for (i = 0; i < sizeof(write_buf); i++) {
        write_buf[i] = i & 0xff;
    }

    unlink(TEST_FILE);
    ioc = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                          TEST_MASK,
                          &error_abort));

    /* Write using pwritev_all with 2 iovecs */
    write_iov[0].iov_base = write_buf;
    write_iov[0].iov_len = 128;
    write_iov[1].iov_base = write_buf + 128;
    write_iov[1].iov_len = 128;
    ret = qio_channel_pwritev_all(ioc, write_iov, 2, 0, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    /* Read back using preadv_all with 2 iovecs */
    read_iov[0].iov_base = read_buf;
    read_iov[0].iov_len = 128;
    read_iov[1].iov_base = read_buf + 128;
    read_iov[1].iov_len = 128;
    ret = qio_channel_preadv_all(ioc, read_iov, 2, 0, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    g_assert_cmpmem(write_buf, sizeof(write_buf),
                    read_buf, sizeof(read_buf));

    /* Read at non-zero offset with preadv_all */
    memset(read_buf, 0, sizeof(read_buf));
    read_iov[0].iov_base = read_buf;
    read_iov[0].iov_len = 64;
    read_iov[1].iov_base = read_buf + 64;
    read_iov[1].iov_len = 64;
    ret = qio_channel_preadv_all(ioc, read_iov, 2, 128, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    g_assert_cmpmem(write_buf + 128, 128,
                    read_buf, 128);

    unlink(TEST_FILE);
    object_unref(OBJECT(ioc));
}

static void test_io_channel_preadv_all_eof(void)
{
    QIOChannel *ioc;
    char write_buf[] = "Hello World, preadv_all_eof";
    char read_buf[sizeof(write_buf)] = {0};
    struct iovec iov;
    int ret;
    Error *err = NULL;

    unlink(TEST_FILE);
    ioc = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                          TEST_MASK,
                          &error_abort));

    ret = qio_channel_pwrite_all(ioc, write_buf, sizeof(write_buf),
                                 0, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    /* Full read succeeds: should return 1 */
    iov.iov_base = read_buf;
    iov.iov_len = sizeof(read_buf);
    ret = qio_channel_preadv_all_eof(ioc, &iov, 1, 0, &error_abort);
    g_assert_cmpint(ret, ==, 1);
    g_assert_cmpmem(write_buf, sizeof(write_buf),
                    read_buf, sizeof(read_buf));

    /* Clean EOF: offset at file end, should return 0 */
    iov.iov_base = read_buf;
    iov.iov_len = 1;
    ret = qio_channel_preadv_all_eof(ioc, &iov, 1,
                                     sizeof(write_buf), &err);
    g_assert_cmpint(ret, ==, 0);
    g_assert_null(err);

    /* Partial EOF: start before end, request extends past */
    iov.iov_base = read_buf;
    iov.iov_len = 8;
    ret = qio_channel_preadv_all_eof(ioc, &iov, 1,
                                     sizeof(write_buf) - 4, &err);
    g_assert_cmpint(ret, ==, -1);
    g_assert_nonnull(err);
    error_free(err);
    err = NULL;

    /* Strict wrapper (preadv_all) treats clean EOF as error */
    iov.iov_base = read_buf;
    iov.iov_len = 1;
    ret = qio_channel_preadv_all(ioc, &iov, 1,
                                 sizeof(write_buf), &err);
    g_assert_cmpint(ret, ==, -1);
    g_assert_nonnull(err);
    error_free(err);

    unlink(TEST_FILE);
    object_unref(OBJECT(ioc));
}

static void test_io_channel_pread_all_eof(void)
{
    QIOChannel *ioc;
    char write_buf[] = "Hello World, pread_all_eof";
    char read_buf[sizeof(write_buf)] = {0};
    int ret;
    Error *err = NULL;

    unlink(TEST_FILE);
    ioc = QIO_CHANNEL(qio_channel_file_new_path(
                          TEST_FILE,
                          O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                          TEST_MASK,
                          &error_abort));

    ret = qio_channel_pwrite_all(ioc, write_buf, sizeof(write_buf),
                                 0, &error_abort);
    g_assert_cmpint(ret, ==, 0);

    /* Full read succeeds: should return 1 */
    ret = qio_channel_pread_all_eof(ioc, read_buf, sizeof(read_buf),
                                    0, &error_abort);
    g_assert_cmpint(ret, ==, 1);
    g_assert_cmpmem(write_buf, sizeof(write_buf),
                    read_buf, sizeof(read_buf));

    /* Clean EOF: should return 0 */
    ret = qio_channel_pread_all_eof(ioc, read_buf, 1,
                                    sizeof(write_buf), &err);
    g_assert_cmpint(ret, ==, 0);
    g_assert_null(err);

    /* Partial EOF: should return -1 */
    ret = qio_channel_pread_all_eof(ioc, read_buf, 8,
                                    sizeof(write_buf) - 4, &err);
    g_assert_cmpint(ret, ==, -1);
    g_assert_nonnull(err);
    error_free(err);

    unlink(TEST_FILE);
    object_unref(OBJECT(ioc));
}
#endif /* CONFIG_PREADV */

#ifndef _WIN32
static void test_io_channel_pipe(bool async)
{
    QIOChannel *src, *dst;
    QIOChannelTest *test;
    int fd[2];

    if (!g_unix_open_pipe(fd, FD_CLOEXEC, NULL)) {
        perror("pipe");
        abort();
    }

    src = QIO_CHANNEL(qio_channel_file_new_fd(fd[1]));
    dst = QIO_CHANNEL(qio_channel_file_new_fd(fd[0]));

    test = qio_channel_test_new();
    qio_channel_test_run_threads(test, async, src, dst);
    qio_channel_test_validate(test);

    object_unref(OBJECT(src));
    object_unref(OBJECT(dst));
}


static void test_io_channel_pipe_async(void)
{
    test_io_channel_pipe(true);
}

static void test_io_channel_pipe_sync(void)
{
    test_io_channel_pipe(false);
}
#endif /* ! _WIN32 */


int main(int argc, char **argv)
{
    module_call_init(MODULE_INIT_QOM);

    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/io/channel/file", test_io_channel_file);
    g_test_add_func("/io/channel/file/rdwr", test_io_channel_file_rdwr);
    g_test_add_func("/io/channel/file/fd", test_io_channel_fd);
#ifdef CONFIG_PREADV
    g_test_add_func("/io/channel/file/pread-all",
                    test_io_channel_pread_all);
    g_test_add_func("/io/channel/file/preadv-all",
                    test_io_channel_preadv_all);
    g_test_add_func("/io/channel/file/preadv-all-eof",
                    test_io_channel_preadv_all_eof);
    g_test_add_func("/io/channel/file/pread-all-eof",
                    test_io_channel_pread_all_eof);
#endif
#ifndef _WIN32
    g_test_add_func("/io/channel/pipe/sync", test_io_channel_pipe_sync);
    g_test_add_func("/io/channel/pipe/async", test_io_channel_pipe_async);
#endif
    return g_test_run();
}
