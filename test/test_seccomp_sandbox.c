/* test_seccomp_sandbox.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Seccomp coverage for wolfProvider SEED-SRC under OpenSSH's preauth sandbox.
 *
 * These are passing regression tests. The original bug held /dev/urandom as a
 * buffered stdio FILE*: OpenSSH's preauth seccomp filter does not allow
 * lseek(), so glibc stdio cleanup could kill the child with SIGSYS while
 * rewinding fread read-ahead. The SEED-SRC path now uses a raw /dev/urandom fd
 * (open/read/close, no stdio buffering), so libc exit performs no lseek(). The
 * tests here would catch a reintroduction of the buffered-stream SIGSYS bug.
 */

#include "unit.h"

#if defined(WP_TEST_SECCOMP_SANDBOX) && defined(WP_HAVE_SEED_SRC) && \
    defined(WP_HAVE_RANDOM)

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <endian.h>
#include <openssl/crypto.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfprovider/wp_wolfprov.h>

/* Check for seccomp support */
#ifdef __has_include
    #if __has_include(<linux/seccomp.h>) && __has_include(<linux/filter.h>)
        #define WP_HAVE_SECCOMP 1
    #endif
#else
    /* Fallback: assume available on Linux */
    #define WP_HAVE_SECCOMP 1
#endif

#ifdef WP_HAVE_SECCOMP

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <sys/syscall.h>

/* Determine the correct audit architecture. */
#if defined(__x86_64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
    /* Unsupported architecture - disable test. */
    #undef WP_HAVE_SECCOMP
#endif

#endif /* WP_HAVE_SECCOMP */

#ifdef WP_HAVE_SECCOMP

#ifdef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL_PROCESS
#else
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL
#endif

/* OpenSSH 9.9p1 sandbox-seccomp-filter.c preauth filter body. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ARG_LO_OFFSET  0
# define ARG_HI_OFFSET  sizeof(uint32_t)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ARG_LO_OFFSET  sizeof(uint32_t)
# define ARG_HI_OFFSET  0
#else
#error "Unknown endianness"
#endif

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 6), \
    /* load and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        ((_arg_val) & 0xFFFFFFFF), 0, 3), \
    /* load and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        (((uint32_t)((uint64_t)(_arg_val) >> 32)) & 0xFFFFFFFF), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))
/* Allow if syscall argument contains only values in mask */
#define SC_ALLOW_ARG_MASK(_nr, _arg_nr, _arg_mask) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
    /* load, mask and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 4), \
    /* load, mask and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
        ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))
/* Deny unless syscall argument contains only values in mask */
#define SC_DENY_UNLESS_ARG_MASK(_nr, _arg_nr, _arg_mask, _errno) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
    /* load, mask and test syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_LO_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~((_arg_mask) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3), \
    /* load, mask and test syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[(_arg_nr)]) + ARG_HI_OFFSET), \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
        ~(((uint32_t)((uint64_t)(_arg_mask) >> 32)) & 0xFFFFFFFF)), \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno)), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, nr))
/* Special handling for futex(2) that combines a bitmap and operation number */
#if defined(__NR_futex) || defined(__NR_futex_time64)
#define SC_FUTEX_MASK (FUTEX_PRIVATE_FLAG|FUTEX_CLOCK_REALTIME)
#define SC_ALLOW_FUTEX_OP(_nr, _op) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 8), \
    /* load syscall argument, low word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[1]) + ARG_LO_OFFSET), \
    /* mask off allowed bitmap values, low word */ \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, ~(SC_FUTEX_MASK & 0xFFFFFFFF)), \
    /* test operation number, low word */ \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ((_op) & 0xFFFFFFFF), 0, 4), \
    /* load syscall argument, high word */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
        offsetof(struct seccomp_data, args[1]) + ARG_HI_OFFSET), \
    /* mask off allowed bitmap values, high word */ \
    BPF_STMT(BPF_ALU+BPF_AND+BPF_K, \
        ~(((uint32_t)((uint64_t)SC_FUTEX_MASK >> 32)) & 0xFFFFFFFF)), \
    /* test operation number, high word */ \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, \
        (((uint32_t)((uint64_t)(_op) >> 32)) & 0xFFFFFFFF), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
    /* reload syscall number; all rules expect it in accumulator */ \
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr))

/* Use this for both __NR_futex and __NR_futex_time64 */
# define SC_FUTEX(_nr) \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT), \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAIT_BITSET), \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE), \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_WAKE_BITSET), \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_REQUEUE), \
    SC_ALLOW_FUTEX_OP(_nr, FUTEX_CMP_REQUEUE)
#endif /* __NR_futex || __NR_futex_time64 */

#if defined(__NR_mmap) || defined(__NR_mmap2)
# ifdef MAP_FIXED_NOREPLACE
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE
# else
#  define SC_MMAP_FLAGS MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED
# endif /* MAP_FIXED_NOREPLACE */
/* Use this for both __NR_mmap and __NR_mmap2 variants */
# define SC_MMAP(_nr) \
    SC_DENY_UNLESS_ARG_MASK(_nr, 3, SC_MMAP_FLAGS, EINVAL), \
    SC_ALLOW_ARG_MASK(_nr, 2, PROT_READ|PROT_WRITE|PROT_NONE)
#endif /* __NR_mmap || __NR_mmap2 */

/* Syscall filtering set for preauth. */
static const struct sock_filter preauth_insns[] = {
    /* Ensure the syscall arch convention is as expected. */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
    /* Load the syscall number for checking. */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS,
        offsetof(struct seccomp_data, nr)),

    /* Syscalls to non-fatally deny */
#ifdef __NR_lstat
    SC_DENY(__NR_lstat, EACCES),
#endif
#ifdef __NR_lstat64
    SC_DENY(__NR_lstat64, EACCES),
#endif
#ifdef __NR_fstat
    SC_DENY(__NR_fstat, EACCES),
#endif
#ifdef __NR_fstat64
    SC_DENY(__NR_fstat64, EACCES),
#endif
#ifdef __NR_fstatat64
    SC_DENY(__NR_fstatat64, EACCES),
#endif
#ifdef __NR_open
    SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
    SC_DENY(__NR_openat, EACCES),
#endif
#ifdef __NR_newfstatat
    SC_DENY(__NR_newfstatat, EACCES),
#endif
#ifdef __NR_stat
    SC_DENY(__NR_stat, EACCES),
#endif
#ifdef __NR_stat64
    SC_DENY(__NR_stat64, EACCES),
#endif
#ifdef __NR_shmget
    SC_DENY(__NR_shmget, EACCES),
#endif
#ifdef __NR_shmat
    SC_DENY(__NR_shmat, EACCES),
#endif
#ifdef __NR_shmdt
    SC_DENY(__NR_shmdt, EACCES),
#endif
#ifdef __NR_ipc
    SC_DENY(__NR_ipc, EACCES),
#endif
#ifdef __NR_statx
    SC_DENY(__NR_statx, EACCES),
#endif

    /* Syscalls to permit */
#ifdef __NR_brk
    SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_clock_gettime
    SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_clock_gettime64
    SC_ALLOW(__NR_clock_gettime64),
#endif
#ifdef __NR_close
    SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit
    SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_exit_group
    SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_futex
    SC_FUTEX(__NR_futex),
#endif
#ifdef __NR_futex_time64
    SC_FUTEX(__NR_futex_time64),
#endif
#ifdef __NR_geteuid
    SC_ALLOW(__NR_geteuid),
#endif
#ifdef __NR_geteuid32
    SC_ALLOW(__NR_geteuid32),
#endif
#ifdef __NR_getpgid
    SC_ALLOW(__NR_getpgid),
#endif
#ifdef __NR_getpid
    SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_getrandom
    SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_gettid
    SC_ALLOW(__NR_gettid),
#endif
#ifdef __NR_gettimeofday
    SC_ALLOW(__NR_gettimeofday),
#endif
#ifdef __NR_getuid
    SC_ALLOW(__NR_getuid),
#endif
#ifdef __NR_getuid32
    SC_ALLOW(__NR_getuid32),
#endif
#ifdef __NR_madvise
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_NORMAL),
# ifdef MADV_FREE
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_FREE),
# endif
# ifdef MADV_DONTNEED
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTNEED),
# endif
# ifdef MADV_DONTFORK
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTFORK),
# endif
# ifdef MADV_DONTDUMP
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_DONTDUMP),
# endif
# ifdef MADV_WIPEONFORK
    SC_ALLOW_ARG(__NR_madvise, 2, MADV_WIPEONFORK),
# endif
    SC_DENY(__NR_madvise, EINVAL),
#endif
#ifdef __NR_mmap
    SC_MMAP(__NR_mmap),
#endif
#ifdef __NR_mmap2
    SC_MMAP(__NR_mmap2),
#endif
#ifdef __NR_mprotect
    SC_ALLOW_ARG_MASK(__NR_mprotect, 2, PROT_READ|PROT_WRITE|PROT_NONE),
#endif
#ifdef __NR_mremap
    SC_ALLOW(__NR_mremap),
#endif
#ifdef __NR_munmap
    SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_nanosleep
    SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_clock_nanosleep
    SC_ALLOW(__NR_clock_nanosleep),
#endif
#ifdef __NR_clock_nanosleep_time64
    SC_ALLOW(__NR_clock_nanosleep_time64),
#endif
#ifdef __NR__newselect
    SC_ALLOW(__NR__newselect),
#endif
#ifdef __NR_ppoll
    SC_ALLOW(__NR_ppoll),
#endif
#ifdef __NR_ppoll_time64
    SC_ALLOW(__NR_ppoll_time64),
#endif
#ifdef __NR_poll
    SC_ALLOW(__NR_poll),
#endif
#ifdef __NR_pselect6
    SC_ALLOW(__NR_pselect6),
#endif
#ifdef __NR_pselect6_time64
    SC_ALLOW(__NR_pselect6_time64),
#endif
#ifdef __NR_read
    SC_ALLOW(__NR_read),
#endif
#ifdef __NR_rt_sigprocmask
    SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_select
    SC_ALLOW(__NR_select),
#endif
#ifdef __NR_shutdown
    SC_ALLOW(__NR_shutdown),
#endif
#ifdef __NR_sigprocmask
    SC_ALLOW(__NR_sigprocmask),
#endif
#ifdef __NR_time
    SC_ALLOW(__NR_time),
#endif
#ifdef __NR_write
    SC_ALLOW(__NR_write),
#endif
#ifdef __NR_writev
    SC_ALLOW(__NR_writev),
#endif
#ifdef __NR_socketcall
    SC_ALLOW_ARG(__NR_socketcall, 0, SYS_SHUTDOWN),
    SC_DENY(__NR_socketcall, EACCES),
#endif
#if defined(__NR_ioctl) && defined(__s390__)
    /* Allow ioctls for ICA crypto card on s390 */
    SC_ALLOW_ARG(__NR_ioctl, 1, Z90STAT_STATUS_MASK),
    SC_ALLOW_ARG(__NR_ioctl, 1, ICARSAMODEXPO),
    SC_ALLOW_ARG(__NR_ioctl, 1, ICARSACRT),
    SC_ALLOW_ARG(__NR_ioctl, 1, ZSECSENDCPRB),
    /* Allow ioctls for EP11 crypto card on s390 */
    SC_ALLOW_ARG(__NR_ioctl, 1, ZSENDEP11CPRB),
#endif
#if defined(__x86_64__) && defined(__ILP32__) && defined(__X32_SYSCALL_BIT)
    /*
     * On Linux x32, the clock_gettime VDSO falls back to the
     * x86-64 syscall under some circumstances, e.g.
     * https://bugs.debian.org/849923
     */
    SC_ALLOW(__NR_clock_gettime & ~__X32_SYSCALL_BIT),
#endif

    /* Default deny */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_FILTER_FAIL),
};

static const struct sock_fprog preauth_program = {
    .len = (unsigned short)(sizeof(preauth_insns) / sizeof(preauth_insns[0])),
    .filter = (struct sock_filter *)preauth_insns,
};

/*
 * Apply seccomp sandbox restrictions matching OpenSSH preauth behavior.
 * Returns 0 on success, -1 on failure.
 */
static int apply_seccomp_sandbox(void)
{
    /*
     * Set resource limits like OpenSSH does.
     * RLIMIT_NOFILE = 1 allows existing fds but prevents new ones.
     */
    struct rlimit rl_zero = {0, 0};
    struct rlimit rl_one = {1, 1};

    if (setrlimit(RLIMIT_FSIZE, &rl_zero) == -1) {
        PRINT_ERR_MSG("setrlimit(RLIMIT_FSIZE) failed: %s", strerror(errno));
        return -1;
    }

    if (setrlimit(RLIMIT_NOFILE, &rl_one) == -1) {
        PRINT_ERR_MSG("setrlimit(RLIMIT_NOFILE) failed: %s", strerror(errno));
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        PRINT_ERR_MSG("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &preauth_program) == -1) {
        PRINT_ERR_MSG("prctl(PR_SET_SECCOMP) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int load_provider_into_ctx(OSSL_LIB_CTX *ctx, const char *providerDir,
    const char *providerName, OSSL_PROVIDER **provider)
{
    int err = 0;

    if (OSSL_PROVIDER_set_default_search_path(ctx, providerDir) != 1) {
        PRINT_ERR_MSG("OSSL_PROVIDER_set_default_search_path failed: %s",
            providerDir);
        err = 1;
    }

    if (err == 0) {
        *provider = OSSL_PROVIDER_load(ctx, providerName);
        if (*provider == NULL) {
            PRINT_ERR_MSG("Failed to load provider %s from %s", providerName,
                providerDir);
            err = 1;
        }
    }

    return err;
}

/* Exit codes reported by seccomp helper child processes. */
#define WP_SECCOMP_CHILD_FILTER_ERR       4
#define WP_SECCOMP_CHILD_OPENSSL_RAND_ERR 20
#define WP_SECCOMP_CHILD_WC_INIT_ERR      21
#define WP_SECCOMP_CHILD_WC_RAND_ERR      22

static int child_exit_under_filter(void)
{
    if (apply_seccomp_sandbox() != 0) {
        _exit(WP_SECCOMP_CHILD_FILTER_ERR);
    }

    /* libc exit() is required here; _exit() skips glibc _IO_cleanup. */
    exit(0);
}

static int run_exit_cleanup_case(const char *name)
{
    pid_t pid;
    int status;
    int err = 0;

    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("%s: fork() failed: %s", name, strerror(errno));
        return 1;
    }

    if (pid == 0) {
        return child_exit_under_filter();
    }

    if (waitpid(pid, &status, 0) == -1) {
        PRINT_ERR_MSG("%s: waitpid() failed: %s", name, strerror(errno));
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        PRINT_MSG("%s: child exited cleanly under OpenSSH preauth filter",
            name);
    }
    else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
        PRINT_ERR_MSG("%s: child killed by SIGSYS during libc exit", name);
        err = 1;
    }
    else if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("%s: child killed by unexpected signal %d", name,
            WTERMSIG(status));
        err = 1;
    }
    else if (WIFEXITED(status)) {
        PRINT_ERR_MSG("%s: child exited with status %d", name,
            WEXITSTATUS(status));
        err = 1;
    }
    else {
        PRINT_ERR_MSG("%s: child exited abnormally", name);
        err = 1;
    }

    return err;
}

static int seccomp_helper_single_stream(const char *providerDir,
    const char *providerName)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *provider = NULL;
    unsigned char buf[32];
    int err = 0;

    /* Entered before unit.c's OpenSSL setup. The customer's preauth child skips
     * provider teardown; NO_ATEXIT reproduces that exit-time behavior here. */
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL) != 1) {
        PRINT_ERR_MSG("OPENSSL_init_crypto(NO_ATEXIT) failed");
        err = 1;
    }

    if (err == 0) {
        ctx = OSSL_LIB_CTX_new();
        if (ctx == NULL) {
            PRINT_ERR_MSG("OSSL_LIB_CTX_new failed");
            err = 1;
        }
    }

    if (err == 0) {
        err = load_provider_into_ctx(ctx, providerDir, providerName, &provider);
    }

    if (err == 0 && RAND_bytes_ex(ctx, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("single-context RAND_bytes_ex failed");
        err = 1;
    }

    /* T1: one SEED-SRC read, no teardown, so the fd is still open at exit. */
    if (err == 0) {
        err = run_exit_cleanup_case("T1 single-context SEED-SRC");
    }

    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(ctx);

    return err;
}

static int seccomp_helper_leak_route(const char *providerDir,
    const char *providerName)
{
    OSSL_LIB_CTX *ctx2 = NULL;
    OSSL_PROVIDER *provider1 = NULL;
    OSSL_PROVIDER *provider2 = NULL;
    unsigned char buf[32];
    int err = 0;

    if (load_provider_into_ctx(NULL, providerDir, providerName, &provider1)
        != 0) {
        err = 1;
    }

    if (err == 0 && RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("default-context RAND_bytes failed");
        err = 1;
    }

    if (err == 0) {
        ctx2 = OSSL_LIB_CTX_new();
        if (ctx2 == NULL) {
            PRINT_ERR_MSG("second OSSL_LIB_CTX_new failed");
            err = 1;
        }
    }

    if (err == 0) {
        err = load_provider_into_ctx(ctx2, providerDir, providerName,
            &provider2);
    }

    if (err == 0 && RAND_bytes_ex(ctx2, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("second-context RAND_bytes_ex failed");
        err = 1;
    }

    /* T2: a second provider init shares the same fd via the refcount rather
     * than orphaning a buffered stream for exit-time cleanup to rewind. */
    if (err == 0) {
        err = run_exit_cleanup_case("T2 second-context SEED-SRC re-init");
    }

    OSSL_PROVIDER_unload(provider2);
    OSSL_LIB_CTX_free(ctx2);
    OSSL_PROVIDER_unload(provider1);

    return err;
}

static int child_rand_under_filter(OSSL_LIB_CTX *ctx)
{
    EVP_RAND_CTX *rctx;
    WC_RNG rng;
    unsigned char buf[32];
    int rngInit = 0;
    int err = 0;

    if (apply_seccomp_sandbox() != 0) {
        return WP_SECCOMP_CHILD_FILTER_ERR;
    }

    /* Force fresh entropy after the sandbox is installed; a cached public DRBG
     * could otherwise hide a teardown that closed the inherited fd. */
    rctx = RAND_get0_public(ctx);
    if (rctx == NULL) {
        PRINT_ERR_MSG("multi-context RAND_get0_public failed under sandbox");
        err = WP_SECCOMP_CHILD_OPENSSL_RAND_ERR;
    }
    else if (EVP_RAND_reseed(rctx, 0, NULL, 0, NULL, 0) != 1) {
        PRINT_ERR_MSG("multi-context EVP_RAND_reseed failed under sandbox");
        err = WP_SECCOMP_CHILD_OPENSSL_RAND_ERR;
    }

    if (err == 0 && RAND_bytes_ex(ctx, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("multi-context RAND_bytes_ex failed under sandbox");
        err = WP_SECCOMP_CHILD_OPENSSL_RAND_ERR;
    }

    /* Also exercise wolfSSL's global seed callback: the second provider init
     * resets it before wp_urandom_init(), covering the stale-callback bug. */
    if (err == 0) {
        if (wc_InitRng(&rng) != 0) {
            PRINT_ERR_MSG("multi-context wc_InitRng failed under sandbox");
            err = WP_SECCOMP_CHILD_WC_INIT_ERR;
        }
        else {
            rngInit = 1;
        }
    }
    if (err == 0 && wc_RNG_GenerateBlock(&rng, buf, sizeof(buf)) != 0) {
        PRINT_ERR_MSG(
            "multi-context wc_RNG_GenerateBlock failed under sandbox");
        err = WP_SECCOMP_CHILD_WC_RAND_ERR;
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }

    return err;
}

static int run_multi_context_survivor_child(OSSL_LIB_CTX *ctx,
    const char *name)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("%s: fork() failed: %s", name, strerror(errno));
        return 1;
    }

    if (pid == 0) {
        _exit(child_rand_under_filter(ctx));
    }

    if (waitpid(pid, &status, 0) == -1) {
        PRINT_ERR_MSG("%s: waitpid() failed: %s", name, strerror(errno));
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        PRINT_MSG("%s: child obtained entropy under OpenSSH preauth filter",
            name);
        return 0;
    }
    if (WIFEXITED(status)) {
        int exitCode = WEXITSTATUS(status);

        if (exitCode == WP_SECCOMP_CHILD_OPENSSL_RAND_ERR) {
            PRINT_ERR_MSG("%s: child failed OpenSSL RAND reseed under "
                "sandbox (exit code %d)", name, exitCode);
        }
        else if (exitCode == WP_SECCOMP_CHILD_WC_INIT_ERR) {
            PRINT_ERR_MSG("%s: child failed wolfCrypt RNG init under "
                "sandbox (exit code %d)", name, exitCode);
        }
        else if (exitCode == WP_SECCOMP_CHILD_WC_RAND_ERR) {
            PRINT_ERR_MSG("%s: child failed wolfCrypt RNG generate under "
                "sandbox (exit code %d)", name, exitCode);
        }
        else {
            PRINT_ERR_MSG("%s: child failed under sandbox (exit code %d)",
                name, exitCode);
        }
        return 1;
    }
    if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("%s: child killed by signal %d", name,
            WTERMSIG(status));
        return 1;
    }

    PRINT_ERR_MSG("%s: child exited abnormally", name);
    return 1;
}

static int seccomp_helper_multi_context_lifecycle(const char *providerDir,
    const char *providerName)
{
    OSSL_LIB_CTX *ctx1 = NULL;
    OSSL_LIB_CTX *ctx2 = NULL;
    OSSL_PROVIDER *provider1 = NULL;
    OSSL_PROVIDER *provider2 = NULL;
    unsigned char buf[32];
    int err = 0;

    ctx1 = OSSL_LIB_CTX_new();
    if (ctx1 == NULL) {
        PRINT_ERR_MSG("first OSSL_LIB_CTX_new failed");
        err = 1;
    }

    if (err == 0) {
        err = load_provider_into_ctx(ctx1, providerDir, providerName,
            &provider1);
    }

    if (err == 0 && RAND_bytes_ex(ctx1, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("first-context RAND_bytes_ex failed");
        err = 1;
    }

    if (err == 0) {
        ctx2 = OSSL_LIB_CTX_new();
        if (ctx2 == NULL) {
            PRINT_ERR_MSG("second OSSL_LIB_CTX_new failed");
            err = 1;
        }
    }

    if (err == 0) {
        err = load_provider_into_ctx(ctx2, providerDir, providerName,
            &provider2);
    }

    if (err == 0 && RAND_bytes_ex(ctx2, buf, sizeof(buf), 0) != 1) {
        PRINT_ERR_MSG("second-context RAND_bytes_ex failed");
        err = 1;
    }

    /*
     * Unload only the first provider/libctx. The second context is still live,
     * so its child must be able to reseed under OpenSSH's filter using the
     * inherited urandom fd and the wolfSSL seed callback.
     */
    if (provider1 != NULL) {
        OSSL_PROVIDER_unload(provider1);
        provider1 = NULL;
    }
    OSSL_LIB_CTX_free(ctx1);
    ctx1 = NULL;

    if (err == 0) {
        err = run_multi_context_survivor_child(ctx2,
            "T3 multi-context survivor after one unload");
    }

    OSSL_PROVIDER_unload(provider2);
    OSSL_LIB_CTX_free(ctx2);

    return err;
}

/*
 * Re-exec entry point for the seccomp helper child: dispatches to the
 * single/leak/multi sub-case by mode. Returns 0 on success, non-zero on
 * failure (2 on bad arguments or unknown mode).
 */
int test_seccomp_sandbox_helper(const char *mode, const char *providerDir,
    const char *providerName)
{
    int err;

    if (mode == NULL || providerDir == NULL || providerName == NULL) {
        PRINT_ERR_MSG("seccomp helper missing arguments");
        return 2;
    }

    if (strcmp(mode, "single") == 0) {
        err = seccomp_helper_single_stream(providerDir, providerName);
    }
    else if (strcmp(mode, "leak") == 0) {
        err = seccomp_helper_leak_route(providerDir, providerName);
    }
    else if (strcmp(mode, "multi") == 0) {
        err = seccomp_helper_multi_context_lifecycle(providerDir,
            providerName);
    }
    else {
        PRINT_ERR_MSG("unknown seccomp helper mode: %s", mode);
        err = 2;
    }

    return err;
}

static int run_seccomp_helper_case(const char *mode, const char *name)
{
    char exePath[PATH_MAX];
    ssize_t exeLen;
    pid_t pid;
    int status;
    int err = 0;
    const char *providerDir = wpUnitProviderDir;
    const char *providerName = wpUnitProviderName;

    if (providerDir == NULL) {
        providerDir = ".libs";
    }
    if (providerName == NULL) {
        providerName = wolfprovider_id;
    }

    exeLen = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (exeLen < 0) {
        PRINT_ERR_MSG("%s: readlink(/proc/self/exe) failed: %s", name,
            strerror(errno));
        return 1;
    }
    if (exeLen >= (ssize_t)sizeof(exePath) - 1) {
        PRINT_ERR_MSG("%s: /proc/self/exe path too long", name);
        return 1;
    }
    exePath[exeLen] = '\0';

    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("%s: fork() failed: %s", name, strerror(errno));
        return 1;
    }

    if (pid == 0) {
        execl(exePath, exePath, "--seccomp-sandbox-helper", mode, providerDir,
            providerName, (char *)NULL);
        PRINT_ERR_MSG("%s: execl helper failed: %s", name, strerror(errno));
        _exit(127);
    }

    if (waitpid(pid, &status, 0) == -1) {
        PRINT_ERR_MSG("%s: waitpid(helper) failed: %s", name, strerror(errno));
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        PRINT_MSG("%s: PASSED", name);
    }
    else if (WIFEXITED(status)) {
        PRINT_ERR_MSG("%s: FAILED, helper exited with status %d", name,
            WEXITSTATUS(status));
        err = 1;
    }
    else if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("%s: helper killed by signal %d", name,
            WTERMSIG(status));
        err = 1;
    }
    else {
        PRINT_ERR_MSG("%s: helper exited abnormally", name);
        err = 1;
    }

    return err;
}

/*
 * Child process regression test function.
 * Applies sandbox and attempts RAND_bytes operations.
 * Returns 0 on success, non-zero on failure.
 */
static int child_test_rand_under_sandbox(OSSL_LIB_CTX *libCtx)
{
    unsigned char buf[32];
    OSSL_LIB_CTX *origCtx;
    int err = 0;

    /* Set the library context */
    origCtx = OSSL_LIB_CTX_set0_default(libCtx);

    /* Apply seccomp sandbox - mimics ssh_sandbox_child() */
    if (apply_seccomp_sandbox() != 0) {
        PRINT_ERR_MSG("Failed to apply seccomp sandbox");
        OSSL_LIB_CTX_set0_default(origCtx);
        return 1;
    }

    /* Generate random bytes under the real preauth filter. The caller uses
     * _exit(), so this stays a fork-safety guard without libc stdio cleanup. */
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("RAND_bytes failed under sandbox");
        err = 1;
    }

    if (err == 0 && RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("Second RAND_bytes failed under sandbox");
        err = 1;
    }

    if (err == 0) {
        EVP_RAND_CTX *rctx = RAND_get0_public(libCtx);
        if (rctx == NULL) {
            PRINT_ERR_MSG("RAND_get0_public failed under sandbox");
            err = 1;
        }
        else if (EVP_RAND_reseed(rctx, 0, NULL, 0, NULL, 0) != 1) {
            PRINT_ERR_MSG("EVP_RAND_reseed failed under sandbox");
            err = 1;
        }
    }

    if (err == 0 && RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("RAND_bytes after reseed failed under sandbox");
        err = 1;
    }

    OSSL_LIB_CTX_set0_default(origCtx);
    return err;
}

/*
 * Run the fork+sandbox regression test for a given library context.
 * Returns 0 on success, non-zero on failure.
 */
static int run_fork_sandbox_test(OSSL_LIB_CTX *libCtx, const char *provName)
{
    pid_t pid;
    int status;
    unsigned char buf[32];
    OSSL_LIB_CTX *origCtx;

    PRINT_MSG("Testing %s provider with fork+sandbox", provName);

    origCtx = OSSL_LIB_CTX_set0_default(libCtx);
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("Pre-fork RAND_bytes failed for %s", provName);
        OSSL_LIB_CTX_set0_default(origCtx);
        return 1;
    }
    OSSL_LIB_CTX_set0_default(origCtx);

    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("fork() failed: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        int child_err;

        child_err = child_test_rand_under_sandbox(libCtx);
        _exit(child_err);
    }

    if (waitpid(pid, &status, 0) == -1) {
        PRINT_ERR_MSG("waitpid() failed: %s", strerror(errno));
        return 1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code == 0) {
            PRINT_MSG("%s: Child succeeded under sandbox", provName);
            return 0;
        }

        PRINT_ERR_MSG("%s: Child failed under sandbox (exit code %d)",
            provName, exit_code);
        return 1;
    }
    else if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("%s: Child killed by signal %d", provName,
            WTERMSIG(status));
        return 1;
    }

    PRINT_ERR_MSG("%s: Child exited abnormally", provName);
    return 1;
}

int test_seccomp_sandbox(void *data)
{
    int err = 0;

    (void)data;

    PRINT_MSG("=== OpenSSH seccomp sandbox SEED-SRC test ===");

    if (run_seccomp_helper_case("single",
        "T1 customer-faithful single SEED-SRC read") != 0) {
        err = 1;
    }

    if (run_seccomp_helper_case("leak",
        "T2 second-libctx SEED-SRC re-init") != 0) {
        err = 1;
    }

    if (run_seccomp_helper_case("multi",
        "T3 multi-context survivor after one unload") != 0) {
        err = 1;
    }

    PRINT_MSG("--- Regression: child reads entropy under sandbox ---");
    if (run_fork_sandbox_test(osslLibCtx, "OpenSSL default") != 0) {
        err = 1;
    }
    if (run_fork_sandbox_test(wpLibCtx, "wolfProvider") != 0) {
        err = 1;
    }

    if (err == 0) {
        PRINT_MSG("=== All seccomp sandbox tests passed ===");
    }

    return err;
}

#else /* !WP_HAVE_SECCOMP */

int test_seccomp_sandbox_helper(const char *mode, const char *providerDir,
    const char *providerName)
{
    (void)mode;
    (void)providerDir;
    (void)providerName;

    PRINT_MSG("Seccomp sandbox helper skipped - seccomp not available");
    return 1;
}

int test_seccomp_sandbox(void *data)
{
    (void)data;
    PRINT_MSG("Seccomp sandbox test skipped - seccomp not available");
    return 0;
}

#endif /* WP_HAVE_SECCOMP */

#else /* !(WP_TEST_SECCOMP_SANDBOX && WP_HAVE_SEED_SRC && WP_HAVE_RANDOM) */

int test_seccomp_sandbox(void *data)
{
    (void)data;
    PRINT_MSG("Seccomp sandbox test skipped - not enabled or not supported");
    PRINT_MSG("Requires: --enable-seed-src and -DWP_TEST_SECCOMP_SANDBOX");
    return 0;
}

#endif /* WP_TEST_SECCOMP_SANDBOX && WP_HAVE_SEED_SRC && WP_HAVE_RANDOM */
