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
 * This test mimics OpenSSH's seccomp sandbox behavior to verify that
 * wolfProvider's DRBG can operate correctly after fork() when file
 * descriptor operations are restricted.
 *
 * OpenSSH Flow (sshd-session.c privsep_preauth):
 *   1. Parent forks child for privilege separation
 *   2. Child calls reseed_prngs() BEFORE sandbox (RAND_poll, RAND_bytes)
 *   3. Child applies seccomp sandbox (blocks open/openat syscalls)
 *   4. Child performs crypto operations under sandbox restrictions
 *
 * The problem: After sandbox is applied, if DRBG needs to reseed,
 * it cannot open /dev/urandom because openat() returns EACCES.
 *
 * This test verifies:
 *   - Default OpenSSL provider works under these conditions (baseline)
 *   - wolfProvider should eventually work (currently expected to fail)
 *
 * NOTE: This test is disabled by default because it uses seccomp which
 * can interfere with other tests and debugging. Enable it by defining
 * WP_TEST_SECCOMP_SANDBOX in CFLAGS:
 *   ./configure CFLAGS="-DWP_TEST_SECCOMP_SANDBOX"
 */

#include "unit.h"

#if defined(WP_TEST_SECCOMP_SANDBOX) && defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>

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
#include <sys/syscall.h>

/* Determine the correct audit architecture */
#if defined(__x86_64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__i386__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__aarch64__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
    #define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#else
    /* Unsupported architecture - disable test */
    #undef WP_HAVE_SECCOMP
#endif

#endif /* WP_HAVE_SECCOMP */

#ifdef WP_HAVE_SECCOMP

/* BPF macros for seccomp filter - mirrors OpenSSH sandbox-seccomp-filter.c */
#define SC_DENY(_nr, _errno) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))

#define SC_ALLOW(_nr) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (_nr), 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

/*
 * Minimal seccomp filter that mimics OpenSSH's preauth sandbox.
 * Key restrictions:
 *   - Deny open/openat with EACCES (prevents opening /dev/urandom)
 *   - Allow essential syscalls for the test to run
 */
static const struct sock_filter naomi_insns[] = {
    /* Verify architecture */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* Load syscall number */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* Deny file open syscalls with EACCES - this is the key restriction */
#ifdef __NR_open
    SC_DENY(__NR_open, EACCES),
#endif
#ifdef __NR_openat
    SC_DENY(__NR_openat, EACCES),
#endif

    /* Allow syscalls needed for the test to function */
#ifdef __NR_read
    SC_ALLOW(__NR_read),
#endif
#ifdef __NR_write
    SC_ALLOW(__NR_write),
#endif
#ifdef __NR_close
    SC_ALLOW(__NR_close),
#endif
#ifdef __NR_exit_group
    SC_ALLOW(__NR_exit_group),
#endif
#ifdef __NR_exit
    SC_ALLOW(__NR_exit),
#endif
#ifdef __NR_brk
    SC_ALLOW(__NR_brk),
#endif
#ifdef __NR_mmap
    SC_ALLOW(__NR_mmap),
#endif
#ifdef __NR_munmap
    SC_ALLOW(__NR_munmap),
#endif
#ifdef __NR_mprotect
    SC_ALLOW(__NR_mprotect),
#endif
#ifdef __NR_futex
    SC_ALLOW(__NR_futex),
#endif
#ifdef __NR_getrandom
    SC_ALLOW(__NR_getrandom),
#endif
#ifdef __NR_getpid
    SC_ALLOW(__NR_getpid),
#endif
#ifdef __NR_gettid
    SC_ALLOW(__NR_gettid),
#endif
#ifdef __NR_rt_sigprocmask
    SC_ALLOW(__NR_rt_sigprocmask),
#endif
#ifdef __NR_rt_sigaction
    SC_ALLOW(__NR_rt_sigaction),
#endif
#ifdef __NR_clock_gettime
    SC_ALLOW(__NR_clock_gettime),
#endif
#ifdef __NR_nanosleep
    SC_ALLOW(__NR_nanosleep),
#endif
#ifdef __NR_sched_yield
    SC_ALLOW(__NR_sched_yield),
#endif
#ifdef __NR_mremap
    SC_ALLOW(__NR_mremap),
#endif
#ifdef __NR_madvise
    SC_ALLOW(__NR_madvise),
#endif

    /* Default: allow other syscalls (we only want to block file opens) */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
};

static const struct sock_fprog naomi_program = {
    .len = (unsigned short)(sizeof(naomi_insns) / sizeof(naomi_insns[0])),
    .filter = (struct sock_filter *)naomi_insns,
};

/*
 * Apply seccomp sandbox restrictions mimicking OpenSSH behavior.
 * Returns 0 on success, -1 on failure.
 */
static int apply_seccomp_sandbox(void)
{
    /*
     * Set resource limits like OpenSSH does.
     * RLIMIT_NOFILE = 1 allows existing fds but prevents new ones.
     * Note: OpenSSH uses 1, not 0, because poll() fails with EINVAL
     * if npfds > RLIMIT_NOFILE.
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

    /* Apply seccomp filter - must set NO_NEW_PRIVS first */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        PRINT_ERR_MSG("prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &naomi_program) == -1) {
        PRINT_ERR_MSG("prctl(PR_SET_SECCOMP) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * Child process test function.
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

    /*
     * Now try to generate random bytes under sandbox.
     * This is the critical test - the DRBG may need to reseed,
     * but it cannot open /dev/urandom because openat() is blocked.
     */
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("RAND_bytes failed under sandbox");
        err = 1;
    }

    /* Try a second call to potentially trigger reseed */
    if (err == 0 && RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("Second RAND_bytes failed under sandbox");
        err = 1;
    }

    OSSL_LIB_CTX_set0_default(origCtx);
    return err;
}

/*
 * Run the fork+sandbox test for a given library context.
 * Returns 0 on success, non-zero on failure.
 */
static int run_fork_sandbox_test(OSSL_LIB_CTX *libCtx, const char *provName)
{
    pid_t pid;
    int status;
    unsigned char buf[32];
    OSSL_LIB_CTX *origCtx;

    PRINT_MSG("Testing %s provider with fork+sandbox", provName);

    /* Pre-fork: Initialize DRBG by generating some random bytes */
    origCtx = OSSL_LIB_CTX_set0_default(libCtx);
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        PRINT_ERR_MSG("Pre-fork RAND_bytes failed for %s", provName);
        OSSL_LIB_CTX_set0_default(origCtx);
        return 1;
    }
    OSSL_LIB_CTX_set0_default(origCtx);

    PRINT_MSG("Pre-fork RAND_bytes succeeded, forking child...");

    /* Fork child process - mimics OpenSSH privsep_preauth() */
    pid = fork();
    if (pid == -1) {
        PRINT_ERR_MSG("fork() failed: %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        /* Child process */
        int child_err;

        /*
         * Note: In OpenSSH, reseed_prngs() is called here BEFORE sandbox.
         * We intentionally skip that step to test the failure case.
         * Once wolfProvider has proper fork-safe DRBG, the reseed
         * should happen automatically or the DRBG should work without
         * needing to open /dev/urandom.
         */

        child_err = child_test_rand_under_sandbox(libCtx);

        /* Exit with status indicating success (0) or failure (1) */
        _exit(child_err);
    }

    /* Parent process - wait for child */
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
        else {
            PRINT_MSG("%s: Child failed under sandbox (exit code %d)",
                      provName, exit_code);
            return 1;
        }
    }
    else if (WIFSIGNALED(status)) {
        PRINT_ERR_MSG("%s: Child killed by signal %d", provName,
                      WTERMSIG(status));
        return 1;
    }

    PRINT_ERR_MSG("%s: Child exited abnormally", provName);
    return 1;
}

/*
 * Main test function for seccomp sandbox DRBG behavior.
 *
 * This test verifies:
 *   1. Default OpenSSL provider works under fork+sandbox (baseline)
 *   2. wolfProvider behavior under fork+sandbox
 *
 * Currently wolfProvider is EXPECTED TO FAIL because the DRBG
 * tries to open /dev/urandom after fork, which is blocked by seccomp.
 */
int test_seccomp_sandbox(void *data)
{
    int err = 0;
    int wp_err;

    (void)data;

    PRINT_MSG("=== Seccomp Sandbox DRBG Test ===");
    PRINT_MSG("This test mimics OpenSSH's fork+sandbox behavior");

    /*
     * Test 1: Default OpenSSL provider (baseline - should pass)
     * This verifies our test harness works correctly.
     */
    PRINT_MSG("");
    PRINT_MSG("--- Test with OpenSSL default provider (baseline) ---");
    err = run_fork_sandbox_test(osslLibCtx, "OpenSSL default");
    if (err != 0) {
        PRINT_ERR_MSG("BASELINE FAILED: OpenSSL default provider failed");
        PRINT_ERR_MSG("This indicates a problem with the test itself");
        return err;
    }
    PRINT_MSG("OpenSSL default provider: PASSED (baseline verified)");

    /*
     * Test 2: wolfProvider
     * Currently expected to fail because DRBG tries to open /dev/urandom
     * after fork, which is blocked by seccomp.
     */
    PRINT_MSG("");
    PRINT_MSG("--- Test with wolfProvider ---");
    wp_err = run_fork_sandbox_test(wpLibCtx, "wolfProvider");

    if (wp_err != 0) {
        PRINT_MSG("wolfProvider: FAILED (expected - DRBG cannot reseed)");
        PRINT_MSG("This is expected until fork-safe DRBG is implemented");
        /*
         * Return the error so the test is marked as failed.
         * Once the fix is implemented, this test should pass.
         */
        return wp_err;
    }

    PRINT_MSG("wolfProvider: PASSED");
    PRINT_MSG("=== All seccomp sandbox tests passed ===");

    return 0;
}

#else /* !WP_HAVE_SECCOMP */

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

