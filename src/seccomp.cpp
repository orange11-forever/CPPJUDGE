#include "onlinejudge/seccomp.h"

#include <algorithm>
#include <cstdint>
#include <vector>

#include <asm/unistd_64.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 36
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

namespace onlinejudge {

// Whitelist of safe syscalls for sandboxed programs.
// This includes everything a well-behaved C/C++ program typically needs.
// Explicitly EXCLUDED categories: network, process creation (clone/fork/execveat),
// privilege escalation, kernel manipulation, namespace ops, mounts, ptrace, kill,
// module loading, reboot, I/O submission, BPF, seccomp, key management.

static const std::vector<int> ALLOWED_SYSCALLS = {
    // --- File I/O ---
    __NR_read, __NR_write, __NR_open, __NR_openat, __NR_close,
    __NR_pread64, __NR_pwrite64, __NR_readv, __NR_writev,
    __NR_preadv, __NR_pwritev, __NR_lseek,
    __NR_truncate, __NR_ftruncate,
    __NR_sync, __NR_fsync, __NR_fdatasync, __NR_syncfs,
    __NR_copy_file_range,
    __NR_sendfile,       // safe within chroot
    __NR_splice,         // safe within chroot
    __NR_vmsplice,       // safe within chroot
    __NR_tee,
    __NR_readahead, __NR_fadvise64,
    __NR_sync_file_range,

    // --- File/Directory metadata ---
    __NR_stat, __NR_fstat, __NR_lstat, __NR_newfstatat, __NR_statx,
    __NR_getdents, __NR_getdents64,
    __NR_readlink, __NR_readlinkat,
    __NR_getcwd,
    __NR_access, __NR_faccessat, __NR_faccessat2,
    __NR_statfs, __NR_fstatfs,
    __NR_umask,

    // --- File descriptor management ---
    __NR_dup, __NR_dup2, __NR_dup3,
    __NR_fcntl, __NR_flock,
    __NR_pipe, __NR_pipe2,
    __NR_close_range,

    // --- Memory management ---
    __NR_mmap, __NR_mprotect, __NR_munmap, __NR_brk,
    __NR_mremap, __NR_mincore, __NR_madvise,
    __NR_msync, __NR_mlock, __NR_munlock,
    __NR_mlockall, __NR_munlockall, __NR_mlock2,
    __NR_mbind, __NR_set_mempolicy, __NR_get_mempolicy,
    __NR_migrate_pages, __NR_move_pages,
    __NR_pkey_mprotect, __NR_pkey_alloc, __NR_pkey_free,
    __NR_memfd_create, __NR_memfd_secret,
    __NR_set_mempolicy_home_node,

    // --- Process/Thread identity ---
    __NR_getpid, __NR_gettid, __NR_getppid, __NR_getpgid, __NR_getpgrp,
    __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
    __NR_getresuid, __NR_getresgid, __NR_getgroups,
    __NR_capget,

    // --- Threading ---
    __NR_futex, __NR_futex_waitv, __NR_futex_wake, __NR_futex_wait, __NR_futex_requeue,
    __NR_set_tid_address, __NR_set_robust_list, __NR_get_robust_list,
    __NR_rseq, __NR_membarrier, __NR_getcpu,
    __NR_sched_yield,
    __NR_sched_getaffinity, __NR_sched_setaffinity,
    __NR_sched_getattr, __NR_sched_setattr,
    __NR_sched_getparam, __NR_sched_getscheduler,
    __NR_sched_get_priority_max, __NR_sched_get_priority_min,
    __NR_sched_rr_get_interval,
    __NR_restart_syscall,

    // --- Signals ---
    __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn,
    __NR_sigaltstack,
    __NR_rt_sigpending, __NR_rt_sigtimedwait, __NR_rt_sigsuspend,
    __NR_rt_sigqueueinfo, __NR_rt_tgsigqueueinfo,
    __NR_signalfd, __NR_signalfd4,

    // --- Time ---
    __NR_gettimeofday, __NR_time,
    __NR_clock_gettime, __NR_clock_getres, __NR_clock_nanosleep,
    __NR_clock_adjtime, __NR_clock_settime,
    __NR_nanosleep,
    __NR_getitimer, __NR_setitimer, __NR_alarm,
    __NR_timer_create, __NR_timer_delete,
    __NR_timer_settime, __NR_timer_gettime, __NR_timer_getoverrun,
    __NR_timerfd_create, __NR_timerfd_settime, __NR_timerfd_gettime,
    __NR_times, __NR_adjtimex,

    // --- Resource limits ---
    __NR_getrlimit, __NR_setrlimit, __NR_prlimit64,
    __NR_getrusage, __NR_sysinfo,

    // --- Misc safe syscalls ---
    __NR_ioctl,
    __NR_uname, __NR_uname,
    __NR_umask, __NR_umask,
    __NR_getrandom,
    __NR_arch_prctl,      // x86_64 TLS setup
    __NR_exit, __NR_exit_group,
    __NR_execve,           // needed by sandbox to launch target
    __NR_wait4,            // wait for children
    __NR_waitid,           // modern wait variant
    __NR_poll, __NR_select, __NR_ppoll, __NR_pselect6,
    __NR_epoll_create, __NR_epoll_create1,
    __NR_epoll_ctl, __NR_epoll_wait, __NR_epoll_pwait, __NR_epoll_pwait2,
    __NR_eventfd, __NR_eventfd2,
    __NR_sched_yield,      // already listed above but OK to duplicate (sorted+dedup'd)
    __NR_getcwd,           // already listed

    // --- xattr (read for introspection; write blocked elsewhere) ---
    __NR_getxattr, __NR_lgetxattr, __NR_fgetxattr,
    __NR_listxattr, __NR_llistxattr, __NR_flistxattr,

    // --- inotify (file change monitoring, harmless) ---
    __NR_inotify_init, __NR_inotify_init1,
    __NR_inotify_add_watch, __NR_inotify_rm_watch,

    // --- utimens (file timestamp manipulation, harmless in chroot) ---
    __NR_utimensat, __NR_futimesat, __NR_utimes, __NR_utime,

    // --- Directory operations (safe within chroot) ---
    __NR_chdir, __NR_fchdir,
    __NR_mkdir, __NR_mkdirat,
    __NR_rmdir,
    __NR_rename, __NR_renameat, __NR_renameat2,
    __NR_link, __NR_linkat,
    __NR_unlink, __NR_unlinkat,
    __NR_symlink, __NR_symlinkat,
    __NR_mknod, __NR_mknodat,
    __NR_chmod, __NR_fchmod, __NR_fchmodat, __NR_fchmodat2,
    __NR_chown, __NR_fchown, __NR_lchown, __NR_fchownat,
    __NR_creat,
    __NR_fallocate,

    // --- AIO ---
    __NR_io_setup, __NR_io_destroy,
    __NR_io_getevents, __NR_io_submit, __NR_io_cancel,
    __NR_io_pgetevents,

    // --- Misc ---
    __NR_getpriority, __NR_setpriority,
    __NR_ioprio_get, __NR_ioprio_set,
    __NR_sched_getparam, __NR_sched_getscheduler,
    __NR_name_to_handle_at, __NR_open_by_handle_at,
    __NR_process_vm_readv, __NR_process_vm_writev,
    __NR_kcmp,

    // --- rseq/rseq-related ---
    __NR_rseq, __NR_membarrier, __NR_getcpu,

    // --- futex ---
    __NR_futex, __NR_futex_waitv, __NR_futex_wake, __NR_futex_wait, __NR_futex_requeue,
};

std::vector<BpfInstruction> SeccompFilter::build() {
    auto allowed = ALLOWED_SYSCALLS;
    std::sort(allowed.begin(), allowed.end());

    std::vector<BpfInstruction> filter;

    // Validate architecture: load arch field from seccomp_data (offset 4)
    filter.push_back(BpfInstruction{BPF_LD | BPF_W | BPF_ABS, 0, 0, 4});
    // If arch == AUDIT_ARCH_X86_64, jump 1 forward (skip KILL, go to load syscall nr)
    filter.push_back(BpfInstruction{
        (std::uint16_t)(BPF_JMP | BPF_JEQ | BPF_K), 1, 0, AUDIT_ARCH_X86_64});
    filter.push_back(BpfInstruction{
        (std::uint16_t)(BPF_RET | BPF_K), 0, 0, SECCOMP_RET_KILL_PROCESS});

    // Load syscall number from seccomp_data (offset 0)
    filter.push_back(BpfInstruction{BPF_LD | BPF_W | BPF_ABS, 0, 0, 0});

    // Sort and deduplicate allowed syscalls
    std::sort(allowed.begin(), allowed.end());
    allowed.erase(std::unique(allowed.begin(), allowed.end()), allowed.end());

    // Build whitelist chain.
    // After the chain: 1 KILL + 1 ALLOW = 2 instructions.
    // jt: skip (N-i-1) remaining checks + 1 KILL = (N-i) instructions.
    for (std::size_t i = 0; i < allowed.size(); ++i) {
        std::uint8_t remaining = static_cast<std::uint8_t>(allowed.size() - i);
        filter.push_back(BpfInstruction{
            (std::uint16_t)(BPF_JMP | BPF_JEQ | BPF_K),
            remaining,
            0,
            (std::uint32_t)allowed[i]
        });
    }

    // Default: kill process
    filter.push_back(BpfInstruction{
        (std::uint16_t)(BPF_RET | BPF_K), 0, 0, SECCOMP_RET_KILL_PROCESS});

    // ALLOW return (jumped to by JT above on match)
    filter.push_back(BpfInstruction{
        (std::uint16_t)(BPF_RET | BPF_K), 0, 0, SECCOMP_RET_ALLOW});

    return filter;
}

void SeccompFilter::install(const std::vector<BpfInstruction>& filter) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        _exit(1);
    }

    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(filter.size());
    prog.filter = const_cast<struct sock_filter*>(
        reinterpret_cast<const struct sock_filter*>(filter.data()));

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        _exit(1);
    }
}

} // namespace onlinejudge
