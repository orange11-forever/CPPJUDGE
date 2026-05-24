#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "onlinejudge/sandbox.h"
#include "onlinejudge/cgroup.h"
#include "onlinejudge/chroot.h"
#include "onlinejudge/config.h"
#include "onlinejudge/errors.h"
#include "onlinejudge/result.h"
#include "onlinejudge/seccomp.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_NEWUSER
#include <linux/sched.h>
#endif

namespace onlinejudge {

// ---------------------------------------------------------------------------
// Shared state passed to the child via clone() argument
// ---------------------------------------------------------------------------
struct CloneArg {
    int sync_pipe[2];     // parent -> child: "go" signal
    int ready_pipe[2];    // child -> parent: "setup done" signal
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
    const SandboxConfig* config;
    std::string chroot_dir;
    std::string cgroup_path;

    // Exit status filled by child on failure
    int child_error_status;
};

// ---------------------------------------------------------------------------
// Signal handling for wall-clock timeout
// ---------------------------------------------------------------------------
static volatile sig_atomic_t g_wall_timeout = 0;

static void alarm_handler(int) {
    g_wall_timeout = 1;
}

// ---------------------------------------------------------------------------
// Utility: full-write to fd, handling EINTR and short writes
// ---------------------------------------------------------------------------
static bool write_all(int fd, const char* data, std::size_t len) {
    while (len > 0) {
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Utility: read all from fd, up to limit
// ---------------------------------------------------------------------------
static std::string read_all(int fd, std::size_t limit) {
    std::string result;
    char buf[65536];
    while (result.size() < limit) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break; // EOF
        std::size_t remaining = limit - result.size();
        result.append(buf, static_cast<std::size_t>(n) > remaining
                              ? remaining
                              : static_cast<std::size_t>(n));
    }
    return result;
}

// ---------------------------------------------------------------------------
// Utility: build char* const* from vector<string> for execve
// ---------------------------------------------------------------------------
static std::vector<char*> to_c_array(const std::vector<std::string>& v) {
    std::vector<char*> result;
    result.reserve(v.size() + 1);
    for (const auto& s : v) {
        result.push_back(const_cast<char*>(s.c_str()));
    }
    result.push_back(nullptr);
    return result;
}

// ---------------------------------------------------------------------------
// Child: main entry point after clone()
// ---------------------------------------------------------------------------
static int child_main(void* arg) {
    CloneArg* ca = static_cast<CloneArg*>(arg);

    // Close unused pipe ends
    ::close(ca->sync_pipe[1]);    // child reads sync
    ::close(ca->ready_pipe[0]);   // child writes ready
    ::close(ca->stdin_pipe[1]);   // child reads stdin
    ::close(ca->stdout_pipe[0]);  // child writes stdout
    ::close(ca->stderr_pipe[0]);  // child writes stderr

    // Wait for parent to set up uid_map, gid_map, and cgroups
    char sync_byte;
    if (::read(ca->sync_pipe[0], &sync_byte, 1) != 1) {
        _exit(1);
    }
    ::close(ca->sync_pipe[0]);

    // Now we are root inside the new user namespace
    (void)!::setgid(0);
    (void)!::setuid(0);

    // Verify we got root in the namespace
    if (::getuid() != 0) {
        _exit(1);
    }

    // Set hostname for UTS namespace isolation
    (void)!::sethostname("sandbox", 7);

    // Jailed executable path
    const char* jailed_exe = ChrootBuilder::jailed_executable_name();

    // ---- chroot ----
    const std::string& jail = ca->chroot_dir;
    if (::chdir(jail.c_str()) == -1) {
        _exit(2);
    }
    if (::chroot(".") == -1) {
        _exit(2);
    }
    if (::chdir("/") == -1) {
        _exit(2);
    }

    // ---- mount /proc in the new namespace ----
    if (::mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) == -1) {
        // Non-fatal: programs can run without /proc
    }

    // ---- create device nodes (we are root in this namespace) ----
    (void)!::mknod("/dev/null",    S_IFCHR | 0666, ::makedev(1, 3));
    (void)!::mknod("/dev/zero",    S_IFCHR | 0666, ::makedev(1, 5));
    (void)!::mknod("/dev/urandom", S_IFCHR | 0444, ::makedev(1, 9));
    (void)!::mknod("/dev/random",  S_IFCHR | 0444, ::makedev(1, 8));

    // ---- rlimits ----
    const auto* config = ca->config;

    // CPU time (in seconds)
    {
        struct rlimit rlim;
        rlim.rlim_cur = (config->time_limit_ms + 999) / 1000;
        rlim.rlim_max = (config->time_limit_ms + 999) / 1000 + 1;
        if (rlim.rlim_cur < 1) rlim.rlim_cur = 1;
        if (rlim.rlim_max < 1) rlim.rlim_max = 1;
        ::setrlimit(RLIMIT_CPU, &rlim);
    }

    // Address space (fallback if cgroups unavailable)
    {
        struct rlimit rlim;
        rlim.rlim_cur = static_cast<rlim_t>(config->memory_limit_kb) * 1024;
        rlim.rlim_max = rlim.rlim_cur;
        // If RLIMIT_AS is already set "unlimited", we can lower it
        ::setrlimit(RLIMIT_AS, &rlim);
    }

    // File size = output limit
    {
        struct rlimit rlim;
        rlim.rlim_cur = static_cast<rlim_t>(config->output_limit_bytes);
        rlim.rlim_max = rlim.rlim_cur;
        ::setrlimit(RLIMIT_FSIZE, &rlim);
    }

    // Max processes / threads
    {
        struct rlimit rlim;
        rlim.rlim_cur = static_cast<rlim_t>(config->max_processes);
        rlim.rlim_max = rlim.rlim_cur;
        ::setrlimit(RLIMIT_NPROC, &rlim);
    }

    // Max open files
    {
        struct rlimit rlim;
        rlim.rlim_cur = static_cast<rlim_t>(config->max_files);
        rlim.rlim_max = rlim.rlim_cur;
        ::setrlimit(RLIMIT_NOFILE, &rlim);
    }

    // Stack size (unlimited — let program use what it needs within AS limit)
    {
        struct rlimit rlim;
        rlim.rlim_cur = RLIM_INFINITY;
        rlim.rlim_max = RLIM_INFINITY;
        ::setrlimit(RLIMIT_STACK, &rlim);
    }

    // ---- seccomp ----
    if (config->enable_seccomp) {
        // Must be called before seccomp install
        auto filter = SeccompFilter::build();
        SeccompFilter::install(filter);
    }

    // ---- Redirect stdin/stdout/stderr ----
    if (config->redirect_stdout) {
        ::dup2(ca->stdout_pipe[1], STDOUT_FILENO);
    }
    if (config->redirect_stderr) {
        ::dup2(ca->stderr_pipe[1], STDERR_FILENO);
    }
    ::dup2(ca->stdin_pipe[0], STDIN_FILENO);

    ::close(ca->stdin_pipe[0]);
    ::close(ca->stdout_pipe[1]);
    ::close(ca->stderr_pipe[1]);

    // ---- Close all remaining FDs > 2 except ready_pipe ----
    int max_fd = static_cast<int>(::sysconf(_SC_OPEN_MAX));
    if (max_fd < 1024) max_fd = 1024;
    for (int fd = 3; fd < max_fd; ++fd) {
        if (fd == ca->ready_pipe[1]) continue; // Keep ready signal fd open
        ::close(fd);
    }

    // ---- Signal parent that setup is done ----
    char ready = 1;
    (void)!::write(ca->ready_pipe[1], &ready, 1);
    ::close(ca->ready_pipe[1]);

    // ---- Execute ----
    auto argv = to_c_array(config->argv);
    auto envp = to_c_array(config->envp);

    ::execve(jailed_exe, argv.data(), envp.data());

    // execve failed — exit via the ready pipe already closed, parent sees exit 127
    _exit(127);
}

// ---------------------------------------------------------------------------
// build and validate result from wait status + rusage
// ---------------------------------------------------------------------------
static SandboxResult build_result(SandboxStatus status,
                                  int wait_status,
                                  const struct rusage& rusage,
                                  std::uint64_t wall_ms,
                                  const std::string& cgroup_path,
                                  const std::string& error_msg = "") {
    SandboxResult result;
    result.status = status;
    result.error_msg = error_msg;
    result.wall_time_ms = wall_ms;

    if (WIFEXITED(wait_status)) {
        result.exit_code = WEXITSTATUS(wait_status);
    }
    if (WIFSIGNALED(wait_status)) {
        result.signal_number = WTERMSIG(wait_status);
    }

    result.cpu_time_ms =
        static_cast<std::uint64_t>(rusage.ru_utime.tv_sec) * 1000 +
        static_cast<std::uint64_t>(rusage.ru_utime.tv_usec) / 1000 +
        static_cast<std::uint64_t>(rusage.ru_stime.tv_sec) * 1000 +
        static_cast<std::uint64_t>(rusage.ru_stime.tv_usec) / 1000;

    if (!cgroup_path.empty()) {
        result.peak_memory_kb = CgroupManager::read_memory_peak(cgroup_path);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Sandbox::run — the main entry point
// ---------------------------------------------------------------------------
SandboxResult Sandbox::run(const SandboxConfig& config) {
    // ---- Pre-flight validation ----
    {
        std::string err;
        if (!config.validate(&err)) {
            return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, "", err);
        }
    }

    // ---- Set up cgroup ----
    std::string cgroup_path;
    {
        std::string name = "oj-" + std::to_string(::getpid()) + "-" +
                           std::to_string(
                               std::chrono::steady_clock::now().time_since_epoch().count());
        cgroup_path = CgroupManager::create(name);
        if (!cgroup_path.empty()) {
            CgroupManager::set_memory_limit(cgroup_path, config.memory_limit_kb);
            CgroupManager::set_pid_limit(cgroup_path,
                                         static_cast<std::uint32_t>(config.max_processes));
        }
    }

    // ---- Build chroot jail ----
    std::string chroot_dir = "/tmp/oj-sandbox-" + std::to_string(::getpid());
    if (!ChrootBuilder::build(chroot_dir, config)) {
        CgroupManager::destroy(cgroup_path);
        return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path,
                            "Failed to build chroot jail");
    }

    // ---- Create pipes ----
    CloneArg ca;
    ca.config = &config;
    ca.chroot_dir = chroot_dir;
    ca.cgroup_path = cgroup_path;
    ca.child_error_status = 0;

    if (::pipe2(ca.sync_pipe, O_CLOEXEC) == -1 ||
        ::pipe2(ca.ready_pipe, O_CLOEXEC) == -1 ||
        ::pipe2(ca.stdin_pipe, O_CLOEXEC) == -1 ||
        ::pipe2(ca.stdout_pipe, O_CLOEXEC) == -1 ||
        ::pipe2(ca.stderr_pipe, O_CLOEXEC) == -1) {
        CgroupManager::destroy(cgroup_path);
        return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path,
                            "Failed to create pipes");
    }

    // ---- Allocate child stack ----
    constexpr std::size_t STACK_SIZE = 4 * 1024 * 1024; // 4 MB
    void* stack = ::mmap(nullptr, STACK_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                         -1, 0);
    if (stack == MAP_FAILED) {
        CgroupManager::destroy(cgroup_path);
        return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path,
                            "Failed to allocate stack");
    }

    // ---- clone() ----
    int clone_flags = SIGCHLD
                    | CLONE_NEWUSER
                    | CLONE_NEWNET
                    | CLONE_NEWPID
                    | CLONE_NEWIPC
                    | CLONE_NEWUTS
                    | CLONE_NEWNS;

    pid_t child_pid = ::clone(child_main,
                               static_cast<char*>(stack) + STACK_SIZE,
                               clone_flags,
                               &ca);

    if (child_pid == -1) {
        ::munmap(stack, STACK_SIZE);
        CgroupManager::destroy(cgroup_path);
        std::string err = "clone() failed: " + std::string(::strerror(errno));
        if (errno == EPERM) {
            err += " (user namespaces may be disabled; check kernel.unprivileged_userns_clone)";
        }
        return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path, err);
    }

    // ---- Parent: set up uid_map / gid_map ----
    // Write "deny" to setgroups (required before writing gid_map)
    {
        std::string path = "/proc/" + std::to_string(child_pid) + "/setgroups";
        int fd = ::open(path.c_str(), O_WRONLY);
        if (fd != -1) {
            (void)!::write(fd, "deny", 4);
            ::close(fd);
        }
    }

    // uid_map: map namespace-uid 0 to our uid
    {
        std::string path = "/proc/" + std::to_string(child_pid) + "/uid_map";
        std::string mapping = "0 " + std::to_string(::getuid()) + " 1";
        int fd = ::open(path.c_str(), O_WRONLY);
        if (fd == -1) {
            ::kill(child_pid, SIGKILL);
            ::waitpid(child_pid, nullptr, 0);
            ::munmap(stack, STACK_SIZE);
            CgroupManager::destroy(cgroup_path);
            return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path,
                                "Failed to write uid_map");
        }
        (void)!::write(fd, mapping.c_str(), mapping.size());
        ::close(fd);
    }

    // gid_map: map namespace-gid 0 to our gid
    {
        std::string path = "/proc/" + std::to_string(child_pid) + "/gid_map";
        std::string mapping = "0 " + std::to_string(::getgid()) + " 1";
        int fd = ::open(path.c_str(), O_WRONLY);
        if (fd == -1) {
            ::kill(child_pid, SIGKILL);
            ::waitpid(child_pid, nullptr, 0);
            ::munmap(stack, STACK_SIZE);
            CgroupManager::destroy(cgroup_path);
            return build_result(SandboxStatus::SANDBOX_ERROR, 0, rusage{}, 0, cgroup_path,
                                "Failed to write gid_map");
        }
        (void)!::write(fd, mapping.c_str(), mapping.size());
        ::close(fd);
    }

    // ---- Attach child to cgroup ----
    if (!cgroup_path.empty()) {
        CgroupManager::attach(cgroup_path, child_pid);
    }

    // ---- Release child from sync wait ----
    char go = 1;
    (void)!::write(ca.sync_pipe[1], &go, 1);
    ::close(ca.sync_pipe[0]);
    ::close(ca.sync_pipe[1]);

    // Close unused pipe ends in parent
    ::close(ca.stdin_pipe[0]);
    ::close(ca.stdout_pipe[1]);
    ::close(ca.stderr_pipe[1]);

    // ---- Wait for child "ready" signal ----
    char ready_byte;
    if (::read(ca.ready_pipe[0], &ready_byte, 1) != 1) {
        // Child failed during setup
        ::close(ca.ready_pipe[0]);
        ::close(ca.stdin_pipe[1]);
        ::close(ca.stdout_pipe[0]);
        ::close(ca.stderr_pipe[0]);
        int status;
        ::waitpid(child_pid, &status, 0);
        ::munmap(stack, STACK_SIZE);
        CgroupManager::destroy(cgroup_path);
        return build_result(SandboxStatus::SANDBOX_ERROR, status, rusage{}, 0, cgroup_path,
                            "Child failed during sandbox setup");
    }
    ::close(ca.ready_pipe[0]);

    // ---- Feed stdin to child ----
    if (!config.stdin_data.empty()) {
        write_all(ca.stdin_pipe[1], config.stdin_data.data(), config.stdin_data.size());
    }
    ::close(ca.stdin_pipe[1]);

    // ---- Arm wall-clock timeout ----
    struct sigaction sa;
    struct sigaction old_sa;
    sa.sa_handler = alarm_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    ::sigaction(SIGALRM, &sa, &old_sa);
    g_wall_timeout = 0;

    unsigned int alarm_sec = static_cast<unsigned int>(
        (config.wall_time_limit_ms + 999) / 1000);
    if (alarm_sec < 1) alarm_sec = 1;
    ::alarm(alarm_sec);

    auto wall_start = std::chrono::steady_clock::now();

    // ---- Wait for child ----
    int wait_status = 0;
    struct rusage rusage;
    std::memset(&rusage, 0, sizeof(rusage));
    pid_t waited = 0;
    bool wall_timeout = false;

    while (true) {
        waited = ::wait4(child_pid, &wait_status, 0, &rusage);
        if (waited == -1) {
            if (errno == EINTR) {
                if (g_wall_timeout) {
                    wall_timeout = true;
                    break;
                }
                continue; // Spurious signal
            }
            // Real error
            break;
        }
        break; // Child reaped
    }

    auto wall_end = std::chrono::steady_clock::now();
    ::alarm(0); // Disarm
    ::sigaction(SIGALRM, &old_sa, nullptr);

    if (wall_timeout) {
        ::kill(child_pid, SIGKILL);
        ::waitpid(child_pid, &wait_status, 0);
    }

    // ---- Read output ----
    std::string stdout_data = read_all(ca.stdout_pipe[0], config.output_limit_bytes);
    std::string stderr_data = read_all(ca.stderr_pipe[0], config.output_limit_bytes);
    ::close(ca.stdout_pipe[0]);
    ::close(ca.stderr_pipe[0]);

    // ---- Compute wall time ----
    std::uint64_t wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(wall_end - wall_start).count());

    // ---- Interpret result ----
    SandboxStatus status;

    if (wall_timeout) {
        status = SandboxStatus::WALL_TIME_EXCEEDED;
    } else if (waited == -1) {
        status = SandboxStatus::SANDBOX_ERROR;
    } else if (WIFEXITED(wait_status)) {
        int code = WEXITSTATUS(wait_status);
        status = (code == 0) ? SandboxStatus::OK : SandboxStatus::NONZERO_EXIT;
        if (code == 127) {
            status = SandboxStatus::RUNTIME_ERROR;
        }
    } else if (WIFSIGNALED(wait_status)) {
        int sig = WTERMSIG(wait_status);
        if (sig == SIGXCPU) {
            status = SandboxStatus::TIME_LIMIT_EXCEEDED;
        } else if (sig == SIGKILL) {
            // wall_timeout case is handled above, so this SIGKILL is from the kernel
            if (!cgroup_path.empty() && CgroupManager::was_oom_killed(cgroup_path)) {
                status = SandboxStatus::MEMORY_LIMIT_EXCEEDED;
            } else {
                // Kernel SIGKILL without OOM => RLIMIT_CPU hard limit reached
                status = SandboxStatus::TIME_LIMIT_EXCEEDED;
            }
        } else if (sig == SIGXFSZ) {
            status = SandboxStatus::OUTPUT_LIMIT_EXCEEDED;
        } else {
            status = SandboxStatus::SIGNALED;
        }
    } else {
        status = SandboxStatus::RUNTIME_ERROR;
    }

    SandboxResult result = build_result(status, wait_status, rusage, wall_ms, cgroup_path);
    result.stdout_data = std::move(stdout_data);
    result.stderr_data = std::move(stderr_data);

    // ---- Cleanup ----
    ::munmap(stack, STACK_SIZE);
    CgroupManager::destroy(cgroup_path);

    // Remove chroot directory
    {
        std::string cmd = "rm -rf " + chroot_dir;
        (void)!::system(cmd.c_str());
    }

    return result;
}

} // namespace onlinejudge
