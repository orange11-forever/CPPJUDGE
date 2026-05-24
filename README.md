# CPPJUDGE — 高性能 C++ 沙箱判题机

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Linux](https://img.shields.io/badge/Linux-5.0%2B-orange.svg)](https://kernel.org)
CPPJUDGE 是一个基于 Linux 内核特性的高性能沙箱判题机。通过 namespace 隔离、cgroups 资源控制、chroot 文件系统隔离和 seccomp 系统调用过滤，为不可信代码提供安全的执行环境。适用于 OJ（Online Judge）系统、代码评测平台和自动化测试场景。

## 特性

- **网络隔离** — `CLONE_NEWNET` 创建独立网络命名空间，无任何网络设备，`seccomp` 拦截 `socket` / `connect` 等网络系统调用
- **文件系统隔离** — `CLONE_NEWNS` + `chroot` 构建最小化 jail，仅包含可执行文件和 `/dev` 设备节点
- **进程隔离** — `CLONE_NEWPID` + `CLONE_NEWIPC` + `CLONE_NEWUTS` 创建独立 PID/IPC/主机名空间
- **权限隔离** — `CLONE_NEWUSER` 实现非 root 运行，子进程在命名空间内为 root 但无宿主实际权限
- **CPU 时间限制** — `RLIMIT_CPU` + `SIGALRM` 双重监控，软硬限分离
- **内存限制** — cgroups v2 `memory.max` / `memory.high` 精确控制，`RLIMIT_AS` 作为回退方案
- **输出大小限制** — 父进程对 stdout/stderr 管道进行截断读取
- **系统调用过滤** — 原始 BPF 白名单（~120 个安全系统调用），无外部依赖，架构校验防 32 位绕过
- **零依赖** — 纯 C++17 + Linux 内核 API，无需 `libseccomp`、`boost` 或任何第三方库

## 架构

```
                    ┌───────────────────────────────────────────────┐
                    │                  Parent Process                │
                    │                                               │
  SandboxConfig ──► │  Sandbox::run()                               │
                    │    │                                          │
                    │    ├─ 1. Validate config                      │
                    │    ├─ 2. Create cgroup                        │
                    │    ├─ 3. Build chroot jail (/tmp/oj-sandbox-*)│
                    │    ├─ 4. Create pipes (sync, ready, stdio)    │
                    │    ├─ 5. clone() with 6 namespace flags       │
                    │    │                                          │
                    │    │   ┌─────────────────────────────────┐    │
                    │    │   │       Child Process              │    │
                    │    │   │  (NEWUSER|NEWNET|NEWPID|         │    │
                    │    │   │   NEWIPC|NEWUTS|NEWNS)          │    │
                    │    │   │                                  │    │
                    │    │   │  a. Wait for parent sync         │    │
                    │    │   │  b. setuid(0) / setgid(0)        │    │
                    │    │   │  c. chroot() + mount /proc       │    │
                    │    │   │  d. setrlimit() × 6              │    │
                    │    │   │  e. Install seccomp BPF filter   │    │
                    │    │   │  f. Redirect stdio to pipes      │    │
                    │    │   │  g. signal parent "ready"         │    │
                    │    │   │  h. execve(target)               │    │
                    │    │   └─────────────────────────────────┘    │
                    │    │                                          │
                    │    ├─ 6. Write uid_map / gid_map              │
                    │    ├─ 7. Attach child to cgroup               │
                    │    ├─ 8. Signal child to proceed              │
                    │    ├─ 9. Send stdin data                      │
                    │    ├─ 10. wait4() with SIGALRM timeout        │
                    │    ├─ 11. Read stdout/stderr (capped)         │
                    │    ├─ 12. Interpret exit status               │
                    │    └─ 13. Cleanup (cgroup, chroot dir)        │
                    │                                               │
                    └───────────────┬───────────────────────────────┘
                                    │
                                    ▼
                              SandboxResult
```

## 需求

- Linux 5.0+（推荐 5.9+，以支持 `close_range`）
- x86_64 架构
- GCC 9+ 或 Clang 10+（需支持 C++17）
- 内核需启用 user namespace：`kernel.unprivileged_userns_clone=1`
- cgroups v2 挂载于 `/sys/fs/cgroup`（可选，用于精确内存控制）

## 构建

```bash
# 直接编译（无需 CMake）
g++ -std=c++17 -O2 -I include \
  src/errors.cpp src/result.cpp src/config.cpp \
  src/seccomp.cpp src/cgroup.cpp src/chroot.cpp \
  src/sandbox.cpp examples/main.cpp \
  -lpthread -o build/simple_judge

# 或使用 CMake
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## 使用

### 命令行

```bash
./build/simple_judge [选项] <可执行文件> [程序参数...]
```

#### 选项

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `--time-limit <ms>` | uint64 | 1000 | CPU 时间限制（毫秒） |
| `--wall-time <ms>` | uint64 | 5000 | 墙钟时间限制（毫秒） |
| `--memory-limit <kb>` | uint64 | 262144 | 内存限制（KB），默认 256 MB |
| `--output-limit <bytes>` | uint64 | 10485760 | 输出大小限制（字节），默认 10 MB |
| `--stdin <file>` | string | — | 从文件读取标准输入 |
| `--stdin-data <string>` | string | — | 直接提供标准输入数据 |
| `--no-seccomp` | flag | false | 禁用 seccomp 系统调用过滤 |
| `--env KEY=VALUE` | string | — | 设置环境变量（可重复） |

#### 示例

```bash
# 基础评测
./build/simple_judge --time-limit 1000 --memory-limit 131072 /tmp/user_program

# 带输入数据
./build/simple_judge --stdin-data "42 100" /tmp/user_program

# 严格限制输出
./build/simple_judge --output-limit 1024 /tmp/user_program

# 从文件读取标准输入
./build/simple_judge --stdin ./testcases/input1.txt /tmp/user_program

# 自定义环境变量
./build/simple_judge --env "PATH=/usr/bin" --env "LANG=C" /tmp/user_program
```

**注意**：被评测程序建议**静态链接**编译（`gcc -static`），因为 chroot jail 中无动态链接器。如需支持动态链接，需将 `ld.so` 和依赖的 `.so` 文件复制到 jail 中。

### C++ API

```cpp
#include "onlinejudge/sandbox.h"
#include "onlinejudge/config.h"
#include "onlinejudge/result.h"

onlinejudge::SandboxConfig config;
config.executable_path   = "/path/to/user_program";
config.argv              = {"./prog", "arg1", "arg2"};
config.time_limit_ms     = 1000;
config.memory_limit_kb   = 256 * 1024; // 256 MB
config.wall_time_limit_ms = 5000;
config.output_limit_bytes = 10 * 1024 * 1024; // 10 MB
config.stdin_data        = "42 100\n";
config.enable_seccomp    = true;

auto result = onlinejudge::Sandbox::run(config);

if (result.status == onlinejudge::SandboxStatus::OK) {
    std::cout << "Accepted!" << std::endl;
    std::cout << result.stdout_data;
} else {
    std::cout << onlinejudge::status_to_string(result.status) << std::endl;
}
```

## API 参考

### SandboxConfig

评测配置结构体。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `executable_path` | `string` | — | **(必需)** 宿主机上可执行文件路径 |
| `argv` | `vector<string>` | — | **(必需)** 命令行参数，argv[0] 为程序名 |
| `envp` | `vector<string>` | 最小环境 | 环境变量，空则提供默认 PATH/HOME/USER |
| `time_limit_ms` | `uint64_t` | 1000 | CPU 时间软限制（毫秒） |
| `wall_time_limit_ms` | `uint64_t` | 5000 | 墙钟时间总限制（毫秒） |
| `memory_limit_kb` | `uint64_t` | 262144 | 内存限制（KB） |
| `output_limit_bytes` | `uint64_t` | 10485760 | stdout+stderr 输出上限（字节） |
| `max_processes` | `size_t` | 1 | 允许的最大进程/线程数 |
| `max_files` | `size_t` | 16 | 允许的最大打开文件数 |
| `stdin_data` | `string` | "" | 标准输入数据 |
| `redirect_stdout` | `bool` | true | 是否捕获标准输出 |
| `redirect_stderr` | `bool` | true | 是否捕获标准错误 |
| `enable_seccomp` | `bool` | true | 是否启用 seccomp 系统调用过滤 |
| `validate()` | 方法 | — | 返回 false 并设置 err_msg |

### SandboxResult

评测结果结构体。

| 字段 | 类型 | 说明 |
|---|---|---|
| `status` | `SandboxStatus` | 评测状态（见下方枚举） |
| `exit_code` | `int` | 进程退出码（仅 `OK`/`NONZERO_EXIT` 有效） |
| `signal_number` | `int` | 终止信号（仅 `SIGNALED` 有效） |
| `cpu_time_ms` | `uint64_t` | 用户态+内核态 CPU 时间 |
| `wall_time_ms` | `uint64_t` | 墙钟运行时间 |
| `peak_memory_kb` | `uint64_t` | 峰值内存（cgroups 可用时） |
| `stdout_data` | `string` | 捕获的标准输出 |
| `stderr_data` | `string` | 捕获的标准错误 |
| `error_msg` | `string` | 错误描述（仅 `SANDBOX_ERROR` 有效） |

### SandboxStatus

| 枚举值 | 含义 |
|---|---|
| `OK` | 正常退出，exit_code = 0 |
| `NONZERO_EXIT` | 正常退出，exit_code ≠ 0 |
| `SIGNALED` | 被信号终止（如 SIGSEGV(11)、SIGSYS(31)） |
| `TIME_LIMIT_EXCEEDED` | CPU 时间超限 |
| `WALL_TIME_EXCEEDED` | 墙钟时间超限 |
| `MEMORY_LIMIT_EXCEEDED` | 内存超限 |
| `OUTPUT_LIMIT_EXCEEDED` | 输出大小超限 |
| `RUNTIME_ERROR` | 运行时错误（exec 失败等） |
| `SANDBOX_ERROR` | 沙箱自身错误（配置无效、权限不足等） |

## 安全模型

### 多层防御

```
┌─────────────────────────────────────────┐
│              第 1 层：Namespace 隔离      │
│  NEWUSER │ NEWNET │ NEWPID │ NEWIPC │ NEWUTS │ NEWNS
├─────────────────────────────────────────┤
│              第 2 层：文件系统隔离         │
│  chroot 到最小 jail → 无宿主文件系统访问   │
├─────────────────────────────────────────┤
│              第 3 层：资源限制            │
│  RLIMIT_CPU │ RLIMIT_AS │ RLIMIT_FSIZE    │
│  RLIMIT_NPROC │ RLIMIT_NOFILE             │
│  cgroups v2: memory.max │ pids.max        │
├─────────────────────────────────────────┤
│              第 4 层：系统调用过滤         │
│  seccomp BPF 白名单 (~120 syscall)        │
│  架构校验 (x86-64 only)                   │
│  禁止: socket │ clone │ mount │ kill ... │
└─────────────────────────────────────────┘
```

### Seccomp 白名单策略

采用**最小权限原则**，仅允许 ~120 个安全系统调用，包括：

- **文件 I/O**：read, write, open, openat, close, pread64, pwrite64, readv, writev, lseek, truncate, ftruncate, sync, fsync, fdatasync, syncfs, copy_file_range, sendfile, splice, vmsplice, tee, readahead, fadvise64, sync_file_range
- **文件元数据**：stat, fstat, lstat, newfstatat, statx, getdents, getdents64, readlink, readlinkat, getcwd, access, faccessat, faccessat2, statfs, fstatfs, umask
- **目录操作**：chdir, mkdir, rmdir, rename, link, unlink, symlink, mknod
- **文件描述符**：dup, dup2, dup3, fcntl, flock, pipe, pipe2, close_range
- **内存管理**：mmap, mprotect, munmap, brk, mremap, mincore, madvise, msync, mlock, munlock, mlockall, munlockall, mlock2, mbind, set_mempolicy, get_mempolicy, migrate_pages, move_pages, pkey_mprotect, pkey_alloc, pkey_free, memfd_create
- **线程/同步**：futex, futex_waitv, futex_wake, futex_wait, futex_requeue, set_tid_address, set_robust_list, get_robust_list, rseq, membarrier, getcpu
- **信号**：rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, rt_sigpending, rt_sigtimedwait, rt_sigsuspend, signalfd, signalfd4
- **时间**：gettimeofday, time, clock_gettime, clock_getres, clock_nanosleep, nanosleep, timer_create, timer_delete, timerfd_create, timerfd_settime, timerfd_gettime, times
- **进程标识**：getpid, gettid, getppid, getpgid, getuid, geteuid, getgid, getegid, getresuid, getresgid, getgroups, capget
- **调度**：sched_yield, sched_getaffinity, sched_setaffinity, sched_getattr, sched_setattr, sched_getparam, sched_getscheduler
- **事件通知**：poll, select, ppoll, pselect6, epoll_create, epoll_create1, epoll_ctl, epoll_wait, epoll_pwait, epoll_pwait2, eventfd, eventfd2
- **资源限制**：getrlimit, setrlimit, prlimit64, getrusage, sysinfo
- **其他**：ioctl, uname, getrandom, arch_prctl, exit, exit_group, execve, wait4, waitid, inotify_init, inotify_init1, inotify_add_watch, inotify_rm_watch

**被明确拦截的危险系统调用**：

- **网络**：socket, connect, accept, bind, listen, sendto, recvfrom, sendmsg, recvmsg 等全部 17 个
- **进程创建**：clone, fork, vfork, clone3, execveat
- **进程控制**：kill, tkill, tgkill, ptrace
- **权限提升**：setuid, setgid, setresuid, setresgid, setfsuid, setfsgid, capset, setgroups
- **命名空间操控**：unshare, setns
- **文件系统操控**：mount, umount2, pivot_root, chroot
- **内核模块**：init_module, delete_module, finit_module
- **其他危险操作**：reboot, kexec_load, kexec_file_load, iopl, ioperm, bpf, seccomp, perf_event_open, userfaultfd, add_key, request_key, keyctl

## 项目结构

```
CPPJUDGE/
├── CMakeLists.txt
├── .gitignore
├── README.md
├── include/
│   └── onlinejudge/
│       ├── sandbox.h        # Sandbox::run() 静态入口
│       ├── config.h         # SandboxConfig 配置结构
│       ├── result.h         # SandboxResult + SandboxStatus 枚举
│       ├── cgroup.h         # CgroupManager cgroups v2 管理
│       ├── chroot.h         # ChrootBuilder jail 构建器
│       ├── seccomp.h        # SeccompFilter BPF 过滤器
│       └── errors.h         # 错误上下文工具
├── src/
│   ├── sandbox.cpp          # 核心沙箱生命周期（clone/wait/pipe/result）
│   ├── seccomp.cpp          # 原始 BPF 过滤器（无 libseccomp 依赖）
│   ├── cgroup.cpp           # cgroups v2 资源控制
│   ├── chroot.cpp           # chroot jail 构建
│   ├── config.cpp           # SandboxConfig::validate()
│   ├── result.cpp           # status_to_string()
│   └── errors.cpp           # 线程局部错误上下文
└── examples/
    └── main.cpp             # CLI 命令行工具
```

## 测试

### 自动测试（推荐）

项目内置自动化测试套件，覆盖全部 8 种沙箱状态：

```bash
# 方式 1：CMake + CTest
mkdir build && cd build
cmake .. -DBUILD_TESTING=ON
make -j$(nproc)
ctest --output-on-failure

# 方式 2：独立脚本（无需 CMake，需 gcc）
./tests/run_tests.sh
```

测试用例：

| 用例 | 程序 | 预期状态 |
|---|---|---|
| Normal exit 0 | `tests/ok.c` | OK |
| Non-zero exit | `tests/nonzero_exit.c` | NONZERO_EXIT |
| Segfault | `tests/segfault.c` | SIGNALED |
| TLE (死循环) | `tests/tle.c` | TIME_LIMIT_EXCEEDED |
| MLE (128MB 申请) | `tests/mle.c` | MEMORY_LIMIT_EXCEEDED |
| OLE (大量输出) | `tests/ole.c` | OUTPUT_LIMIT_EXCEEDED |
| Seccomp 拦截 | `tests/seccomp_violation.c` | SIGNALED |
| Wall-time 超限 | `tests/ok.c` + 极短墙钟 | WALL_TIME_EXCEEDED |

### 手动测试

```bash
# 编译测试程序
gcc -static -o /tmp/test_hello test.c

# 基础功能测试
./build/simple_judge --time-limit 1000 --memory-limit 131072 /tmp/test_hello

## 已知限制

1. **RLIMIT_CPU 粒度为秒级** — 内核 `RLIMIT_CPU` 以秒为单位，子秒 CPU 时间限制需配合墙钟时间使用
2. **动态链接程序** — chroot jail 中无动态链接器，被评测程序需静态编译（`gcc -static`）或手动将 `ld.so` / `libc.so` 复制到 jail
3. **cgroups v2 权限** — 非 root 用户需 cgroup 委托（systemd `Delegate=yes`），否则回退到 `RLIMIT_AS`
4. **管道缓冲区** — stdout/stderr 写入超过 `PIPE_BUF`（默认 64KB）会阻塞子进程，依赖墙钟时间超时终止
5. **x86_64 only** — seccomp 过滤器包含架构白名单（`AUDIT_ARCH_X86_64`），不支持 ARM/AArch64

---

**CPPJUDGE** — 安全、高效、零依赖的 C++ 沙箱判题核心。
