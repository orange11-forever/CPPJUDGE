#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace onlinejudge {

struct SandboxConfig {
    std::string executable_path;
    std::vector<std::string> argv;
    std::vector<std::string> envp;

    std::uint64_t time_limit_ms = 1000;
    std::uint64_t wall_time_limit_ms = 5000;
    std::uint64_t memory_limit_kb = 256 * 1024;
    std::uint64_t output_limit_bytes = 10 * 1024 * 1024;
    std::size_t max_processes = 1;
    std::size_t max_files = 16;

    std::string stdin_data;
    bool redirect_stdout = true;
    bool redirect_stderr = true;

    std::string work_dir = "/";

    bool enable_seccomp = true;

    bool validate(std::string* err_msg = nullptr) const;
};

} // namespace onlinejudge
