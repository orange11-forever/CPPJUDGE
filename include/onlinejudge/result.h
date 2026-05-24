#pragma once

#include <cstdint>
#include <string>

namespace onlinejudge {

enum class SandboxStatus {
    OK = 0,
    NONZERO_EXIT,
    SIGNALED,
    TIME_LIMIT_EXCEEDED,
    WALL_TIME_EXCEEDED,
    MEMORY_LIMIT_EXCEEDED,
    OUTPUT_LIMIT_EXCEEDED,
    RUNTIME_ERROR,
    SANDBOX_ERROR,
};

struct SandboxResult {
    SandboxStatus status;
    int exit_code = 0;
    int signal_number = 0;
    std::uint64_t cpu_time_ms = 0;
    std::uint64_t wall_time_ms = 0;
    std::uint64_t peak_memory_kb = 0;
    std::string stdout_data;
    std::string stderr_data;
    std::string error_msg;
};

const char* status_to_string(SandboxStatus status);

} // namespace onlinejudge
