#pragma once

#include <cstdint>
#include <string>

namespace onlinejudge {

class CgroupManager {
public:
    static std::string create(const std::string& name);
    static bool attach(const std::string& cgroup_path, pid_t pid);
    static bool set_memory_limit(const std::string& cgroup_path, std::uint64_t limit_kb);
    static bool set_pid_limit(const std::string& cgroup_path, std::uint32_t max_pids);
    static std::uint64_t read_memory_peak(const std::string& cgroup_path);
    static bool was_oom_killed(const std::string& cgroup_path);
    static void destroy(const std::string& cgroup_path);
};

} // namespace onlinejudge
