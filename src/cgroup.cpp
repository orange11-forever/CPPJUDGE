#include "onlinejudge/cgroup.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace onlinejudge {

static const std::string CGROUP_ROOT = "/sys/fs/cgroup";

static bool write_to_file(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    return f.good();
}

static std::string read_from_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string content;
    std::getline(f, content);
    return content;
}

static std::string find_delegated_cgroup() {
    // Try user.slice/user-UID.slice (systemd-managed cgroups v2)
    std::string user_slice = CGROUP_ROOT + "/user.slice/user-" +
                             std::to_string(getuid()) + ".slice";

    struct stat st;
    if (stat(user_slice.c_str(), &st) == 0 && S_ISDIR(st.st_mode) &&
        access((user_slice + "/cgroup.procs").c_str(), W_OK) == 0) {
        return user_slice;
    }

    // Fallback: check if we can write to the root cgroup directly
    if (access((CGROUP_ROOT + "/cgroup.procs").c_str(), W_OK) == 0) {
        return CGROUP_ROOT;
    }

    return "";
}

std::string CgroupManager::create(const std::string& name) {
    std::string parent = find_delegated_cgroup();
    if (parent.empty()) return "";

    std::string path = parent + "/" + name;
    if (mkdir(path.c_str(), 0755) == -1) {
        return (errno == EEXIST) ? path : "";
    }
    return path;
}

bool CgroupManager::attach(const std::string& cgroup_path, pid_t pid) {
    return write_to_file(cgroup_path + "/cgroup.procs", std::to_string(pid));
}

bool CgroupManager::set_memory_limit(const std::string& cgroup_path, std::uint64_t limit_kb) {
    std::string limit_str = std::to_string(limit_kb * 1024); // Convert KB to bytes
    bool ok = write_to_file(cgroup_path + "/memory.max", limit_str);
    ok = write_to_file(cgroup_path + "/memory.high", limit_str) && ok;
    return ok;
}

bool CgroupManager::set_pid_limit(const std::string& cgroup_path, std::uint32_t max_pids) {
    return write_to_file(cgroup_path + "/pids.max", std::to_string(max_pids));
}

std::uint64_t CgroupManager::read_memory_peak(const std::string& cgroup_path) {
    std::string val = read_from_file(cgroup_path + "/memory.peak");
    if (val.empty()) return 0;
    // memory.peak reports in bytes
    try {
        return std::stoull(val) / 1024;
    } catch (...) {
        return 0;
    }
}

bool CgroupManager::was_oom_killed(const std::string& cgroup_path) {
    std::string events = read_from_file(cgroup_path + "/memory.events");
    if (events.empty()) return false;

    // Parse memory.events looking for "oom_kill <count>"
    std::istringstream ss(events);
    std::string key;
    std::uint64_t value;
    while (ss >> key >> value) {
        if (key == "oom_kill" && value > 0) {
            return true;
        }
    }
    return false;
}

void CgroupManager::destroy(const std::string& cgroup_path) {
    if (cgroup_path.empty()) return;
    // Kill all processes in the cgroup first
    write_to_file(cgroup_path + "/cgroup.kill", "1");
    rmdir(cgroup_path.c_str());
}

} // namespace onlinejudge
