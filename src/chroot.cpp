#include "onlinejudge/chroot.h"
#include "onlinejudge/config.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace onlinejudge {

static bool copy_file(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in.is_open()) return false;

    std::ofstream out(dst, std::ios::binary);
    if (!out.is_open()) return false;

    out << in.rdbuf();
    return out.good();
}

static bool create_directory(const std::string& path, mode_t mode) {
    if (mkdir(path.c_str(), mode) == -1) {
        return errno == EEXIST;
    }
    return true;
}

bool ChrootBuilder::build(const std::string& target_dir, const SandboxConfig& config) {
    // Create target directory structure
    if (!create_directory(target_dir, 0755)) return false;

    std::string dev_dir = target_dir + "/dev";
    if (!create_directory(dev_dir, 0755)) return false;

    std::string proc_dir = target_dir + "/proc";
    if (!create_directory(proc_dir, 0755)) return false;

    // Device nodes are created by the child after chroot (it has CAP_MKNOD in the namespace).
    // The parent cannot create them without root.

    // Copy the executable into the jail
    std::string jailed_exe = target_dir + "/executable";
    if (!copy_file(config.executable_path, jailed_exe)) return false;
    if (chmod(jailed_exe.c_str(), 0755) == -1) return false;

    return true;
}

const char* ChrootBuilder::jailed_executable_name() {
    return "/executable";
}

} // namespace onlinejudge
