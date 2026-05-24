#include "onlinejudge/config.h"

#include <cerrno>
#include <cstring>
#include <string>
#include <unistd.h>

namespace onlinejudge {

bool SandboxConfig::validate(std::string* err_msg) const {
    if (executable_path.empty()) {
        if (err_msg) *err_msg = "executable_path is empty";
        return false;
    }

    if (::access(executable_path.c_str(), X_OK) != 0) {
        if (err_msg) *err_msg = "cannot access executable: " + std::string(::strerror(errno));
        return false;
    }

    if (argv.empty()) {
        if (err_msg) *err_msg = "argv is empty";
        return false;
    }

    if (time_limit_ms == 0) {
        if (err_msg) *err_msg = "time_limit_ms must be > 0";
        return false;
    }

    if (wall_time_limit_ms == 0) {
        if (err_msg) *err_msg = "wall_time_limit_ms must be > 0";
        return false;
    }

    if (memory_limit_kb == 0) {
        if (err_msg) *err_msg = "memory_limit_kb must be > 0";
        return false;
    }

    if (output_limit_bytes == 0) {
        if (err_msg) *err_msg = "output_limit_bytes must be > 0";
        return false;
    }

    if (max_processes == 0) {
        if (err_msg) *err_msg = "max_processes must be > 0";
        return false;
    }

    return true;
}

} // namespace onlinejudge
