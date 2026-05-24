#pragma once

#include <string>

namespace onlinejudge {

struct SandboxConfig;

class ChrootBuilder {
public:
    static bool build(const std::string& target_dir, const SandboxConfig& config);
    static const char* jailed_executable_name();
};

} // namespace onlinejudge
