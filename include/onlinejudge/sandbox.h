#pragma once

#include "onlinejudge/config.h"
#include "onlinejudge/result.h"

namespace onlinejudge {

class Sandbox {
public:
    static SandboxResult run(const SandboxConfig& config);

    Sandbox() = delete;
    ~Sandbox() = delete;
};

} // namespace onlinejudge
