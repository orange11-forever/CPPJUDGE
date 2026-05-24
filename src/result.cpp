#include "onlinejudge/result.h"

namespace onlinejudge {

const char* status_to_string(SandboxStatus status) {
    switch (status) {
    case SandboxStatus::OK:                   return "OK";
    case SandboxStatus::NONZERO_EXIT:         return "NONZERO_EXIT";
    case SandboxStatus::SIGNALED:             return "SIGNALED";
    case SandboxStatus::TIME_LIMIT_EXCEEDED:  return "TIME_LIMIT_EXCEEDED";
    case SandboxStatus::WALL_TIME_EXCEEDED:   return "WALL_TIME_EXCEEDED";
    case SandboxStatus::MEMORY_LIMIT_EXCEEDED: return "MEMORY_LIMIT_EXCEEDED";
    case SandboxStatus::OUTPUT_LIMIT_EXCEEDED: return "OUTPUT_LIMIT_EXCEEDED";
    case SandboxStatus::RUNTIME_ERROR:        return "RUNTIME_ERROR";
    case SandboxStatus::SANDBOX_ERROR:        return "SANDBOX_ERROR";
    }
    return "UNKNOWN";
}

} // namespace onlinejudge
