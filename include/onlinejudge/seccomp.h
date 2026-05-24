#pragma once

#include <cstdint>
#include <vector>

namespace onlinejudge {

struct BpfInstruction {
    std::uint16_t code;
    std::uint8_t  jt;
    std::uint8_t  jf;
    std::uint32_t k;
};

class SeccompFilter {
public:
    static std::vector<BpfInstruction> build();
    static void install(const std::vector<BpfInstruction>& filter);
};

} // namespace onlinejudge
