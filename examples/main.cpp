#include "onlinejudge/sandbox.h"
#include "onlinejudge/config.h"
#include "onlinejudge/result.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <getopt.h>
#include <unistd.h>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << R"( [options] <executable> [args...]

Options:
  --time-limit <ms>        CPU time limit in ms (default: 1000)
  --wall-time <ms>         Wall-clock time limit in ms (default: 5000)
  --memory-limit <kb>      Memory limit in KB (default: 262144)
  --output-limit <bytes>   Output size limit in bytes (default: 10485760)
  --stdin <file>           Read stdin from file
  --stdin-data <string>    Provide stdin data directly
  --no-seccomp             Disable seccomp syscall filter
  --env <KEY=VALUE>        Set environment variable (repeatable)
  -h, --help               Show this help
)";
}

int main(int argc, char* argv[]) {
    onlinejudge::SandboxConfig config;

    // Parse known options
    static struct option long_opts[] = {
        {"time-limit",   required_argument, nullptr, 't'},
        {"wall-time",    required_argument, nullptr, 'w'},
        {"memory-limit", required_argument, nullptr, 'm'},
        {"output-limit", required_argument, nullptr, 'o'},
        {"stdin",        required_argument, nullptr, 'i'},
        {"stdin-data",   required_argument, nullptr, 'd'},
        {"no-seccomp",   no_argument,       nullptr, 's'},
        {"env",          required_argument, nullptr, 'e'},
        {"help",         no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 't':
            config.time_limit_ms = static_cast<std::uint64_t>(std::atoll(optarg));
            break;
        case 'w':
            config.wall_time_limit_ms = static_cast<std::uint64_t>(std::atoll(optarg));
            break;
        case 'm':
            config.memory_limit_kb = static_cast<std::uint64_t>(std::atoll(optarg));
            break;
        case 'o':
            config.output_limit_bytes = static_cast<std::uint64_t>(std::atoll(optarg));
            break;
        case 'i': {
            std::ifstream f(optarg, std::ios::binary);
            if (!f.is_open()) {
                std::cerr << "Error: cannot open stdin file: " << optarg << std::endl;
                return 1;
            }
            std::string data((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
            config.stdin_data = std::move(data);
            break;
        }
        case 'd':
            config.stdin_data = optarg;
            break;
        case 's':
            config.enable_seccomp = false;
            break;
        case 'e':
            config.envp.push_back(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: no executable specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    config.executable_path = argv[optind];
    for (int i = optind; i < argc; ++i) {
        config.argv.push_back(argv[i]);
    }

    // Default environment: minimal
    if (config.envp.empty()) {
        config.envp.push_back("PATH=/usr/bin:/bin");
        config.envp.push_back("HOME=/");
        config.envp.push_back("USER=sandbox");
    }

    auto result = onlinejudge::Sandbox::run(config);

    std::cout << "Status:       " << onlinejudge::status_to_string(result.status) << std::endl;
    std::cout << "Exit code:    " << result.exit_code << std::endl;
    std::cout << "Signal:       " << result.signal_number << std::endl;
    std::cout << "CPU time:     " << result.cpu_time_ms << " ms" << std::endl;
    std::cout << "Wall time:    " << result.wall_time_ms << " ms" << std::endl;
    std::cout << "Peak memory:  " << result.peak_memory_kb << " KB" << std::endl;

    if (!result.stdout_data.empty()) {
        std::cout << "--- stdout ---" << std::endl;
        std::cout << result.stdout_data;
        if (result.stdout_data.back() != '\n') std::cout << std::endl;
    }

    if (!result.stderr_data.empty()) {
        std::cout << "--- stderr ---" << std::endl;
        std::cout << result.stderr_data;
        if (result.stderr_data.back() != '\n') std::cout << std::endl;
    }

    if (!result.error_msg.empty()) {
        std::cout << "Error:        " << result.error_msg << std::endl;
    }

    return (result.status == onlinejudge::SandboxStatus::OK) ? 0 : 1;
}
