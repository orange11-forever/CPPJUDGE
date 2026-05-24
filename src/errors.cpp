#include "onlinejudge/errors.h"

#include <mutex>

namespace onlinejudge {

static std::mutex g_error_mutex;
static thread_local std::string g_error_msg;

void set_error_context(std::string msg) {
    g_error_msg = std::move(msg);
}

std::string get_error_context() {
    return g_error_msg;
}

void clear_error_context() {
    g_error_msg.clear();
}

} // namespace onlinejudge
