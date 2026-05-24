#pragma once

#include <string>

namespace onlinejudge {

void set_error_context(std::string msg);
std::string get_error_context();
void clear_error_context();

} // namespace onlinejudge
