#pragma once

#include <stdexcept>
#include <string>

// Keys:   protocol  src  dst  host  port  srcport  dstport
// Rules:  same key twice is OR, diff keys mean AND.
namespace filter {

struct FilterError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string to_bpf(const std::string& text);

} 