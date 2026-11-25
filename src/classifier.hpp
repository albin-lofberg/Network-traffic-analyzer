#pragma once

#include <cstddef>
#include <cstdint>

#include "decoder.hpp"

namespace classifier {

enum class App { Unknown, Http, Tls, Dns, Ssh };

enum class Basis {
    None,    
    Payload,  
    Port,     
};

struct Result {
    App app = App::Unknown;
    Basis basis = Basis::None;
};

const char* app_name(App app);    
const char* basis_name(Basis b);  

Result classify(const decoder::Packet& p, const std::uint8_t* data, std::size_t caplen);

}