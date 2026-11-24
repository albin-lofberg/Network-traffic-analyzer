#pragma once

#include <cstddef>
#include <cstdint>
#include <string>


namespace decoder {
    const int LinkEthernet = 1;    
    const int LinkLinuxSll = 113;   
    const int LinkLinuxSll2 = 276;

    enum class Status {
        Ok,           
        Truncated,   
        Malformed,    
        Unsupported,  
    };

    struct Packet {
        Status status = Status::Ok;
        const char* decode_fail_reason = "";

        std::uint16_t ether_type = 0;

        // IPv4 
        std::string src_ip;
        std::string dst_ip;
        std::uint8_t ip_protocol = 0;  // 6 = TCP, 17 = UDP, 1 = ICMP, ...
        bool fragment = false;         

        // TCP / UDP
        bool has_ports = false;
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;
        std::uint8_t tcp_flags = 0;
        std::size_t payload_length = 0;

        // ICMP
        std::uint8_t icmp_type = 0;
        std::uint8_t icmp_code = 0;
    };

    Packet decode(int link_type, const std::uint8_t* data, std::size_t caplen);

    std::string describe(const Packet& p);
}