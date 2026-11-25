#include "decoder.hpp"

#include <arpa/inet.h>
#include <cstdio>

namespace decoder {

    namespace {

    struct Bytes {
        const std::uint8_t* data;
        std::size_t size;

       
        bool in_bounds(std::size_t offset, std::size_t length) const {
            return offset <= size && length <= size - offset;
        }
        
        // Returns single byte
        std::uint8_t u8(std::size_t offset) const
        { 
            return data[offset]; 
        }

        // Reads two bytes and returns as single number
        std::uint16_t u16(std::size_t offset) const {    
            const std::uint16_t big_end = data[offset] << 8;      
            const std::uint16_t little_end = data[offset + 1];           // 0x00bb
            return big_end | little_end;
        }
    };

    Packet fail(Packet p, Status status, const char* reason) {
        p.status = status;
        p.decode_fail_reason = reason;
        return p;
    }

    const std::uint16_t EtherIpv4 = 0x0800;
    const std::uint16_t EtherIpv6 = 0x86DD;
    const std::uint16_t EtherVlan = 0x8100;


    bool parse_link(int link_type, const Bytes& b, Packet& p,
        std::size_t& ip_offset, Status& why, const char*& reason) {
        
        // 4/5 fails are truncated, so set here. If no fail, why isn't
        // used so no need to change it to OK
        why = Status::Truncated;
        
        switch (link_type) {
        case LinkEthernet:
            if (!b.in_bounds(0, 14)) {
                reason = "Too short ethernet header";
                return false;
            }

            p.ether_type = b.u16(12);
            ip_offset = 14;

            if (p.ether_type == EtherVlan) { 
                if (!b.in_bounds(0, 18)) { 
                    reason = "vlan tag too short"; 
                    return false; 
                }
                p.ether_type = b.u16(16);
                ip_offset = 18;
            }

            return true;

        case LinkLinuxSll:
            if (!b.in_bounds(0, 16)) { 
                reason = "short SLL header"; 
                return false; 
            }
            p.ether_type = b.u16(14);
            ip_offset = 16;
            return true;

        case LinkLinuxSll2:
            if (!b.in_bounds(0, 20)) 
            { 
                reason = "short SLL2 header"; 
                return false; 
            }
            p.ether_type = b.u16(0);
            ip_offset = 20;
            return true;

        default:
            why = Status::Unsupported;
            reason = "unknown link type";
            return false;
        }
    } 

    // parse_ipv4 and parse_ipv6 below parse_transport.

    Packet parse_transport(const Bytes& b, Packet p, std::size_t t_layer, std::size_t t_layer_size) {
        
        if (p.ip_protocol == ProtocolTcp) {

            if (!b.in_bounds(t_layer, 20)) {
                return fail(p, Status::Truncated, "short TCP header");
            }

            const int tcp_words = b.u8(t_layer + 12) >> 4;
            const std::size_t tcp_len = static_cast<std::size_t>(tcp_words) * 4;
            
            if (tcp_len < 20){
                return fail(p, Status::Malformed, "TCP header length below 20");
            }    
            if (tcp_len > t_layer_size){
                return fail(p, Status::Malformed, "TCP header longer than packet");
            } 
            if (!b.in_bounds(t_layer, tcp_len)){
                return fail(p, Status::Truncated, "TCP options cut off");
            }

            p.has_ports = true;
            p.src_port = b.u16(t_layer);
            p.dst_port = b.u16(t_layer + 2);
            p.tcp_flags = b.u8(t_layer + 13);
            p.payload_length = t_layer_size - tcp_len;
            p.payload_offset = t_layer + tcp_len;
            return p;
        }

        if (p.ip_protocol == ProtocolUdp) {

            if (!b.in_bounds(t_layer, 8)) {
                return fail(p, Status::Truncated, "short UDP header");
            }

            const std::size_t udp_len = b.u16(t_layer + 4);
            if (udp_len < 8) {
                return fail(p, Status::Malformed, "UDP length below 8");
            }

            p.has_ports = true;
            p.src_port = b.u16(t_layer);
            p.dst_port = b.u16(t_layer + 2);
            p.payload_length = udp_len - 8;
            p.payload_offset = t_layer + 8;
            return p;
        }

        if (p.ip_protocol == ProtocolIcmp || p.ip_protocol == ProtocolIcmpv6) {
            if (!b.in_bounds(t_layer, 2)) {
                return fail(p, Status::Truncated, "short ICMP header");
            }
            p.icmp_type = b.u8(t_layer);
            p.icmp_code = b.u8(t_layer + 1);
            p.payload_length = t_layer_size;
            return p;
        }

        p.payload_length = t_layer_size;  
        return p;
    }

     std::string ipv4_to_string(const Bytes& b, std::size_t offset) {
        char text[16];
        std::snprintf(text, sizeof text, "%u.%u.%u.%u", b.u8(offset), b.u8(offset + 1),
                    b.u8(offset + 2), b.u8(offset + 3));
        return text;
    } 

    std::string ipv6_to_string(const Bytes& b, std::size_t offset) {
        char text[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, b.data + offset, text, sizeof text);  
        return text;
    }

    Packet parse_ipv4(const Bytes& b, Packet p, std::size_t ip_offset) {
        
        if (!b.in_bounds(ip_offset, 20)) {
            return fail(p, Status::Truncated, "short IPv4 header");
        }
        if ((b.u8(ip_offset) >> 4) != 4) {
            return fail(p, Status::Malformed, "IP version is not 4");
        }

        p.ip_version = 4;

        const int ihl_words = b.u8(ip_offset) & 0x0F;
        const std::size_t header_len = ihl_words * 4;
        
        if (header_len < 20) {
            return fail(p, Status::Malformed, "IPv4 header length below 20");
        }
        if (!b.in_bounds(ip_offset, header_len)) {
            return fail(p, Status::Truncated, "IPv4 options cut off");
        }

        const std::size_t total = b.u16(ip_offset + 2);  
        if (total < header_len) {
            return fail(p, Status::Malformed, "IPv4 total length below header length");
        }

        p.ip_protocol = b.u8(ip_offset + 9);
        p.src_ip = ipv4_to_string(b, ip_offset + 12);
        p.dst_ip = ipv4_to_string(b, ip_offset + 16);

        const std::uint16_t frag = b.u16(ip_offset + 6);
        if ((frag & 0x1FFF) != 0) {  // not the first fragment: no transport header here
            p.fragment = true;
            p.payload_length = total - header_len;
            return p;
        }
        return parse_transport(b, p, ip_offset + header_len, total - header_len);
    }

    // Constants extension headers - IPv6
    const std::uint8_t HopByHop = 0;
    const std::uint8_t Routing = 43;
    const std::uint8_t Fragment = 44;
    const std::uint8_t Auth = 51;
    const std::uint8_t DestOptions = 60;
    const int MaxExtHeaders = 8;


    bool is_extension_header(std::uint8_t next_header) {
        return next_header == HopByHop || next_header == Routing 
            || next_header == Fragment || next_header == Auth 
            || next_header == DestOptions;
    }


    Packet parse_ipv6(const Bytes& b, Packet p, std::size_t ip_offset) {
        
        if (!b.in_bounds(ip_offset, 40)) {
            return fail(p, Status::Truncated, "short IPv6 header");
        }
        if ((b.u8(ip_offset) >> 4) != 6) {
            return fail(p, Status::Malformed, "IP version is not 6");
        }

        p.ip_version = 6;

        const std::size_t payload_len = b.u16(ip_offset + 4);  
        std::uint8_t next_header = b.u8(ip_offset + 6);
        p.src_ip = ipv6_to_string(b, ip_offset + 8);
        p.dst_ip = ipv6_to_string(b, ip_offset + 24);

        // Extension header tomfoolery
        std::size_t offset = ip_offset + 40;

        while (is_extension_header(next_header)) {

            if (++p.ext_header_count > MaxExtHeaders) {
                return fail(p, Status::Malformed, "too many IPv6 extension headers");
            }
            
            if (!b.in_bounds(offset, 8)) {
                return fail(p, Status::Truncated, "IPv6 extension header cut off");
            }

            const std::uint8_t this_header = next_header;
            next_header = b.u8(offset);

            const int length_field = b.u8(offset + 1);
            std::size_t ext_hdr_length = 8; 

            if (this_header == Auth) {
                ext_hdr_length = (static_cast<std::size_t>(length_field) + 2) * 4;  // 4-byte units
            } else if (this_header != Fragment) {
                ext_hdr_length = (static_cast<std::size_t>(length_field) + 1) * 8;  // 8-byte units
            }
            if (!b.in_bounds(offset, ext_hdr_length)) {
                return fail(p, Status::Truncated, "IPv6 extension header cut off");
            }

            if (this_header == Fragment && (b.u16(offset + 2) & 0xFFF8) != 0) {
                p.fragment = true; 
            }
            offset += ext_hdr_length;
        }

        const std::size_t skipped = offset - (ip_offset + 40);
        if (skipped > payload_len) {
            return fail(p, Status::Malformed, "IPv6 extension headers longer than payload");
        }

        // while loop went through all ext headers. 
        // Next header now is what comes after the headers (transport protocol)
        p.ip_protocol = next_header;
        const std::size_t t_layer_size = payload_len - skipped;
        if (p.fragment) {
            p.payload_length = t_layer_size;
            return p;
        }
        return parse_transport(b, p, offset, t_layer_size);
    }
    
}

    Packet decode(int link_type, const std::uint8_t* data, std::size_t caplen) {
        const Bytes b{data, caplen};
        Packet p;

        std::size_t ip_offset = 0;
        Status why = Status::Ok;
        const char* reason = "";

        if (!parse_link(link_type, b, p, ip_offset, why, reason)) {
            return fail(p, why, reason);
        }

        if (p.ether_type == EtherIpv4) {
            return parse_ipv4(b, p, ip_offset);
        }
        if (p.ether_type == EtherIpv6) {
            return parse_ipv6(b, p, ip_offset);
        }  

        return fail(p, Status::Unsupported, "not IP");
        
    }
    
    
    std::string describe(const Packet& p) {
        if (p.status != Status::Ok) {
            const char* kind = p.status == Status::Truncated   ? "truncated"
                             : p.status == Status::Malformed ? "malformed"
                             : "unsupported";
            char text[96];
            std::snprintf(text, sizeof text, "[%s] %s (ethertype 0x%04x)", kind, p.decode_fail_reason,
                        static_cast<unsigned>(p.ether_type));
            return text;
        }

        auto endpoint = [&](const std::string& ip, std::uint16_t port) {
            
            if (!p.has_ports) {
                return ip;
            }

            std::string host = ip;
            if (p.ip_version == 6) {
                host = "[" + ip + "]";
            }            
            return host + ":" + std::to_string(port);
        };

        std::string line = endpoint(p.src_ip, p.src_port) + " -> " + endpoint(p.dst_ip, p.dst_port);
        if (p.ext_header_count > 0) {
            line += "  (+" + std::to_string(p.ext_header_count) + " ext)";
        }


        if (p.fragment) return line + "  fragment";

        if (p.ip_protocol == ProtocolTcp) {
            static const struct { 
                std::uint8_t bit; 
                const char* name; 
            } 
            
            kFlags[] = {
            {0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, 
            {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}
            };

            std::string flags;
            for (const auto& f : kFlags) {
                if (p.tcp_flags & f.bit) {
                    flags += (flags.empty() ? "" : ",") + std::string(f.name);
                }
            }
            return line + "  TCP [" + flags + "]  payload=" + std::to_string(p.payload_length);
        }
        if (p.ip_protocol == ProtocolUdp) {
            return line + "  UDP  payload=" + std::to_string(p.payload_length);
        }
        if (p.ip_protocol == ProtocolIcmp || p.ip_protocol == ProtocolIcmpv6) {
            return line + (p.ip_protocol == ProtocolIcmp ? "  ICMP type=" : "  ICMPv6 type=") +
                std::to_string(p.icmp_type) + " code=" + std::to_string(p.icmp_code);
        }
        return line + "  proto=" + std::to_string(p.ip_protocol);
    }

}

