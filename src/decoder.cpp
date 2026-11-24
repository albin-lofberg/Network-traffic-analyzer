#include "decoder.hpp"

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
    
    std::string ipv4_to_string(const Bytes& b, std::size_t offset) {
        char text[16];
        std::snprintf(text, sizeof text, "%u.%u.%u.%u", b.u8(offset), b.u8(offset + 1),
                    b.u8(offset + 2), b.u8(offset + 3));
        return text;
    } 
}

    Packet decode(int link_type, const std::uint8_t* data, std::size_t caplen) {
        Bytes b = {data, caplen};
        Packet p;

        // Ip_offset in parse_link. Modified in parser
        std::size_t ip = 0;
        Status why = Status::Ok;
        const char* reason = "";

        if (!parse_link(link_type, b, p, ip, why, reason)){
            return fail(p, why, reason);
        } 

        // Only have IPv4 implemented right now
        if (p.ether_type != EtherIpv4) {
         return fail(p, Status::Unsupported, "not IPv4");
        }


        // ---- IPv4 ----

        // If capture too small. IP header min of 20 bytes
        if (!b.in_bounds(ip, 20)){
            return fail(p, Status::Truncated, "Truncated IPv4 Header");
        }

        // Shifts first byte four bits to right. Little end falls off, big end left
        if ((b.u8(ip) >> 4) != 4){
            return fail(p, Status::Malformed, "IP version is not 4");
        }

        // takes lower half of first byte
        int ihl_words = b.u8(ip) & 0x0F;
        const std::size_t ihl = static_cast<std::size_t>(ihl_words) * 4;        
        // ihl_words min of 5 -> ihl > 5 * 4 = 20
        if (ihl < 20){
            return fail(p, Status::Malformed, "IPv4 IHL field below 5 (header under 20 bytes)");
        }

        // If capture too small for options
        if (!b.in_bounds(ip, ihl)){
            return fail(p, Status::Truncated, "IPv4 options cut off");
        }

        const std::size_t total = b.u16(ip + 2);
        if (total < ihl){
            return fail(p, Status::Malformed, "Total length below IPv4 header length");
        }

        p.ip_protocol = b.u8(ip + 9);
        p.src_ip = ipv4_to_string(b, ip + 12);
        p.dst_ip = ipv4_to_string(b, ip + 16);

        const std::uint16_t frag = b.u16(ip + 6);
        // Highest 3 bits are flags, rest offset
        if ((frag & 0x1FFF) != 0) {  
            p.fragment = true;
            p.payload_length = total - ihl;
            return p;
        }

        const std::size_t t_layer = ip + ihl;           
        const std::size_t t_layer_size = total - ihl;   
        // ---- TCP ----
        if (p.ip_protocol == 6) {
            if (!b.in_bounds(t_layer, 20)){
                return fail(p, Status::Truncated, "short TCP header");
            }

            int tcp_words = b.u8(t_layer + 12) >> 4;
            const std::size_t tcp_len = static_cast<std::size_t>(tcp_words) * 4;
            
            if (tcp_len < 20){
                return fail(p, Status::Malformed, "TCP header length below 20");
            }
            if (tcp_len > t_layer_size) {
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
            return p;
        }

        // ---- UDP ----
        if (p.ip_protocol == 17) {

            if (!b.in_bounds(t_layer, 8)) {
                return fail(p, Status::Truncated, "short UDP header");
            }
            const std::size_t udp_len = b.u16(t_layer + 4);
            if (udp_len < 8){
                return fail(p, Status::Malformed, "UDP length below 8");
            }
            p.has_ports = true;
            p.src_port = b.u16(t_layer);
            p.dst_port = b.u16(t_layer + 2);
            p.payload_length = udp_len - 8;
            return p;
        }

        // ---- ICMP ----
        if (p.ip_protocol == 1) {
            
            if (!b.in_bounds(t_layer, 2)){
                return fail(p, Status::Truncated, "short ICMP header");
            }
            p.icmp_type = b.u8(t_layer);
            p.icmp_code = b.u8(t_layer + 1);
            p.payload_length = t_layer_size;
            return p;
        }

        // If not TCP, UDP or ICMP
        p.payload_length = t_layer_size; 
        return p;
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

        std::string line = p.src_ip;
        if (p.has_ports) line += ":" + std::to_string(p.src_port);
        line += " -> " + p.dst_ip;
        if (p.has_ports) line += ":" + std::to_string(p.dst_port);

        if (p.fragment) return line + "  fragment";

        if (p.ip_protocol == 6) {
            static const struct { std::uint8_t bit; const char* name; } kFlags[] = {
                {0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}};
            std::string flags;
            for (const auto& f : kFlags) {
                if (p.tcp_flags & f.bit) flags += (flags.empty() ? "" : ",") + std::string(f.name);
            }
            return line + "  TCP [" + flags + "]  payload=" + std::to_string(p.payload_length);
        }
        if (p.ip_protocol == 17) return line + "  UDP  payload=" + std::to_string(p.payload_length);
        if (p.ip_protocol == 1) {
            return line + "  ICMP type=" + std::to_string(p.icmp_type) +
                " code=" + std::to_string(p.icmp_code);
        }
        return line + "  proto=" + std::to_string(p.ip_protocol);
    }

}

