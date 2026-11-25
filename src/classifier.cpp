#include "classifier.hpp"

#include <algorithm>
#include <cstring>

namespace classifier {
namespace {

    struct Payload {
        const std::uint8_t* data;
        std::size_t size;

        // Could just use memcmp
        bool starts_with(const char* text) const {
            const std::size_t n = std::strlen(text);
            if (size < n) {
                return false;
            }
            for (std::size_t i = 0; i < n; ++i) {
                if (data[i] != static_cast<std::uint8_t>(text[i])) {
                    return false;
                }
            }
            return true;
        }

        std::uint8_t u8(std::size_t i) const { 
            return data[i]; 
        }
        std::uint16_t u16(std::size_t i) const {
            const int high = data[i];
            const int low = data[i + 1];
            const int value = (high << 8) | low;
            return static_cast<std::uint16_t>(value);        
        }
    };

    Payload payload_of(const decoder::Packet& p, const std::uint8_t* data, std::size_t caplen) {
        if (p.payload_offset > caplen) {
            return {data, 0};
        }
        const std::size_t captured = caplen - p.payload_offset;

        return {data + p.payload_offset, std::min(captured, p.payload_length)};
    }

    bool looks_like_http(const Payload& d) {
        static const char* const Starts[] = 
        {"GET ",     "POST ",  "HEAD ",   "PUT ",
        "DELETE ",  "PATCH ", "OPTIONS ", "CONNECT ",
        "HTTP/1."};

        for (const char* start : Starts) {
            if (d.starts_with(start)) {
                return true;
            }
        }
        return false;
    }

    bool looks_like_ssh(const Payload& d) 
    { 
        return d.starts_with("SSH-"); 
    }

    bool looks_like_tls(const Payload& d) {
        if (d.size < 5) {
            return false;
        }

        const std::uint8_t type = d.u8(0);
        if (type < 20 || type > 23) {
            return false;
        }

        if (d.u8(1) != 3 || d.u8(2) > 4) {
            return false;  
        }

        // largest record tls allows
        return d.u16(3) <= 16384 + 2048;               
    }

    bool looks_like_dns(const Payload& d) {
        if (d.size < 12) {
            return false;
        }
        const unsigned opcode = (d.u8(2) >> 3) & 0x0F;
        const unsigned rcode = d.u8(3) & 0x0F;
        const unsigned questions = d.u16(4);

        if (opcode > 5 || rcode > 10 || questions == 0 || questions > 16) {
            return false;
        }

        std::size_t pos = 12;
        for (;;) {
            if (pos >= d.size) {
                return false;
            }
            const std::uint8_t label = d.u8(pos);
            if (label == 0) {  
                ++pos;
                break;
            }
            if (label > 63) {
                return false;  
            }
            pos += 1u + label;
        }
        return pos + 4 <= d.size; 
    }

    App app_port_mapping(std::uint16_t port, bool tcp) {
        switch (port) {
            case 80:
            case 8080: return tcp ? App::Http : App::Unknown;
            case 443:  return tcp ? App::Tls : App::Unknown;
            case 22:   return tcp ? App::Ssh : App::Unknown;
            case 53:   return App::Dns;  
            default:   return App::Unknown;
        }
    }
}

    Result classify(const decoder::Packet& p, const std::uint8_t* data, std::size_t caplen) {
       
        if (p.status != decoder::Status::Ok || !p.has_ports || p.fragment) {
            return {};
        }

        bool tcp = false;
        if (p.ip_protocol == decoder::ProtocolTcp) {
            tcp = true;
        }
        

        const Payload payload = payload_of(p, data, caplen);
        if (tcp) {
            if (looks_like_http(payload)) {
                return {App::Http, Basis::Payload};
            }
            if (looks_like_tls(payload)) {
                return {App::Tls, Basis::Payload};
            }
            if (looks_like_ssh(payload)) {
                return {App::Ssh, Basis::Payload};
            }
        } 
        else if (looks_like_dns(payload)) {
            return {App::Dns, Basis::Payload};
        }

        for (const std::uint16_t port : {p.dst_port, p.src_port}) {
            const App app = app_port_mapping(port, tcp);
            if (app != App::Unknown) {
                return {app, Basis::Port};
            }
        }
        return {};
    }

    const char* app_name(App app) {
        switch (app) {
            case App::Http: return "HTTP";
            case App::Tls:  return "TLS";
            case App::Dns:  return "DNS";
            case App::Ssh:  return "SSH";
            case App::Unknown: break;
        }
        return "unknown";
    }

    const char* basis_name(Basis b) {
        switch (b) {
            case Basis::Payload: return "payload";
            case Basis::Port:    return "port";
            case Basis::None:    break;
        }
        return "";
    }      
}