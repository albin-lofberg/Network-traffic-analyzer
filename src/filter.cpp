#include "filter.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <sstream>
#include <utility>
#include <vector>

namespace filter {
namespace {

    std::string lower(std::string text) {
        for (char& c : text) {
            const unsigned char byte = static_cast<unsigned char>(c);
            c = static_cast<char>(std::tolower(byte));
        }
        return text;
    }

    std::string protocol_to_bpf(const std::string& name) {
        static const std::map<std::string, std::string> Protocols = {
            {"tcp", "tcp"},         {"udp", "udp"},        {"icmp", "icmp"},
            {"icmp6", "icmp6"},     {"ipv4", "ip"},        {"ipv6", "ip6"},
            {"http", "tcp port 80"}, {"https", "tcp port 443"}, {"dns", "port 53"},
            {"ssh", "tcp port 22"},
        };

        const auto it = Protocols.find(name);
        if (it == Protocols.end()) {
            throw FilterError("unknown protocol '" + name +
                            "' (known: tcp udp icmp icmp6 ipv4 ipv6 http https dns ssh)");
        }
        return it->second;
    }

    std::string address_to_bpf(const std::string& direction, const std::string& value) {
        const std::size_t slash = value.find('/');
        const std::string address = value.substr(0, slash);

        unsigned char buffer[16];
        int family = AF_INET;
        if (inet_pton(AF_INET, address.c_str(), buffer) != 1) {
            family = AF_INET6;
            if (inet_pton(AF_INET6, address.c_str(), buffer) != 1) {
                throw FilterError("'" + value + "' is not an IP address");
            }
        }
        if (slash == std::string::npos) {
            return direction + "host " + address;
        }

        const std::string prefix = value.substr(slash + 1);
        const bool digits = !prefix.empty() && prefix.size() <= 3 &&
                            std::all_of(prefix.begin(), prefix.end(),
                                        [](unsigned char c) { return std::isdigit(c) != 0; });
        const int max_bits = family == AF_INET ? 32 : 128;
        if (!digits || std::atoi(prefix.c_str()) > max_bits) {
            throw FilterError("bad prefix length in '" + value + "'");
        }
        return direction + "net " + address + "/" + prefix;
    }

    std::string port_to_bpf(const std::string& direction, const std::string& value) {
        const bool digits = !value.empty() && value.size() <= 5 &&
                            std::all_of(value.begin(), value.end(),
                                        [](unsigned char c) { return std::isdigit(c) != 0; });
        
                                        const int port = digits ? std::atoi(value.c_str()) : 0;
        if (port < 1 || port > 65535) {
            throw FilterError("'" + value + "' is not a port (1-65535)");
        }
        return direction + "port " + std::to_string(port);
    }

    std::string term_to_bpf(const std::string& key, const std::string& value) {
        if (key == "protocol") {
            return protocol_to_bpf(lower(value));
        }
        if (key == "src") {
            return address_to_bpf("src ", value);
        }
        if (key == "dst") {
            return address_to_bpf("dst ", value);
        }
        if (key == "host") {
            return address_to_bpf("", value);
        }
        if (key == "port") {
            return port_to_bpf("", value);
        }
        if (key == "srcport") {
            return port_to_bpf("src ", value);
        }
        if (key == "dstport") {
            return port_to_bpf("dst ", value);
        }
        throw FilterError("unknown filter key '" + key +
                        "' (known: protocol src dst host port srcport dstport)");
    }

    struct Group {
        std::string key;
        std::vector<std::string> terms;
    };

}

    std::string to_bpf(const std::string& text) {

        std::vector<Group> groups;

        std::istringstream words(text);
        std::string word;
        while (words >> word) {
            const std::size_t colon = word.find(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 == word.size()) {
                throw FilterError("expected key:value, got '" + word + "'");
            }
            const std::string key = lower(word.substr(0, colon));
            const std::string bpf = term_to_bpf(key, word.substr(colon + 1));

            auto group = std::find_if(groups.begin(), groups.end(),
                                    [&](const Group& g) { return g.key == key; });
            if (group == groups.end()) {
                groups.push_back({key, {}});
                group = std::prev(groups.end());
            }
            group->terms.push_back(bpf);
        }

        std::string out;
        for (const Group& group : groups) {
            std::string joined;
            for (const std::string& term : group.terms) {
                if (!joined.empty()) {
                    joined += " or ";
                }
                joined += "(" + term + ")";
            }
            if (!out.empty()) {
                out += " and ";
            }
            out += "(" + joined + ")";
        }
        return out;
    }

} 