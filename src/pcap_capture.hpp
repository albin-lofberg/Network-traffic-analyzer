#pragma once

#include <pcap/pcap.h>
#include <functional>
#include <memory>
#include <optional>
#include <string>

/* Owns one libpcap capture session then closes it. Live or from a file. */
class PcapCapture{
public:
    using PacketCallback = std::function<void(const pcap_pkthdr&, const u_char*)>;

    static PcapCapture open_live(const std::string& interface);
    static PcapCapture open_offline(const std::string& path);

    void run(int count, PacketCallback packet_callback_);

    void stop();

    bool is_live() const;
    std::string link_type_name() const;

    std::optional<pcap_stat> stats() const;

private:
    // unique_ptr takes (raw connection, function to call for cleanup)
    using Session = std::unique_ptr<pcap_t, void (*)(pcap_t*)>;
    
    PcapCapture(Session session, bool live_);

    static void trampoline(u_char* user, const pcap_pkthdr* header, const u_char* bytes);

    // Member functions
    Session session_;
    bool live_;
    PacketCallback packet_callback_;
    std::string error_;
};