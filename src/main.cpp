#include <pcap/pcap.h> 
#include <CLI/CLI.hpp>

#include <exception>
#include <cstdio>
#include <iostream>
#include <csignal>
#include <memory>
#include <stdexcept>
#include <string>
#include <ctime>
#include <cstdint>

#include "pcap_capture.hpp"
#include "decoder.hpp"

namespace {
    PcapCapture* g_capture = nullptr;

    void on_signal(int) {
        if (g_capture != nullptr){
            g_capture->stop();
        }
    }

    void install_signal_handlers() {
        struct sigaction sa {};
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }

    std::string format_time(const timeval& tv) {
        const std::time_t seconds = tv.tv_sec;   
        std::tm t{};                             
        localtime_r(&seconds, &t);               

        char buffer[32];
        std::snprintf(buffer, sizeof buffer, "%02d:%02d:%02d.%06ld",
                    t.tm_hour, t.tm_min, t.tm_sec, static_cast<long>(tv.tv_usec));
        return buffer;
    }

    void list_interfaces() {
        char errbuf[PCAP_ERRBUF_SIZE] = {};
        pcap_if_t* raw = nullptr;
        if (pcap_findalldevs(&raw, errbuf) == PCAP_ERROR) {
            throw std::runtime_error(std::string("pcap_findalldevs: ") + errbuf);
        }
        std::unique_ptr<pcap_if_t, void (*)(pcap_if_t*)> devices(raw, &pcap_freealldevs);

        for (const pcap_if_t* d = devices.get(); d != nullptr; d = d->next) {
            std::cout << d->name;
            if (d->description != nullptr) {
                std::cout << "  -" << d->description << "-";
            }
            std::cout << '\n';
        }
    }
}


int main(int argc, char** argv){
    CLI::App app{"analyzer - a small network traffic analyzer (phase 2)"};

    bool list = false;
    std::string interface;
    std::string pcap_file;
    int count = 0;

    app.add_flag("-l,--list-interfaces", list, "List capture interfaces and exit");
    auto* interface_opt =
        app.add_option("-i,--interface", interface, "Interface to capture on");
    auto* file_opt = app.add_option("-r,--read", pcap_file, "Read packets from a pcap file")
                         ->check(CLI::ExistingFile);
    app.add_option("-c,--count", count, "Stop after N packets (0 = no limit)")
        ->check(CLI::NonNegativeNumber);
    interface_opt->excludes(file_opt);

    CLI11_PARSE(app, argc, argv);

    try {
        if (list) {
            list_interfaces();
            return 0;
        }
        if (interface.empty() && pcap_file.empty()) {
            std::cerr << "error: give an interface (-i) or a pcap file (-r). See --help.\n";
            return 2;
        }

        PcapCapture capture = pcap_file.empty() ? PcapCapture::open_live(interface)
                                                : PcapCapture::open_offline(pcap_file);
        g_capture = &capture;
        install_signal_handlers();

        std::cerr << "link type: " << capture.link_type_name() << '\n';

        const int link_type = capture.link_type();
        std::uint64_t packets = 0;
        std::uint64_t not_ok = 0;
        capture.run(count, [&](const pcap_pkthdr& header, const u_char* bytes) {
            ++packets;
            const decoder::Packet p = decoder::decode(link_type, bytes, header.caplen);
            if (p.status != decoder::Status::Ok) ++not_ok;
            std::printf("%s  %s\n", format_time(header.ts).c_str(),
                        decoder::describe(p).c_str());
        });
        g_capture = nullptr;

        std::cout << packets << " packets captured, " << not_ok << " not fully decoded";
        if (const auto st = capture.stats()) {
            std::cout << ", " << st->ps_recv << " received by filter, " << st->ps_drop
                      << " dropped by kernel";
        }
        std::cout << '\n';
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
