#include "pcap_capture.hpp"

#include <stdexcept>
#include <utility>


namespace {
const int SnapLen = 65535;
const int Promisc = 1;
const int TimeOut = 1000;
}


PcapCapture::PcapCapture(Session session, bool live)
    : session_(std::move(session)), live_(live) {}
    
// live = true
PcapCapture PcapCapture::open_live(const std::string& interface){
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* raw = pcap_open_live(interface.c_str(), SnapLen, Promisc, TimeOut, errbuf);

    if (raw == nullptr){
        throw std::runtime_error("Can't open interface -" + interface + "-: " + errbuf);
    }
    return PcapCapture(Session(raw, &pcap_close), true);
}

// live = false
PcapCapture PcapCapture::open_offline(const std::string& path){
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* raw = pcap_open_offline(path.c_str(), errbuf);

    if (raw == nullptr){
        throw std::runtime_error("Can't open file -" + path + "-: " + errbuf);
    }
    return PcapCapture(Session(raw, &pcap_close), false);
}

// Count: how many packets capured - packet_callback: function run on every packet
void PcapCapture::run(int count, PacketCallback packet_callback){
    // Move pointer to .hpp so all functions in this class can access it
    packet_callback_ = std::move(packet_callback);
    error_.clear();
    
    // reinterpret_cast treats this as a different pointer type (is PcapCapture, treated
    //      as u_char*)
    const int result = pcap_loop(session_.get(), count, &PcapCapture::trampoline, 
                                 reinterpret_cast<u_char*>(this));

    if (!error_.empty()){
        throw std::runtime_error(error_);
    }
    if (result == PCAP_ERROR){
        throw std::runtime_error(pcap_geterr(session_.get()));
    }
}

void PcapCapture::stop() {
    pcap_breakloop(session_.get());
}

// Header has info about packet. Bytes points to contents of packet
void PcapCapture::trampoline(u_char* user, const pcap_pkthdr* header, const u_char* bytes){
    PcapCapture* self = reinterpret_cast<PcapCapture*>(user);
    try {
        self->packet_callback_(*header, bytes);
    } 
    catch (const std::exception& e){
        self->error_ = e.what();
        pcap_breakloop(self->session_.get());

    } 
    catch (...) {
        self->error_ = "unkown error";
        pcap_breakloop(self->session_.get());
    }
}

std::string PcapCapture::link_type_name() const {
    const int data_link_type = pcap_datalink(session_.get());
    const char* name = pcap_datalink_val_to_name(data_link_type);
    if (name == nullptr){
        return "Unknown -" + std::to_string(data_link_type) + "-";
    }
    return name;
}

// Return type is either pcap_stat or nothing
std::optional<pcap_stat> PcapCapture::stats() const {
    if (!live_){
        return std::nullopt;
    }
    pcap_stat st{};
    if (pcap_stats(session_.get(), &st) != 0){
        return std::nullopt;
    }
    return st;
}

bool PcapCapture::is_live() const{
    return live_;
}

int PcapCapture::link_type() const {
    return pcap_datalink(session_.get());
}
