# Network Traffic Analyzer
```
A command-line network traffic analyzer in C++. It captures live traffic or reads
pcap files, decodes the packets, identifies the application protocol, and filters
with a small query syntax compiled to BPF.
```
## Features

- Live capture from an interface or pcap file reading through libpcap
- Decodes Ethernet, Linux cooked capture, IPv4, IPv6 with extension headers, TCP, UDP, ICMP and ICMPv6
- Bounds-checked parsing: every length read from a packet is validated before use
- Identifies HTTP, TLS, SSH and DNS from the payload and, if necessary, port
- Filter syntax translated to BPF

## Build

Requires a C++17 compiler, CMake 3.16+ and libpcap (`sudo apt install libpcap-dev`).
CLI11 is downloaded automatically.

Run following commands to build. 
```
cmake -S . -B build && cmake --build build
```

## Usage
The 'samples/' folder contains synthetic traffic so you can try the programm
without capturing anything. 
To run and test the program run the following commands. 

```
# decode every packet in the sample file
./build/analyzer -r samples/phase3.pcap

# only HTTPS traffic
./build/analyzer -r samples/phase3.pcap -f "protocol:https"

# live capture: 100 packets of DNS on eth0 (needs root; find your interface with --list-interfaces)
sudo ./build/analyzer -i eth0 -c 100 -f "port:53"

# list capture interfaces
./build/analyzer --list-interfaces
```

## Roadmap
Possible future additions:
- Terminal UI 
- Threaded capture pipeline so capture never waits for the display
- Traffic statistics


