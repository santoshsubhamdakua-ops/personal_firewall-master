#ifndef FIREWALL_H
#define FIREWALL_H

//std lib include
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include <iostream>

//linux networking and system headers
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

//structures
//holds extracted attributes of an intercepted network packet

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    size_t payload_size;
};

//tracks real time traffic statistics

struct FirewallStats {
    uint64_t total_packets = 0;
    uint64_t accepted_packets = 0;
    uint64_t dropped_packets = 0;

};

//personal firewall class declaration

class PersonalFirewall {
    private: 
        int raw_socket;
        std::vector<std::string> blocked_ips;
        std::vector<std::uint16_t> blocked_ports;
        std::ofstream log_file;
        FirewallStats stats;

        void inspect_packet(unsigned char* buffer, ssize_t size);

        void log_action(const std::string& action, const PacketInfo& pkt, const std::string& reason);

    public:
    PersonalFirewall();
    ~PersonalFirewall();
    //configuration & execution
    bool init();
    void start();
    
    //rule management
    void add_blocked_ip(const std::string& ip);
    void add_blocked_port(uint16_t port);

    //getters
    FirewallStats get_stats() const;


};
#endif //FIREWALL_H