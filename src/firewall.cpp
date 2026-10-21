#include "firewall.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cerrno>

//Constructor and destructor
 PersonalFirewall::PersonalFirewall() : raw_socket(-1) {
        // Open log file in append mode
        log_file.open("logs/firewall.log", std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "[!] Warning: Unable to open logs/firewall.log for writing." << std::endl;
        }
    }

    PersonalFirewall::~PersonalFirewall() {
        // Clean up socket file descriptor
        if (raw_socket >= 0) {
            close(raw_socket);
            std::cout << "[+] Raw socket closed cleanly."<< std::endl;
        }
         // Flush and close log stream
        if (log_file.is_open()) {
            log_file.close();
        }   
    }

    //rule management api
    void PersonalFirewall::add_blocked_ip(const std::string& ip) {
        blocked_ips.push_back(ip);
        std::cout<< "[+] Rule Added: Block IP -> " << ip << std::endl;
    }
    
    void PersonalFirewall::add_blocked_port(uint16_t port) {
        blocked_ports.push_back(port);
        std::cout << "[+] Rule Added Block Port -> " << port << std::endl;

    }

    FirewallStats PersonalFirewall::get_stats() const {
        return stats;

    }

    //Initialization Routine

    bool PersonalFirewall::init() {
        raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

        if(raw_socket < 0) {
            std::cerr << "[-] Error opening raw socket: " << strerror(errno) << std::endl;
            std::cerr << "[-] Hint: Raw sockets require root/sudo privileges." << std::endl;

            return false;
        }

        std::cout << "[+] Personal Firewall Engine Initialized. Socket Descriptor: " << raw_socket << std::endl;
        return true;
    }

    //Packet capture loop

    void PersonalFirewall::start() {
        if (raw_socket < 0){
        std::cerr << "[-] Cannot start firewall. Socket not initialized." << std::endl;
        return; 
        }
    
    unsigned char buffer[65536];
    std::cout << "[+] Personal Firewall Active. Intercepting Packets..\n" << std::endl;

    while(true) {
        ssize_t data_size = recvfrom(raw_socket,buffer,sizeof(buffer), 0, nullptr,nullptr);
        if (data_size < 0){
            std::cerr << "[-] Error receiving packet payload. " << std::endl;
            break;
        }
        stats.total_packets++;
        inspect_packet(buffer,data_size);

    }
    }

    //Byte-level packet inspector

void PersonalFirewall::inspect_packet(unsigned char* buffer, ssize_t size) {
    //Overlay ip header struct on raw memory buffer
    struct iphdr* ip_header = (struct iphdr*)buffer;

    char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;

        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

        unsigned short iphdrlen = ip_header->ihl * 4;

        struct tcphdr* tcp_header = (struct tcphdr*)(buffer + iphdrlen);

        uint16_t src_port = ntohs(tcp_header->source);
        uint16_t dst_port = ntohs(tcp_header->dest);

        PacketInfo pkt;
        pkt.src_ip = std::string(src_ip);
        pkt.dst_ip = std::string(dst_ip);
        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.protocol = "TCP";
        pkt.payload_size = size - iphdrlen - (tcp_header->doff * 4);

        bool drop = false;
        std::string reason;

        for (const auto& ip : blocked_ips) {
            if (pkt.src_ip == ip || pkt.dst_ip == ip) {
                drop = true;
                reason = "IP Blocklist Match [" + ip + "]";
                break;
            }
        }

        if (!drop) {
            for (auto port : blocked_ports) {
                if (pkt.dst_port == port) {
                    drop = true;
                    reason = "Port Blocklist Match [" +std::to_string(port) + "]";
                    break;
                }
            }
        }

        if (drop) {
            stats.dropped_packets++;
            log_action("DROPPED", pkt, reason);
        } else {
            stats.accepted_packets++;
            log_action("ACCEPTED", pkt, "Allowed Traffic");
        }
    
}

    void PersonalFirewall::log_action(const std::string& action, const PacketInfo& pkt, const std::string& reason) {
        if (action == "DROPPED") {
            std::cout << "\033[91m[DROPPED]\033[0m " << pkt.src_ip << ":" << pkt.src_port
                      << " -> " << pkt.dst_ip << ":" << pkt.dst_port
                      << " (" << pkt.protocol << ") | Reason: " << reason << std::endl;
        } else {
            std::cout << "\033[92m[ACCEPTED]\033[0m " << pkt.src_ip << ":" << pkt.src_port
                      << " -> " << pkt.dst_ip << ":" << pkt.dst_port
                      << " (" << pkt.protocol << ")" << std::endl;
        }

        // Write to audit log file
        if (log_file.is_open()) {
            log_file << "[" << action << "] " << pkt.src_ip << ":" << pkt.src_port
                     << " -> " << pkt.dst_ip << ":" << pkt.dst_port
                     << " (" << pkt.protocol << ") | " << reason << "\n";
            log_file.flush();
        }
    }

int main() {
        std::cout << "=====================================================" << std::endl;
        std::cout << "          Personal Firewall C++ Engine               " << std::endl;
        std::cout << "=====================================================" << std::endl;

        PersonalFirewall fw;

        fw.add_blocked_ip("192.168.1.250");
        fw.add_blocked_ip("10.0.0.99");
        fw.add_blocked_port(23);   
        fw.add_blocked_port(445);  
        fw.add_blocked_port(3389);

        if (!fw.init()) {
            return 1;
        }

        fw.start();
        return 0;
    }