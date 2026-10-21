# Personal Firewall (C++)

A lightweight, user-space personal firewall implemented in modern C++ (C++17) for Linux systems. The firewall captures, parses, and evaluates network traffic at the byte level using raw sockets (`SOCK_RAW`) and enforces IP and port filtering rules.

## Features

- **Raw Socket Interception:** Direct access to IPv4 TCP packets using Linux `AF_INET` raw sockets.
- **Header Parsing:** Byte-level inspection of IP and TCP headers, handling network-to-host byte order conversions (`ntohs`).
- **Rule Matching Engine:** Configurable blocklists for source/destination IP addresses and target TCP ports.
- **Audit Logging:** Color-coded console output and persistent file logging (`logs/firewall.log`).
- **Clean Resource Management:** Graceful socket cleanup and signal handling.

## Project Structure

```text
personal_firewall/
├── bin/              # Output binary directory
├── config/
│   └── rules.json    # Firewall rules configuration
├── include/
│   └── firewall.h    # Class declaration & packet data structures
├── logs/
│   └── firewall.log  # Real-time event log file
├── src/
│   └── firewall.cpp  # Engine implementation & packet inspector
├── Makefile          # Build automation
└── README.md         # Documentation
```

## Prerequisites

- **OS:** Linux (Ubuntu, Debian, Fedora, Arch, etc.)
- **Compiler:** `g++` (supporting C++17)
- **Privileges:** `sudo` / Root access (required for raw socket operations)

## Build & Run

### 1. Build the Binary
```bash
make
```

### 2. Run the Firewall
```bash
make run
# Or directly:
sudo ./bin/firewall
```

### 3. Clean Build Artifacts
```bash
make clean
```

## Sample Output

```text
=====================================================
          Personal Firewall C++ Engine               
=====================================================
[+] Rule Added: Block IP -> 192.168.1.250
[+] Rule Added: Block IP -> 10.0.0.99
[+] Rule Added: Block Port -> 23
[+] Rule Added: Block Port -> 445
[+] Rule Added: Block Port -> 3389
[+] Personal Firewall Engine Initialized. Socket Descriptor: 4
[+] Personal Firewall Active. Intercepting Packets..

[ACCEPTED] 20.42.73.31:443 -> 10.207.49.220:45888 (TCP)
[ACCEPTED] 140.82.114.22:443 -> 10.207.49.220:47524 (TCP)
[DROPPED]  192.168.1.250:52134 -> 10.207.49.220:23 (TCP) | Reason: IP Blocklist Match [192.168.1.250]
```

## License

MIT License
