#Compiler & Flags
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Iinclude
TARGET = bin/firewall
SRC = src/firewall.cpp

all: $(TARGET)

#rule to compile source files into the output binary
$(TARGET): $(SRC)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET)
	@echo "[+] Build Successfull: $(TARGET)"

#clean up build artifacts

clean:
	rm -rf bin/firewll logs/*.log
	@echo "[+] Cleanup complete."

#Helper command to run the firewall with required root previleges
run: $(TARGET)
	sudo ./"$(TARGET)"
.PHONY: all clean run

