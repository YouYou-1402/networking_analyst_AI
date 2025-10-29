# Makefile for Packet Ingress CLI Test
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g -O2
INCLUDES = -I../../src/common -I../../src/core/layer1
LDFLAGS = -lpcap -lpthread -lssl -lcrypto -lz

# Source files
SOURCES = test_packet_ingress_cli.cpp \
          ../../src/core/layer1/packet_ingress.cpp \
          ../../src/common/packet_parser.cpp \
          ../../src/common/logger.cpp \
          ../../src/common/utils.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Target executable
TARGET = test_packet_ingress_cli

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) *.log

run: $(TARGET)
	sudo ./$(TARGET)

install:
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean run install uninstall
