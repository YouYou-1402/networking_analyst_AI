# Makefile for packet_parser tests
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g
INCLUDES = -I../../src/common
LDFLAGS = -lgtest -lgtest_main -lpthread -lssl -lcrypto -lz

# Source files
SOURCES = test_common_packet_parser.cpp \
          ../../src/common/packet_parser.cpp \
          ../../src/common/utils.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Target executable
TARGET = test_packet_parser

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
