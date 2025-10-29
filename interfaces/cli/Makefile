# Makefile for Network Security AI CLI

CXX = g++
CLANG = clang
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -Wno-unused-parameter

# BPF compilation flags - ONLY use libbpf headers
BPF_CFLAGS = -O2 -g -Wall \
             -target bpf \
             -D__TARGET_ARCH_x86 \
             -I/usr/include

INCLUDES = -I../../src/common -I../../src/core/layer1
LIBS = -lpcap -lbpf -lpthread -lssl -lcrypto -lz -lreadline

# Directories
LAYER1_DIR = ../../src/core/layer1
COMMON_DIR = ../../src/common
BUILD_DIR = build

# Source files
CLI_SRCS = cli_main.cpp cli_parser.cpp cli_commands.cpp
LAYER1_SRCS = $(LAYER1_DIR)/packet_ingress.cpp \
              $(LAYER1_DIR)/xdp_filter.cpp
COMMON_SRCS = $(COMMON_DIR)/logger.cpp \
              $(COMMON_DIR)/packet_parser.cpp \
              $(COMMON_DIR)/network_utils.cpp \
              $(COMMON_DIR)/utils.cpp \
              $(COMMON_DIR)/config_manager.cpp \
              $(COMMON_DIR)/flow_manager.cpp

# BPF
BPF_SRC = $(LAYER1_DIR)/xdp_filter.bpf.c
BPF_OBJ = $(BUILD_DIR)/xdp_filter.bpf.o

# Object files
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
LAYER1_OBJS = $(patsubst $(LAYER1_DIR)/%.cpp,$(BUILD_DIR)/layer1_%.o,$(LAYER1_SRCS))
COMMON_OBJS = $(patsubst $(COMMON_DIR)/%.cpp,$(BUILD_DIR)/common_%.o,$(COMMON_SRCS))
ALL_OBJS = $(CLI_OBJS) $(LAYER1_OBJS) $(COMMON_OBJS)

TARGET = nsai-cli

.PHONY: all clean install uninstall help dirs bpf check-deps

all: check-deps dirs bpf $(TARGET)

check-deps:
	@echo "🔍 Checking dependencies..."
	@command -v clang >/dev/null 2>&1 || { echo "❌ clang not found"; exit 1; }
	@echo "✅ clang: $(shell clang --version | head -1)"
	@test -f /usr/include/bpf/bpf_helpers.h || { \
		echo "❌ libbpf-dev not installed"; \
		echo "   Run: sudo apt-get install libbpf-dev"; \
		exit 1; \
	}
	@echo "✅ libbpf-dev installed"
	@echo ""

dirs:
	@mkdir -p $(BUILD_DIR)

bpf: dirs $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "🔨 Compiling BPF: $<"
	@echo "   Command: $(CLANG) $(BPF_CFLAGS) -c $< -o $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@ 2>&1 | head -20
	@if [ $$? -eq 0 ]; then \
		if command -v llvm-strip >/dev/null 2>&1; then \
			llvm-strip -g $@; \
			echo "✅ BPF compiled and stripped"; \
		else \
			echo "✅ BPF compiled"; \
		fi; \
		ls -lh $@; \
	else \
		echo "❌ BPF compilation failed"; \
		exit 1; \
	fi
	@echo ""

$(TARGET): $(ALL_OBJS)
	@echo "🔗 Linking $@..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ Build complete!"
	@ls -lh $@

%.o: %.cpp
	@echo "🔨 $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/layer1_%.o: $(LAYER1_DIR)/%.cpp
	@echo "🔨 $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/common_%.o: $(COMMON_DIR)/%.cpp
	@echo "🔨 $<"
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo "🧹 Cleaning..."
	@rm -f $(TARGET) $(CLI_OBJS)
	@rm -rf $(BUILD_DIR)
	@echo "✅ Done"

install: $(TARGET) $(BPF_OBJ)
	@echo "📦 Installing..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	sudo mkdir -p /usr/local/share/nsai/bpf
	sudo cp $(BPF_OBJ) /usr/local/share/nsai/bpf/
	@echo "✅ Installed to:"
	@echo "   - /usr/local/bin/$(TARGET)"
	@echo "   - /usr/local/share/nsai/bpf/xdp_filter.bpf.o"

uninstall:
	@echo "🗑️  Uninstalling..."
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -rf /usr/local/share/nsai
	@echo "✅ Uninstalled"

help:
	@echo "Available targets:"
	@echo "  all (default) - Build everything"
	@echo "  bpf           - Build BPF program only"
	@echo "  check-deps    - Check dependencies"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install to system"
	@echo "  uninstall     - Remove from system"
