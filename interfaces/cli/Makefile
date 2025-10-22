# Makefile for Network Security AI CLI

CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -Wno-unused-parameter
INCLUDES = -I../../src/common -I../../src/core/layer1
LIBS = -lpcap -lbpf -lpthread -lssl -lcrypto -lz -lreadline

# Directories
SRC_DIR = .
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
              $(COMMON_DIR)/utils.cpp

# Object files
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
LAYER1_OBJS = $(patsubst $(LAYER1_DIR)/%.cpp,$(BUILD_DIR)/layer1_%.o,$(LAYER1_SRCS))
COMMON_OBJS = $(patsubst $(COMMON_DIR)/%.cpp,$(BUILD_DIR)/common_%.o,$(COMMON_SRCS))

ALL_OBJS = $(CLI_OBJS) $(LAYER1_OBJS) $(COMMON_OBJS)

TARGET = nsai-cli

.PHONY: all clean install uninstall help dirs

all: dirs $(TARGET)

# Create build directory
dirs:
	@mkdir -p $(BUILD_DIR)

$(TARGET): $(ALL_OBJS)
	@echo "🔗 Linking $@..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ Build successful!"

# Compile CLI files
%.o: %.cpp
	@echo "🔨 Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile Layer1 files
$(BUILD_DIR)/layer1_%.o: $(LAYER1_DIR)/%.cpp
	@echo "🔨 Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Compile Common files
$(BUILD_DIR)/common_%.o: $(COMMON_DIR)/%.cpp
	@echo "🔨 Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	@echo "🧹 Cleaning..."
	rm -f $(TARGET) $(CLI_OBJS)
	rm -rf $(BUILD_DIR)
	@echo "✅ Clean complete!"

install: $(TARGET)
	@echo "📦 Installing..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "✅ Installed to /usr/local/bin/$(TARGET)"

uninstall:
	@echo "🗑️  Uninstalling..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✅ Uninstalled"

help:
	@echo "Available targets:"
	@echo "  all       - Build the CLI (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build"
	@echo "  make clean        # Clean"
	@echo "  sudo make install # Install"
