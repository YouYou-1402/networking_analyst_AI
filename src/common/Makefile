# Makefile đơn giản để build libcommon.a

# Compiler
CXX = g++
AR = ar

# Flags
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -fPIC
ARFLAGS = rcs

# Directories
BUILD_DIR = ../../build
LIB_DIR = ../../lib

# Library name
LIB = $(LIB_DIR)/libcommon.a

# Source files
SRCS = config_manager.cpp \
       flow_manager.cpp \
       logger.cpp \
       network_utils.cpp \
       packet_parser.cpp \
       utils.cpp

# Object files
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

# Default target
all: $(LIB)

# Create library
$(LIB): $(OBJS) | $(LIB_DIR)
	@echo "Creating library $@"
	$(AR) $(ARFLAGS) $@ $(OBJS)
	@echo "Done!"

# Compile source files
$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	@echo "Compiling $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# Clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(LIB)

# Show info
info:
	@echo "Library: $(LIB)"
	@ls -lh $(LIB) 2>/dev/null || echo "Not built yet"
	@echo ""
	@echo "Contents:"
	@ar -t $(LIB) 2>/dev/null || echo "Not built yet"

.PHONY: all clean info
