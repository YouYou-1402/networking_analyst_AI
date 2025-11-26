# tests/gui/Makefile
.PHONY: all build clean run install help

BUILD_DIR = build

all: build

build:
	@echo "Building Network Security GUI..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && make -j$(shell nproc)
	@echo "Build complete!"

clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

run: build
	@echo "Running Network Security GUI (requires root)..."
	@sudo $(BUILD_DIR)/NetworkSecurityGUI

install: build
	@echo "Installing..."
	@cd $(BUILD_DIR) && sudo make install
	@echo "Install complete!"

debug:
	@echo "Building in debug mode..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j$(shell nproc)

release:
	@echo "Building in release mode..."
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(shell nproc)

help:
	@echo "Available targets:"
	@echo "  make build   - Build the project"
	@echo "  make clean   - Clean build files"
	@echo "  make run     - Build and run (requires root)"
	@echo "  make install - Install to system"
	@echo "  make debug   - Build in debug mode"
	@echo "  make release - Build in release mode"
