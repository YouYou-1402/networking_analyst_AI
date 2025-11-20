# tests/unit/Makefile
# Makefile for NetworkSecurityAI Unit Tests

# ==================== Compiler Settings ====================
CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -g
INCLUDES := -I../../src/common
LDFLAGS := -L../../lib
LIBS := -lcommon -lgtest -lgtest_main -lpthread -lcrypto -lz

# ==================== Directories ====================
SRC_DIR := ../../src/common
BUILD_DIR := build
BIN_DIR := bin
LIB_DIR := ../../lib

# ==================== Test Files ====================
TEST_SOURCES := \
	test_common_utils.cpp \
	test_common_logger.cpp \
	test_common_config_manager.cpp \
	test_common_network_utils.cpp \
	test_common_packet_parser.cpp \
	test_common_flow_manager.cpp

# ==================== Test Executables ====================
TEST_EXECUTABLES := $(TEST_SOURCES:%.cpp=$(BIN_DIR)/%)

# ==================== Targets ====================

.PHONY: all clean run test help dirs

# Default target
all: dirs $(TEST_EXECUTABLES)

# Create necessary directories
dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p test_logs

# ==================== Build Individual Tests ====================

$(BIN_DIR)/test_common_utils: test_common_utils.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

$(BIN_DIR)/test_common_logger: test_common_logger.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

$(BIN_DIR)/test_common_config_manager: test_common_config_manager.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

$(BIN_DIR)/test_common_network_utils: test_common_network_utils.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

$(BIN_DIR)/test_common_packet_parser: test_common_packet_parser.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

$(BIN_DIR)/test_common_flow_manager: test_common_flow_manager.cpp
	@echo "🔨 Compiling $@..."
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LIBS)
	@echo "✅ $@ compiled successfully!"

# ==================== Run All Tests ====================

run: all
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║         🚀 Running All Unit Tests                          ║"
	@echo "╚════════════════════════════════════════════════════════════╝"
	@echo ""
	@for test in $(TEST_EXECUTABLES); do \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "▶️  Running: $$test"; \
		echo "═══════════════════════════════════════════════════════════"; \
		./$$test || exit 1; \
		echo ""; \
	done
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║         ✅ All Tests Passed Successfully!                  ║"
	@echo "╚════════════════════════════════════════════════════════════╝"

# Alias for run
test: run

# ==================== Run Individual Tests ====================

test-utils: $(BIN_DIR)/test_common_utils
	@echo "🧪 Running Utils Tests..."
	@./$(BIN_DIR)/test_common_utils

test-logger: $(BIN_DIR)/test_common_logger
	@echo "🧪 Running Logger Tests..."
	@./$(BIN_DIR)/test_common_logger

test-config: $(BIN_DIR)/test_common_config_manager
	@echo "🧪 Running Config Manager Tests..."
	@./$(BIN_DIR)/test_common_config_manager

test-network: $(BIN_DIR)/test_common_network_utils
	@echo "🧪 Running Network Utils Tests..."
	@./$(BIN_DIR)/test_common_network_utils

test-parser: $(BIN_DIR)/test_common_packet_parser
	@echo "🧪 Running Packet Parser Tests..."
	@./$(BIN_DIR)/test_common_packet_parser

test-flow: $(BIN_DIR)/test_common_flow_manager
	@echo "🧪 Running Flow Manager Tests..."
	@./$(BIN_DIR)/test_common_flow_manager

# ==================== Run Tests with Verbose Output ====================

run-verbose: all
	@echo "🚀 Running All Tests (Verbose Mode)..."
	@for test in $(TEST_EXECUTABLES); do \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "▶️  Running: $$test"; \
		echo "═══════════════════════════════════════════════════════════"; \
		./$$test --gtest_print_time=1 --gtest_color=yes || exit 1; \
		echo ""; \
	done

# ==================== Run Tests with Filter ====================

run-filter:
	@if [ -z "$(FILTER)" ]; then \
		echo "❌ Error: Please specify FILTER"; \
		echo "Usage: make run-filter FILTER='TestSuiteName.TestName'"; \
		exit 1; \
	fi
	@echo "🔍 Running tests matching filter: $(FILTER)"
	@for test in $(TEST_EXECUTABLES); do \
		./$$test --gtest_filter=$(FILTER) || exit 1; \
	done

# ==================== Generate Test Report ====================

report: all
	@echo "📊 Generating Test Report..."
	@mkdir -p reports
	@for test in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test); \
		echo "Running $$test_name..."; \
		./$$test --gtest_output=xml:reports/$$test_name.xml; \
	done
	@echo "✅ Test reports generated in reports/ directory"

# ==================== Memory Check with Valgrind ====================

valgrind: all
	@echo "🔍 Running Tests with Valgrind..."
	@for test in $(TEST_EXECUTABLES); do \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════"; \
		echo "🔍 Valgrind: $$test"; \
		echo "═══════════════════════════════════════════════════════════"; \
		valgrind --leak-check=full --show-leak-kinds=all \
			--track-origins=yes --verbose \
			./$$test || exit 1; \
		echo ""; \
	done

# ==================== Code Coverage ====================

coverage: CXXFLAGS += -fprofile-arcs -ftest-coverage
coverage: LIBS += -lgcov
coverage: clean all
	@echo "📊 Running Tests with Coverage..."
	@for test in $(TEST_EXECUTABLES); do \
		./$$test; \
	done
	@echo "📊 Generating Coverage Report..."
	@lcov --capture --directory . --output-file coverage.info
	@genhtml coverage.info --output-directory coverage_report
	@echo "✅ Coverage report generated in coverage_report/"

# ==================== Clean ====================

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(BIN_DIR)
	@rm -rf test_logs
	@rm -rf reports
	@rm -rf coverage_report
	@rm -f *.gcda *.gcno *.gcov coverage.info
	@echo "✅ Cleanup complete!"

# ==================== Help ====================

help:
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║         NetworkSecurityAI Unit Tests - Makefile            ║"
	@echo "╚════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "  📦 Build Targets:"
	@echo "    all              - Build all test executables (default)"
	@echo "    dirs             - Create necessary directories"
	@echo ""
	@echo "  🧪 Test Targets:"
	@echo "    run / test       - Build and run all tests"
	@echo "    run-verbose      - Run all tests with verbose output"
	@echo "    run-filter       - Run tests matching filter (use FILTER=...)"
	@echo ""
	@echo "  🎯 Individual Tests:"
	@echo "    test-utils       - Run Utils tests only"
	@echo "    test-logger      - Run Logger tests only"
	@echo "    test-config      - Run Config Manager tests only"
	@echo "    test-network     - Run Network Utils tests only"
	@echo "    test-parser      - Run Packet Parser tests only"
	@echo "    test-flow        - Run Flow Manager tests only"
	@echo ""
	@echo "  📊 Analysis Targets:"
	@echo "    report           - Generate XML test reports"
	@echo "    valgrind         - Run tests with Valgrind memory check"
	@echo "    coverage         - Generate code coverage report"
	@echo ""
	@echo "  🧹 Utility Targets:"
	@echo "    clean            - Remove all build artifacts"
	@echo "    help             - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                              # Build all tests"
	@echo "  make run                          # Build and run all tests"
	@echo "  make test-logger                  # Run logger tests only"
	@echo "  make run-filter FILTER='Utils*'   # Run tests matching 'Utils*'"
	@echo "  make valgrind                     # Run with memory check"
	@echo "  make coverage                     # Generate coverage report"
	@echo ""
