# =============================================================================
# MAKEFILE - Network Security Analyzer (Auto MOC Detection)
# =============================================================================

CXX      := g++
TARGET   := NetworkSecurityAnalyzer
BUILD    := build
SRC      := src
IFACE    := interfaces
OBJ      := $(BUILD)/obj
BIN      := $(BUILD)

CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2 -DNDEBUG
LDFLAGS  := 

# ==================== Include Paths ====================
CXXFLAGS += -I$(SRC)
CXXFLAGS += -I$(SRC)/common
CXXFLAGS += -I$(SRC)/core/layer1
CXXFLAGS += -I$(SRC)/core/layer1/filter
CXXFLAGS += -I$(SRC)/core/storage
CXXFLAGS += -I$(IFACE)/gui
CXXFLAGS += -I$(IFACE)/gui/widgets
CXXFLAGS += -I$(IFACE)/gui/models
CXXFLAGS += -I$(IFACE)/gui/dialogs
CXXFLAGS += -I$(IFACE)/gui/utils

# ==================== Qt6 Detection & MOC ====================
QT6_AVAILABLE := $(shell pkg-config --exists Qt6Core && echo yes || echo no)

ifeq ($(QT6_AVAILABLE),yes)
    $(info ✓ Qt6 detected)
    QT_MODULES := Qt6Core Qt6Widgets Qt6Network Qt6Gui
    
    # Try multiple MOC locations
    QT6_BIN_DIR := $(shell pkg-config --variable=host_bins Qt6Core 2>/dev/null)
    QT6_LIBEXEC := $(shell pkg-config --variable=libexecdir Qt6Core 2>/dev/null)
    
    # Priority order for finding MOC
    MOC := $(shell \
        if [ -f "$(QT6_BIN_DIR)/moc" ]; then \
            echo "$(QT6_BIN_DIR)/moc"; \
        elif [ -f "$(QT6_LIBEXEC)/moc" ]; then \
            echo "$(QT6_LIBEXEC)/moc"; \
        elif [ -f "/usr/lib/qt6/bin/moc" ]; then \
            echo "/usr/lib/qt6/bin/moc"; \
        elif [ -f "/usr/lib/qt6/libexec/moc" ]; then \
            echo "/usr/lib/qt6/libexec/moc"; \
        elif command -v moc-qt6 >/dev/null 2>&1; then \
            echo "moc-qt6"; \
        else \
            echo "moc"; \
        fi \
    )
else
    $(info ✓ Qt5 detected)
    QT_MODULES := Qt5Core Qt5Widgets Qt5Network Qt5Gui
    MOC := moc
endif

# Verify MOC
MOC_VERSION := $(shell $(MOC) -v 2>&1 | head -1)
$(info → MOC: $(MOC))
$(info → Version: $(MOC_VERSION))

# Check if MOC is valid
ifeq ($(MOC),moc)
    MOC_CHECK := $(shell $(MOC) -v 2>&1 | grep -q "Qt 6" && echo qt6 || echo qt5)
    ifneq ($(MOC_CHECK),qt6)
        ifeq ($(QT6_AVAILABLE),yes)
            $(error ERROR: Qt6 is available but MOC is Qt5. Please install qt6-base-dev-tools)
        endif
    endif
endif

CXXFLAGS += $(shell pkg-config --cflags $(QT_MODULES))
LDFLAGS  += $(shell pkg-config --libs $(QT_MODULES))

# ==================== System Libraries ====================
CXXFLAGS += $(shell pkg-config --cflags libpcap spdlog 2>/dev/null || true)
LDFLAGS  += $(shell pkg-config --libs libpcap spdlog 2>/dev/null || true)
LDFLAGS  += -pthread -lcap -lz -lbz2 -llzma -lcrypto -lssl

# ==================== Source Files ====================
COMMON_SRCS := \
    $(SRC)/common/packet_parser.cpp \
    $(SRC)/common/utils.cpp \
    $(SRC)/common/logger.cpp \
    $(SRC)/common/config_manager.cpp \
    $(SRC)/common/flow_manager.cpp \
    $(SRC)/common/network_utils.cpp

LAYER1_SRCS := \
    $(SRC)/core/layer1/packet_ingress.cpp \
    $(SRC)/core/layer1/filter/filter_expression.cpp \
    $(SRC)/core/layer1/filter/filter_field_evaluator.cpp \
    $(SRC)/core/layer1/filter/filter_parser.cpp \
    $(SRC)/core/layer1/filter/filter_types.cpp \
    $(SRC)/core/layer1/filter/packet_filter.cpp \
    $(SRC)/core/layer1/filter/predefined_filters.cpp

STORAGE_SRCS := \
    $(SRC)/core/storage/packet_storage.cpp \
    $(SRC)/core/storage/pcap_writer.cpp

GUI_SRCS := \
    $(IFACE)/gui/main.cpp \
    $(IFACE)/gui/main_window.cpp \
    $(IFACE)/gui/widgets/packet_list_widget.cpp \
    $(IFACE)/gui/widgets/packet_detail_widget.cpp \
    $(IFACE)/gui/widgets/packet_hex_widget.cpp \
    $(IFACE)/gui/widgets/filter_bar_widget.cpp \
    $(IFACE)/gui/widgets/status_bar_widget.cpp \
    $(IFACE)/gui/models/packet_table_model.cpp \
    $(IFACE)/gui/dialogs/capture_dialog.cpp \
    $(IFACE)/gui/dialogs/preferences_dialog.cpp \
    $(IFACE)/gui/utils/color_rules.cpp


CORE_SRCS := $(LAYER1_SRCS) $(STORAGE_SRCS)
APP_SRCS  := $(CORE_SRCS) $(GUI_SRCS)

# ==================== Object Files ====================
COMMON_OBJS  := $(patsubst $(SRC)/common/%.cpp,$(OBJ)/common/%.o,$(COMMON_SRCS))
LAYER1_OBJS  := $(patsubst $(SRC)/core/layer1/%.cpp,$(OBJ)/core/layer1/%.o,$(LAYER1_SRCS))
STORAGE_OBJS := $(patsubst $(SRC)/core/storage/%.cpp,$(OBJ)/core/storage/%.o,$(STORAGE_SRCS))
GUI_OBJS     := $(patsubst $(IFACE)/gui/%.cpp,$(OBJ)/gui/%.o,$(GUI_SRCS))

CORE_OBJS := $(LAYER1_OBJS) $(STORAGE_OBJS)
APP_OBJS  := $(CORE_OBJS) $(GUI_OBJS)

# ==================== MOC Files ====================
# Define each MOC file explicitly to avoid pattern matching issues
MOC_MAIN_WINDOW_CPP        := $(BUILD)/moc/moc_main_window.cpp
MOC_PACKET_LIST_CPP        := $(BUILD)/moc/moc_packet_list_widget.cpp
MOC_PACKET_DETAIL_CPP      := $(BUILD)/moc/moc_packet_detail_widget.cpp
MOC_PACKET_HEX_CPP         := $(BUILD)/moc/moc_packet_hex_widget.cpp
MOC_FILTER_BAR_CPP         := $(BUILD)/moc/moc_filter_bar_widget.cpp
MOC_STATUS_BAR_CPP         := $(BUILD)/moc/moc_status_bar_widget.cpp
MOC_TABLE_MODEL_CPP        := $(BUILD)/moc/moc_packet_table_model.cpp
MOC_CAPTURE_DIALOG_CPP     := $(BUILD)/moc/moc_capture_dialog.cpp
MOC_PREFERENCES_DIALOG_CPP := $(BUILD)/moc/moc_preferences_dialog.cpp

MOC_MAIN_WINDOW_OBJ        := $(OBJ)/moc/moc_main_window.o
MOC_PACKET_LIST_OBJ        := $(OBJ)/moc/moc_packet_list_widget.o
MOC_PACKET_DETAIL_OBJ      := $(OBJ)/moc/moc_packet_detail_widget.o
MOC_PACKET_HEX_OBJ         := $(OBJ)/moc/moc_packet_hex_widget.o
MOC_FILTER_BAR_OBJ         := $(OBJ)/moc/moc_filter_bar_widget.o
MOC_STATUS_BAR_OBJ         := $(OBJ)/moc/moc_status_bar_widget.o
MOC_TABLE_MODEL_OBJ        := $(OBJ)/moc/moc_packet_table_model.o
MOC_CAPTURE_DIALOG_OBJ     := $(OBJ)/moc/moc_capture_dialog.o
MOC_PREFERENCES_DIALOG_OBJ := $(OBJ)/moc/moc_preferences_dialog.o

MOC_SRCS := \
    $(MOC_MAIN_WINDOW_CPP) \
    $(MOC_PACKET_LIST_CPP) \
    $(MOC_PACKET_DETAIL_CPP) \
    $(MOC_PACKET_HEX_CPP) \
    $(MOC_FILTER_BAR_CPP) \
    $(MOC_STATUS_BAR_CPP) \
    $(MOC_TABLE_MODEL_CPP) \
    $(MOC_CAPTURE_DIALOG_CPP) \
    $(MOC_PREFERENCES_DIALOG_CPP)

MOC_OBJS := \
    $(MOC_MAIN_WINDOW_OBJ) \
    $(MOC_PACKET_LIST_OBJ) \
    $(MOC_PACKET_DETAIL_OBJ) \
    $(MOC_PACKET_HEX_OBJ) \
    $(MOC_FILTER_BAR_OBJ) \
    $(MOC_STATUS_BAR_OBJ) \
    $(MOC_TABLE_MODEL_OBJ) \
    $(MOC_CAPTURE_DIALOG_OBJ) \
    $(MOC_PREFERENCES_DIALOG_OBJ)


COMMON_LIB := $(BUILD)/lib/libcommon.a

# ==================== Main Targets ====================
.PHONY: all clean run debug install help info check-qt list-moc

all: check-qt $(BIN)/$(TARGET)
	@echo ""
	@echo "╔════════════════════════════════════════╗"
	@echo "║  ✓ Build completed successfully!      ║"
	@echo "╚════════════════════════════════════════╝"
	@echo "Run with: sudo ./$(BIN)/$(TARGET)"

check-qt:
	@echo ""
	@echo "╔════════════════════════════════════════╗"
	@echo "║  Qt Configuration Check                ║"
	@echo "╚════════════════════════════════════════╝"
	@if [ "$(QT6_AVAILABLE)" = "no" ]; then \
		echo "⚠ WARNING: Qt6 not found, using Qt5"; \
		echo "  Install Qt6: sudo apt-get install qt6-base-dev qt6-base-dev-tools"; \
	fi
	@if ! $(MOC) -v >/dev/null 2>&1; then \
		echo "✗ ERROR: MOC not found or not working"; \
		echo "  Install: sudo apt-get install qt6-base-dev-tools"; \
		exit 1; \
	fi
	@echo ""

$(BIN)/$(TARGET): $(COMMON_LIB) $(APP_OBJS) $(MOC_OBJS)
	@echo "→ Linking executable..."
	@mkdir -p $(BIN)
	$(CXX) $(APP_OBJS) $(MOC_OBJS) $(COMMON_LIB) -o $@ $(LDFLAGS)
	@echo "✓ Executable created: $@"

$(COMMON_LIB): $(COMMON_OBJS)
	@echo "→ Creating static library..."
	@mkdir -p $(BUILD)/lib
	ar rcs $@ $^
	@echo "✓ Library created: $@"

# ==================== Compile Rules ====================
# Common library
$(OBJ)/common/%.o: $(SRC)/common/%.cpp
	@echo "→ Compiling [COMMON]: $<"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Core Layer1 (including filter subdirectory)
$(OBJ)/core/layer1/%.o: $(SRC)/core/layer1/%.cpp
	@echo "→ Compiling [LAYER1]: $<"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Core Storage
$(OBJ)/core/storage/%.o: $(SRC)/core/storage/%.cpp
	@echo "→ Compiling [STORAGE]: $<"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# GUI (all subdirectories: widgets, models, dialogs, utils)
$(OBJ)/gui/%.o: $(IFACE)/gui/%.cpp
	@echo "→ Compiling [GUI]: $<"
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ==================== MOC Rules ====================
# Main window
$(MOC_MAIN_WINDOW_CPP): $(IFACE)/gui/main_window.hpp
	@echo "→ MOC: main_window.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

# Widgets
$(MOC_PACKET_LIST_CPP): $(IFACE)/gui/widgets/packet_list_widget.hpp
	@echo "→ MOC [WIDGET]: packet_list_widget.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

$(MOC_PACKET_DETAIL_CPP): $(IFACE)/gui/widgets/packet_detail_widget.hpp
	@echo "→ MOC [WIDGET]: packet_detail_widget.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

$(MOC_PACKET_HEX_CPP): $(IFACE)/gui/widgets/packet_hex_widget.hpp
	@echo "→ MOC [WIDGET]: packet_hex_widget.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

$(MOC_FILTER_BAR_CPP): $(IFACE)/gui/widgets/filter_bar_widget.hpp
	@echo "→ MOC [WIDGET]: filter_bar_widget.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

# Status Bar Widget
$(MOC_STATUS_BAR_CPP): $(IFACE)/gui/widgets/status_bar_widget.hpp
	@echo "→ MOC [WIDGET]: status_bar_widget.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

$(MOC_STATUS_BAR_OBJ): $(MOC_STATUS_BAR_CPP)
	@echo "→ Compiling [MOC]: moc_status_bar_widget.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@


# Models
$(MOC_TABLE_MODEL_CPP): $(IFACE)/gui/models/packet_table_model.hpp
	@echo "→ MOC [MODEL]: packet_table_model.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

# Dialogs
$(MOC_CAPTURE_DIALOG_CPP): $(IFACE)/gui/dialogs/capture_dialog.hpp
	@echo "→ MOC [DIALOG]: capture_dialog.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

$(MOC_PREFERENCES_DIALOG_CPP): $(IFACE)/gui/dialogs/preferences_dialog.hpp
	@echo "→ MOC [DIALOG]: preferences_dialog.hpp"
	@mkdir -p $(BUILD)/moc
	$(MOC) $< -o $@

# Compile MOC generated files
$(MOC_MAIN_WINDOW_OBJ): $(MOC_MAIN_WINDOW_CPP)
	@echo "→ Compiling [MOC]: moc_main_window.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_PACKET_LIST_OBJ): $(MOC_PACKET_LIST_CPP)
	@echo "→ Compiling [MOC]: moc_packet_list_widget.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_PACKET_DETAIL_OBJ): $(MOC_PACKET_DETAIL_CPP)
	@echo "→ Compiling [MOC]: moc_packet_detail_widget.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_PACKET_HEX_OBJ): $(MOC_PACKET_HEX_CPP)
	@echo "→ Compiling [MOC]: moc_packet_hex_widget.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_FILTER_BAR_OBJ): $(MOC_FILTER_BAR_CPP)
	@echo "→ Compiling [MOC]: moc_filter_bar_widget.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_TABLE_MODEL_OBJ): $(MOC_TABLE_MODEL_CPP)
	@echo "→ Compiling [MOC]: moc_packet_table_model.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_CAPTURE_DIALOG_OBJ): $(MOC_CAPTURE_DIALOG_CPP)
	@echo "→ Compiling [MOC]: moc_capture_dialog.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(MOC_PREFERENCES_DIALOG_OBJ): $(MOC_PREFERENCES_DIALOG_CPP)
	@echo "→ Compiling [MOC]: moc_preferences_dialog.cpp"
	@mkdir -p $(OBJ)/moc
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ==================== Utility Targets ====================
run: all
	sudo $(BIN)/$(TARGET)

debug: CXXFLAGS += -g -O0 -DDEBUG
debug: CXXFLAGS := $(filter-out -O2 -DNDEBUG,$(CXXFLAGS))
debug: clean all

clean:
	@echo "→ Cleaning..."
	rm -rf $(BUILD)
	@echo "✓ Clean completed"

install: all
	@echo "→ Installing..."
	sudo install -m 755 $(BIN)/$(TARGET) /usr/local/bin/
	sudo setcap cap_net_raw+ep /usr/local/bin/$(TARGET)
	@echo "✓ Installation completed"

list-moc:
	@echo "MOC Source Files:"
	@for src in $(MOC_SRCS); do echo "  $$src"; done
	@echo ""
	@echo "MOC Object Files:"
	@for obj in $(MOC_OBJS); do echo "  $$obj"; done

info:
	@echo ""
	@echo "╔════════════════════════════════════════╗"
	@echo "║  Build Configuration                   ║"
	@echo "╚════════════════════════════════════════╝"
	@echo "Compiler:      $(CXX)"
	@echo "MOC:           $(MOC)"
	@echo "Qt Modules:    $(QT_MODULES)"
	@echo "Qt6 Available: $(QT6_AVAILABLE)"
	@echo "Target:        $(TARGET)"
	@echo ""
	@echo "Source Files:"
	@echo "  Common:      $(words $(COMMON_SRCS)) files"
	@echo "  Layer1:      $(words $(LAYER1_SRCS)) files"
	@echo "  Storage:     $(words $(STORAGE_SRCS)) files"
	@echo "  GUI:         $(words $(GUI_SRCS)) files"
	@echo "  MOC Files:   $(words $(MOC_SRCS)) files"
	@echo ""

help:
	@echo "Available targets:"
	@echo "  make          - Build (default)"
	@echo "  make run      - Build and run"
	@echo "  make debug    - Debug build"
	@echo "  make clean    - Clean all"
	@echo "  make install  - Install to system"
	@echo "  make info     - Show build info"
	@echo "  make list-moc - List MOC files"
	@echo "  make check-qt - Check Qt configuration"

.PRECIOUS: $(MOC_SRCS)
.DELETE_ON_ERROR:
