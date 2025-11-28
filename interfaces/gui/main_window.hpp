// src/gui/main_window.hpp

#ifndef MAIN_WINDOW_HPP
#define MAIN_WINDOW_HPP

#include <QMainWindow>
#include <QSplitter>
#include <QMenu>
#include <QMenuBar>
#include <QToolBar>
#include <QTimer>
#include <QLabel>
#include <atomic>
#include <memory>
#include <vector>

#include "common/packet_parser.hpp"
#include "core/layer1/filter/packet_filter.hpp"
#include "core/layer1/packet_ingress.hpp"

// Include widgets
#include "widgets/packet_list_widget.hpp"
#include "widgets/packet_detail_widget.hpp"
#include "widgets/packet_hex_widget.hpp"
#include "widgets/filter_bar_widget.hpp"
#include "widgets/status_bar_widget.hpp"
#include "dialogs/capture_dialog.hpp"
#include "dialogs/preferences_dialog.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        class MainWindow : public QMainWindow
        {
            Q_OBJECT

        public:
            explicit MainWindow(QWidget* parent = nullptr);
            ~MainWindow();

        protected:
            void closeEvent(QCloseEvent* event) override;
            void keyPressEvent(QKeyEvent* event) override;

        private slots:
            // ... (giữ nguyên tất cả slots)
            void onFileOpen();
            void onFileSave();
            void onFileSaveAs();
            void onFileExport();
            void onFileClose();
            void onFileQuit();

            void onEditCopy();
            void onEditFind();
            void onEditFindNext();
            void onEditMarkPacket();
            void onEditMarkAll();
            void onEditUnmarkAll();
            void onEditPreferences();

            void onViewZoomIn();
            void onViewZoomOut();
            void onViewResetZoom();
            void onViewFullScreen();
            void onViewColoringRules();
            void onViewTimeDisplay();
            void onViewNameResolution();

            void onGoToPacket();
            void onGoFirstPacket();
            void onGoLastPacket();
            void onGoNextPacket();
            void onGoPreviousPacket();
            void onGoNextMarked();
            void onGoPreviousMarked();

            void onCaptureStart();
            void onCaptureStop();
            void onCaptureRestart();
            void onCaptureOptions();
            void onCaptureInterfaces();

            void onAnalyzeDisplayFilters();
            void onAnalyzeCaptureFilters();
            void onAnalyzeFollowTCPStream();
            void onAnalyzeFollowUDPStream();
            void onAnalyzeExpertInfo();
            void onAnalyzeConversations();
            void onAnalyzeEndpoints();
            void onAnalyzeProtocolHierarchy();

            void onStatisticsSummary();
            void onStatisticsProtocolHierarchy();
            void onStatisticsConversations();
            void onStatisticsEndpoints();
            void onStatisticsIOGraph();
            void onStatisticsFlowGraph();
            void onStatisticsHTTP();
            void onStatisticsDNS();

            void onToolsFirewall();
            void onToolsCredentials();
            void onToolsLua();

            void onHelpContents();
            void onHelpWebsite();
            void onHelpAbout();

            void onPacketCaptured(const Common::ParsedPacket& packet);
            void onPacketSelected(int row);
            void onPacketDoubleClicked(int row);
            void onFilterChanged(const QString& filter);
            void onFilterApplied();

            void updateStatusBar();
            void updateWindowTitle();
            void updatePacketCount();
            void updateCaptureTime();

        private:
            void setupUI();
            void setupMenuBar();
            void setupToolBar();
            void setupStatusBar();
            void setupConnections();

            void loadSettings();
            void saveSettings();
            void applyTheme();

            void startCapture(const std::string& interface);
            void stopCapture();
            void clearPackets();
            void loadPcapFile(const QString& filename);
            void savePcapFile(const QString& filename);

            void processPacket(const Common::ParsedPacket& packet);
            void applyFilter();
            void updatePacketList();

            // ==================== MEMBER VARIABLES (CORRECT ORDER) ====================
            
            // ✅ 1. PRIMITIVE TYPES FIRST (no dependencies)
            bool is_capturing_;
            bool is_live_capture_;
            int selected_packet_index_;
            uint64_t capture_start_time_;
            double capture_duration_;
            
            // ✅ 2. ATOMICS (no dependencies)
            std::atomic<uint64_t> packet_count_;
            std::atomic<uint64_t> displayed_count_;
            std::atomic<uint64_t> marked_count_;
            std::atomic<uint64_t> bytes_captured_;
            
            // ✅ 3. STRINGS (no dependencies)
            QString current_file_;
            QString current_interface_;
            QString current_filter_;
            
            // ✅ 4. SETTINGS STRUCT
            struct Settings {
                QStringList recent_files;
                QStringList recent_filters;
                QString last_directory;
                QString last_interface;
                bool auto_scroll;
                bool show_hex;
                bool resolve_names;
                int font_size;
                QString theme;
            } settings_;
            
            // ✅ 5. CONTAINERS (depend on primitives)
            struct PacketData {
                Common::ParsedPacket parsed;
                std::vector<uint8_t> raw_data;
                uint64_t timestamp;
                size_t index;
                bool marked;
                bool filtered;
            };
            
            std::vector<PacketData> packets_;
            std::vector<size_t> filtered_indices_;
            
            // ✅ 6. UNIQUE_PTR (core components - no Qt parent)
            std::unique_ptr<Common::PacketParser> packet_parser_;
            std::unique_ptr<Layer1::Filter::PacketFilter> packet_filter_;
            std::unique_ptr<Layer1::PacketIngress> packet_ingress_;
            
            // ✅ 7. QT WIDGETS (will be created with 'this' as parent)
            // Main layout
            QSplitter* main_splitter_;
            QSplitter* detail_splitter_;
            
            // Main widgets
            PacketListWidget* packet_list_;
            PacketDetailWidget* packet_detail_;
            PacketHexWidget* packet_hex_;
            FilterBarWidget* filter_bar_;
            StatusBarWidget* status_bar_;
            
            // ✅ 8. QT MENUS (created with menuBar())
            QMenu* file_menu_;
            QMenu* edit_menu_;
            QMenu* view_menu_;
            QMenu* go_menu_;
            QMenu* capture_menu_;
            QMenu* analyze_menu_;
            QMenu* statistics_menu_;
            QMenu* tools_menu_;
            QMenu* help_menu_;
            
            // ✅ 9. QT TOOLBARS (created with addToolBar())
            QToolBar* main_toolbar_;
            QToolBar* display_toolbar_;
            
            // ✅ 10. QT DIALOGS (created on demand)
            CaptureDialog* capture_dialog_;
            PreferencesDialog* preferences_dialog_;
            
            // ✅ 11. QT ACTIONS (created in setupMenuBar)
            // File actions
            QAction* action_open_;
            QAction* action_save_;
            QAction* action_save_as_;
            QAction* action_export_;
            QAction* action_close_;
            QAction* action_quit_;
            
            // Edit actions
            QAction* action_copy_;
            QAction* action_find_;
            QAction* action_find_next_;
            QAction* action_mark_packet_;
            QAction* action_mark_all_;
            QAction* action_unmark_all_;
            QAction* action_preferences_;
            
            // View actions
            QAction* action_zoom_in_;
            QAction* action_zoom_out_;
            QAction* action_reset_zoom_;
            QAction* action_fullscreen_;
            QAction* action_coloring_rules_;
            QAction* action_time_display_;
            QAction* action_name_resolution_;
            
            // Go actions
            QAction* action_go_to_packet_;
            QAction* action_first_packet_;
            QAction* action_last_packet_;
            QAction* action_next_packet_;
            QAction* action_previous_packet_;
            
            // Capture actions
            QAction* action_start_capture_;
            QAction* action_stop_capture_;
            QAction* action_restart_capture_;
            QAction* action_capture_options_;
            QAction* action_capture_interfaces_;
            
            // Analyze actions
            QAction* action_follow_tcp_;
            QAction* action_follow_udp_;
            QAction* action_expert_info_;
            
            // ✅ 12. QT TIMERS (created last)
            QTimer* capture_timer_;
            QTimer* stats_timer_;
            
            // Constants
            static constexpr int MAX_RECENT_FILES = 10;
            static constexpr int UPDATE_INTERVAL_MS = 100;
            static constexpr size_t MAX_PACKETS_IN_MEMORY = 1000000;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // MAIN_WINDOW_HPP
