// tests/gui/main_window.hpp
#ifndef MAIN_WINDOW_HPP
#define MAIN_WINDOW_HPP

#include <QMainWindow>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QTextEdit>
#include <QCheckBox>
#include <QTimer>
#include <QStatusBar>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QProgressBar>
#include <QToolBar>
#include <QDialog>
#include <QTreeWidget>
#include <QScrollBar>
#include <memory>
#include <atomic>
#include <thread>
#include <algorithm>
#include <mutex>
#include <vector>
#include <chrono>

#include "packet_index.hpp"
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/core/layer1/packet_filter.hpp"
#include "../../src/core/storage/packet_storage.hpp"
#include "../../src/common/packet_parser.hpp"

using namespace NetworkSecurity::Layer1;
using namespace NetworkSecurity::Common;
using namespace NetworkSecurity::Core::Storage;
using namespace NetworkSecurity::GUI;

// ==================== Packet Detail Dialog ====================

class PacketDetailDialog : public QDialog
{
    Q_OBJECT
    
public:
    explicit PacketDetailDialog(const ParsedPacket& packet, QWidget *parent = nullptr);
    
private:
    void setupUI();
    void displayPacketDetails(const ParsedPacket& packet);
    void addEthernetLayer(const ParsedPacket& packet);
    void addIPv4Layer(const ParsedPacket& packet);
    void addIPv6Layer(const ParsedPacket& packet);
    void addTCPLayer(const ParsedPacket& packet);
    void addUDPLayer(const ParsedPacket& packet);
    void addICMPLayer(const ParsedPacket& packet);
    void addARPLayer(const ParsedPacket& packet);
    void displayHexDump(const ParsedPacket& packet);
    
    QTreeWidget* m_detailTree;
    QTextEdit* m_hexDump;
    const ParsedPacket& m_packet;
};

// ==================== Main Window ====================

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Capture controls
    void onStartCapture();
    void onStopCapture();
    void onPauseCapture();
    void onClearPackets();
    void onSavePackets();
    
    // Filter controls
    void onApplyFilter();
    void onClearFilter();
    void onQuickFilter(const QString &text);
    
    // UI updates
    void updateStatistics();
    void updatePacketTable();
    void onPacketSelected(int row, int column);
    void onPacketDoubleClicked(int row, int column);
    void onTableScrolled(int value);
    
    // File operations
    void onLoadPcap();
    void onAbout();
    void onExportStatistics();

private:
    // UI Setup
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void setupCapturePanel();
    void setupFilterPanel();
    void setupPacketTable();
    void setupDetailPanel();
    void setupStatisticsPanel();
    void setupStatusBar();
    
    // Helper functions
    void loadNetworkInterfaces();
    void addPacketToTable(const PacketIndex* index, size_t packet_num);
    void addLivePacketToTable(const ParsedPacket &packet, size_t packet_num);
    void displayPacketDetails(const ParsedPacket &packet);
    void loadVisiblePackets();
    void updateFilterStatistics();
    QString formatBytes(uint64_t bytes);
    QString getProtocolColor(const QString &protocol);
    
    // Packet callback
    void handlePacket(const ParsedPacket &packet);

private:
    // Core components
    std::unique_ptr<PacketIngress> m_ingress;
    std::unique_ptr<AdvancedFilterManager> m_filter_manager;
    std::unique_ptr<PacketStorage> m_storage;
    std::unique_ptr<PacketParser> m_parser;
    std::unique_ptr<PcapIndexManager> m_index_manager;
    
    // Capture state
    std::atomic<bool> m_is_capturing{false};
    std::atomic<bool> m_is_paused{false};
    std::atomic<uint64_t> m_total_packets{0};
    std::atomic<uint64_t> m_matched_packets{0};
    std::atomic<uint64_t> m_filtered_packets{0};
    std::atomic<uint64_t> m_total_bytes{0};
    
    std::chrono::steady_clock::time_point m_start_time;
    
    // Packet storage
    std::vector<ParsedPacket> m_packets;
    std::mutex m_packets_mutex;
    
    bool m_is_file_mode{false};
    int m_last_scroll_pos{0};
    
    // UI Components - Menu
    QMenu *m_fileMenu;
    QMenu *m_captureMenu;
    QMenu *m_helpMenu;
    
    QAction *m_loadAction;
    QAction *m_saveAction;
    QAction *m_exportAction;
    QAction *m_exitAction;
    QAction *m_startAction;
    QAction *m_stopAction;
    QAction *m_aboutAction;
    
    // UI Components - Toolbar
    QToolBar *m_toolBar;
    
    // UI Components - Capture Panel
    QGroupBox *m_captureGroup;
    QComboBox *m_interfaceCombo;
    QPushButton *m_startButton;
    QPushButton *m_stopButton;
    QPushButton *m_pauseButton;
    QPushButton *m_clearButton;
    QCheckBox *m_promiscuousCheck;
    QCheckBox *m_saveToFileCheck;
    QLineEdit *m_savePathEdit;
    QPushButton *m_browseButton;
    
    // UI Components - Filter Panel
    QGroupBox *m_filterGroup;
    QLineEdit *m_filterEdit;
    QPushButton *m_applyFilterButton;
    QPushButton *m_clearFilterButton;
    QComboBox *m_quickFilterCombo;
    
    // UI Components - Packet Table
    QTableWidget *m_packetTable;
    
    // UI Components - Detail Panel
    QGroupBox *m_detailGroup;
    QTextEdit *m_detailText;
    
    // UI Components - Statistics Panel
    QGroupBox *m_statsGroup;
    QLabel *m_totalPacketsLabel;
    QLabel *m_matchedPacketsLabel;
    QLabel *m_filteredPacketsLabel;
    QLabel *m_totalBytesLabel;
    QLabel *m_durationLabel;
    QLabel *m_rateLabel;
    QProgressBar *m_cpuUsageBar;
    
    // UI Components - Status Bar
    QLabel *m_statusLabel;
    QLabel *m_interfaceLabel;
    
    // Update timer
    QTimer *m_updateTimer;
};

#endif // MAIN_WINDOW_HPP
