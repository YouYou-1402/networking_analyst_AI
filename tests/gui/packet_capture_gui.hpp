// packet_capture_gui.hpp
#ifndef PACKET_CAPTURE_GUI_HPP
#define PACKET_CAPTURE_GUI_HPP

#include <QMainWindow>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QTimer>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QThread>
#include <QMutex>
#include <QQueue>
#include <memory>
#include <atomic>

#include "packet_ingress.hpp"
#include "packet_parser.hpp"

using namespace NetworkSecurity::Layer1;
using namespace NetworkSecurity::Common;

/**
 * @brief Worker thread để capture packets
 */
class CaptureWorker : public QObject {
    Q_OBJECT

public:
    explicit CaptureWorker(const IngressConfig& config);
    ~CaptureWorker();

public slots:
    void startCapture();
    void stopCapture();

signals:
    void packetCaptured(const ParsedPacket& packet);
    void statsUpdated(const IngressStats& stats);
    void errorOccurred(const QString& error);
    void captureStarted();
    void captureStopped();

private:
    void packetCallback(const ParsedPacket& packet);
    
    std::unique_ptr<PacketIngress> ingress_;
    IngressConfig config_;
    std::atomic<bool> running_;
};

/**
 * @brief Main GUI Window
 */
class PacketCaptureGUI : public QMainWindow {
    Q_OBJECT

public:
    explicit PacketCaptureGUI(QWidget* parent = nullptr);
    ~PacketCaptureGUI();

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    // Control slots
    void onStartCapture();
    void onStopCapture();
    void onClearPackets();
    void onExportPackets();
    void onApplyFilter();
    void onInterfaceChanged(int index);
    
    // Packet handling
    void onPacketReceived(const ParsedPacket& packet);
    void onStatsUpdated(const IngressStats& stats);
    void onErrorOccurred(const QString& error);
    
    // Table interaction
    void onPacketSelected(int row, int column);
    void onPacketDoubleClicked(int row, int column);
    
    // Timer
    void updateUI();

private:
    // UI Setup
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void setupStatusBar();
    void setupControlPanel();
    void setupPacketTable();
    void setupDetailPanel();
    void setupHexView();
    
    // Helper functions
    void loadInterfaces();
    void updatePacketTable(const ParsedPacket& packet);
    void updatePacketDetails(const ParsedPacket& packet);
    void updateHexView(const ParsedPacket& packet);
    void updateStatistics(const IngressStats& stats);
    QString formatTimestamp(uint64_t timestamp_us);
    QString formatBytes(uint64_t bytes);
    QColor getProtocolColor(const QString& protocol);
    QString getProtocolIcon(const QString& protocol);
    
    // Capture control
    void startCaptureThread();
    void stopCaptureThread();
    
private:
    // UI Components - Control Panel
    QComboBox* interfaceCombo_;
    QLineEdit* bpfFilterEdit_;
    QPushButton* startButton_;
    QPushButton* stopButton_;
    QPushButton* clearButton_;
    QPushButton* exportButton_;
    QCheckBox* promiscuousCheck_;
    QSpinBox* snaplenSpin_;
    
    // Packet Table
    QTableWidget* packetTable_;
    int packetCount_;
    
    // Detail Panel
    QTextEdit* detailText_;
    
    // Hex View
    QTextEdit* hexView_;
    
    // Statistics Labels
    QLabel* packetsReceivedLabel_;
    QLabel* packetsDroppedLabel_;
    QLabel* bytesReceivedLabel_;
    QLabel* captureRateLabel_;
    QLabel* statusLabel_;
    
    // Capture Thread
    QThread* captureThread_;
    CaptureWorker* captureWorker_;
    
    // Data
    QQueue<ParsedPacket> packetQueue_;
    QMutex queueMutex_;
    std::vector<ParsedPacket> capturedPackets_;
    
    // Timer
    QTimer* updateTimer_;
    
    // State
    bool isCapturing_;
    IngressConfig currentConfig_;
};

#endif // PACKET_CAPTURE_GUI_HPP
