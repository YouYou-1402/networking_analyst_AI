// tests/gui/main_window.cpp
#include "main_window.hpp"
#include <QMessageBox>
#include <QFileDialog>
#include <QHeaderView>
#include <QDateTime>
#include <QFont>
#include <QColor>
#include <QInputDialog>
#include <QProgressDialog>
#include <spdlog/spdlog.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUI();
    
    // Khởi tạo components
    m_parser = std::make_unique<PacketParser>();
    m_filter_manager = std::make_unique<AdvancedFilterManager>();
    m_index_manager = std::make_unique<PcapIndexManager>();
    
    // Connect signals
    connect(m_packetTable->verticalScrollBar(), &QScrollBar::valueChanged,
            this, &MainWindow::onTableScrolled);
    connect(m_packetTable, &QTableWidget::cellDoubleClicked,
            this, &MainWindow::onPacketDoubleClicked);
    
    // Update timer
    m_updateTimer = new QTimer(this);
    connect(m_updateTimer, &QTimer::timeout, this, &MainWindow::updateStatistics);
    m_updateTimer->start(1000);
    
    spdlog::info("MainWindow initialized");
}

MainWindow::~MainWindow()
{
    if (m_is_capturing.load()) {
        onStopCapture();
    }
}

// ==================== UI Setup ====================

void MainWindow::setupUI()
{
    setWindowTitle("Network Security AI - Packet Capture & Analysis");
    resize(1400, 900);
    
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    
    setupMenuBar();
    setupToolBar();
    
    // Top panel
    QHBoxLayout *topLayout = new QHBoxLayout();
    setupCapturePanel();
    setupFilterPanel();
    topLayout->addWidget(m_captureGroup, 2);
    topLayout->addWidget(m_filterGroup, 3);
    mainLayout->addLayout(topLayout);
    
    // Middle panel
    QSplitter *middleSplitter = new QSplitter(Qt::Horizontal);
    setupPacketTable();
    setupStatisticsPanel();
    middleSplitter->addWidget(m_packetTable);
    middleSplitter->addWidget(m_statsGroup);
    middleSplitter->setStretchFactor(0, 4);
    middleSplitter->setStretchFactor(1, 1);
    mainLayout->addWidget(middleSplitter, 3);
    
    // Bottom panel
    setupDetailPanel();
    mainLayout->addWidget(m_detailGroup, 1);
    
    setupStatusBar();
}

void MainWindow::setupMenuBar()
{
    // File Menu
    m_fileMenu = menuBar()->addMenu("&File");
    
    m_loadAction = new QAction("&Load PCAP...", this);
    m_loadAction->setShortcut(QKeySequence::Open);
    connect(m_loadAction, &QAction::triggered, this, &MainWindow::onLoadPcap);
    m_fileMenu->addAction(m_loadAction);
    
    m_saveAction = new QAction("&Save Packets...", this);
    m_saveAction->setShortcut(QKeySequence::Save);
    connect(m_saveAction, &QAction::triggered, this, &MainWindow::onSavePackets);
    m_fileMenu->addAction(m_saveAction);
    
    m_exportAction = new QAction("&Export Statistics...", this);
    connect(m_exportAction, &QAction::triggered, this, &MainWindow::onExportStatistics);
    m_fileMenu->addAction(m_exportAction);
    
    m_fileMenu->addSeparator();
    
    m_exitAction = new QAction("E&xit", this);
    m_exitAction->setShortcut(QKeySequence::Quit);
    connect(m_exitAction, &QAction::triggered, this, &QWidget::close);
    m_fileMenu->addAction(m_exitAction);
    
    // Capture Menu
    m_captureMenu = menuBar()->addMenu("&Capture");
    
    m_startAction = new QAction("&Start", this);
    m_startAction->setShortcut(Qt::Key_F5);
    connect(m_startAction, &QAction::triggered, this, &MainWindow::onStartCapture);
    m_captureMenu->addAction(m_startAction);
    
    m_stopAction = new QAction("S&top", this);
    m_stopAction->setShortcut(Qt::Key_F6);
    m_stopAction->setEnabled(false);
    connect(m_stopAction, &QAction::triggered, this, &MainWindow::onStopCapture);
    m_captureMenu->addAction(m_stopAction);
    
    // Help Menu
    m_helpMenu = menuBar()->addMenu("&Help");
    
    m_aboutAction = new QAction("&About", this);
    connect(m_aboutAction, &QAction::triggered, this, &MainWindow::onAbout);
    m_helpMenu->addAction(m_aboutAction);
}

void MainWindow::setupToolBar()
{
    m_toolBar = addToolBar("Main Toolbar");
    m_toolBar->setMovable(false);
    
    m_toolBar->addAction(m_loadAction);
    m_toolBar->addSeparator();
    m_toolBar->addAction(m_startAction);
    m_toolBar->addAction(m_stopAction);
    m_toolBar->addSeparator();
    m_toolBar->addAction(m_saveAction);
}

void MainWindow::setupCapturePanel()
{
    m_captureGroup = new QGroupBox("Capture Settings");
    QVBoxLayout *layout = new QVBoxLayout();
    
    // Interface selection
    QHBoxLayout *ifaceLayout = new QHBoxLayout();
    ifaceLayout->addWidget(new QLabel("Interface:"));
    m_interfaceCombo = new QComboBox();
    loadNetworkInterfaces();
    ifaceLayout->addWidget(m_interfaceCombo, 1);
    layout->addLayout(ifaceLayout);
    
    // Capture options
    m_promiscuousCheck = new QCheckBox("Promiscuous Mode");
    m_promiscuousCheck->setChecked(true);
    layout->addWidget(m_promiscuousCheck);
    
    // Save to file option
    QHBoxLayout *saveLayout = new QHBoxLayout();
    m_saveToFileCheck = new QCheckBox("Save to file:");
    m_savePathEdit = new QLineEdit("./captures/capture.pcap");
    m_browseButton = new QPushButton("Browse...");
    connect(m_browseButton, &QPushButton::clicked, [this]() {
        QString filename = QFileDialog::getSaveFileName(this, "Save Capture File", 
                                                        "./captures", "PCAP Files (*.pcap)");
        if (!filename.isEmpty()) {
            m_savePathEdit->setText(filename);
        }
    });
    saveLayout->addWidget(m_saveToFileCheck);
    saveLayout->addWidget(m_savePathEdit);
    saveLayout->addWidget(m_browseButton);
    layout->addLayout(saveLayout);
    
    // Control buttons
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_startButton = new QPushButton("Start");
    m_startButton->setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;");
    connect(m_startButton, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    
    m_stopButton = new QPushButton("Stop");
    m_stopButton->setStyleSheet("background-color: #f44336; color: white; font-weight: bold;");
    m_stopButton->setEnabled(false);
    connect(m_stopButton, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    
    m_pauseButton = new QPushButton("Pause");
    m_pauseButton->setEnabled(false);
    connect(m_pauseButton, &QPushButton::clicked, this, &MainWindow::onPauseCapture);
    
    m_clearButton = new QPushButton("Clear");
    connect(m_clearButton, &QPushButton::clicked, this, &MainWindow::onClearPackets);
    
    buttonLayout->addWidget(m_startButton);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addWidget(m_pauseButton);
    buttonLayout->addWidget(m_clearButton);
    layout->addLayout(buttonLayout);
    
    m_captureGroup->setLayout(layout);
}

void MainWindow::setupFilterPanel()
{
    m_filterGroup = new QGroupBox("Packet Filter");
    QVBoxLayout *layout = new QVBoxLayout();
    
    // Quick filters
    QHBoxLayout *quickLayout = new QHBoxLayout();
    quickLayout->addWidget(new QLabel("Quick Filter:"));
    m_quickFilterCombo = new QComboBox();
    m_quickFilterCombo->addItem("None");
    m_quickFilterCombo->addItem("TCP");
    m_quickFilterCombo->addItem("UDP");
    m_quickFilterCombo->addItem("ICMP");
    m_quickFilterCombo->addItem("ARP");
    m_quickFilterCombo->addItem("HTTP (port 80)");
    m_quickFilterCombo->addItem("HTTPS (port 443)");
    m_quickFilterCombo->addItem("DNS (port 53)");
    m_quickFilterCombo->addItem("SSH (port 22)");
    connect(m_quickFilterCombo, &QComboBox::currentTextChanged, 
            this, &MainWindow::onQuickFilter);
    quickLayout->addWidget(m_quickFilterCombo, 1);
    layout->addLayout(quickLayout);
    
    // Custom filter
    QHBoxLayout *customLayout = new QHBoxLayout();
    customLayout->addWidget(new QLabel("Custom Filter:"));
    m_filterEdit = new QLineEdit();
    m_filterEdit->setPlaceholderText("e.g., ip.src == 192.168.1.1 && tcp.port == 80");
    connect(m_filterEdit, &QLineEdit::returnPressed, this, &MainWindow::onApplyFilter);
    customLayout->addWidget(m_filterEdit, 1);
    layout->addLayout(customLayout);
    
    // Filter buttons
    QHBoxLayout *filterButtonLayout = new QHBoxLayout();
    m_applyFilterButton = new QPushButton("Apply Filter");
    m_applyFilterButton->setStyleSheet("background-color: #2196F3; color: white;");
    connect(m_applyFilterButton, &QPushButton::clicked, this, &MainWindow::onApplyFilter);
    
    m_clearFilterButton = new QPushButton("Clear Filter");
    connect(m_clearFilterButton, &QPushButton::clicked, this, &MainWindow::onClearFilter);
    
    QPushButton *helpButton = new QPushButton("Help");
    helpButton->setIcon(style()->standardIcon(QStyle::SP_MessageBoxQuestion));
    connect(helpButton, &QPushButton::clicked, this, &MainWindow::showFilterHelp);

    filterButtonLayout->addWidget(m_applyFilterButton);
    filterButtonLayout->addWidget(m_clearFilterButton);
    filterButtonLayout->addWidget(helpButton);
    layout->addLayout(filterButtonLayout);
    
    // Filter examples
    QLabel *examplesLabel = new QLabel(
        "<small><b>Examples:</b><br>"
        "• ip.addr == 192.168.1.1<br>"
        "• tcp.port == 80 || tcp.port == 443<br>"
        "• tcp.flags.syn == 1 && tcp.flags.ack == 0</small>"
    );
    examplesLabel->setWordWrap(true);
    layout->addWidget(examplesLabel);
    
    m_filterGroup->setLayout(layout);
}

void MainWindow::setupPacketTable()
{
    m_packetTable = new QTableWidget();
    m_packetTable->setColumnCount(7);
    m_packetTable->setHorizontalHeaderLabels({
        "No.", "Time", "Protocol", "Source", "Destination", "Length", "Info"
    });
    
    m_packetTable->setColumnWidth(0, 60);
    m_packetTable->setColumnWidth(1, 120);
    m_packetTable->setColumnWidth(2, 80);
    m_packetTable->setColumnWidth(3, 200);
    m_packetTable->setColumnWidth(4, 200);
    m_packetTable->setColumnWidth(5, 80);
    m_packetTable->setColumnWidth(6, 400);
    
    m_packetTable->horizontalHeader()->setStretchLastSection(true);
    m_packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_packetTable->setAlternatingRowColors(true);
    m_packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    connect(m_packetTable, &QTableWidget::cellClicked, 
            this, &MainWindow::onPacketSelected);
}

void MainWindow::setupDetailPanel()
{
    m_detailGroup = new QGroupBox("Packet Details");
    QVBoxLayout *layout = new QVBoxLayout();
    
    m_detailText = new QTextEdit();
    m_detailText->setReadOnly(true);
    m_detailText->setFont(QFont("Courier", 9));
    layout->addWidget(m_detailText);
    
    m_detailGroup->setLayout(layout);
}

void MainWindow::setupStatisticsPanel()
{
    m_statsGroup = new QGroupBox("Statistics");
    QVBoxLayout *layout = new QVBoxLayout();
    
    m_totalPacketsLabel = new QLabel("Total Packets: 0");
    m_matchedPacketsLabel = new QLabel("Displayed: 0");
    m_filteredPacketsLabel = new QLabel("Hidden: 0");
    m_totalBytesLabel = new QLabel("Total Bytes: 0 B");
    m_durationLabel = new QLabel("Duration: 00:00:00");
    m_rateLabel = new QLabel("Rate: 0 pkt/s");
    
    QFont boldFont;
    boldFont.setBold(true);
    m_totalPacketsLabel->setFont(boldFont);
    
    layout->addWidget(m_totalPacketsLabel);
    layout->addWidget(m_matchedPacketsLabel);
    layout->addWidget(m_filteredPacketsLabel);
    layout->addWidget(m_totalBytesLabel);
    layout->addWidget(m_durationLabel);
    layout->addWidget(m_rateLabel);
    
    layout->addSpacing(20);
    
    layout->addWidget(new QLabel("CPU Usage:"));
    m_cpuUsageBar = new QProgressBar();
    m_cpuUsageBar->setRange(0, 100);
    m_cpuUsageBar->setValue(0);
    layout->addWidget(m_cpuUsageBar);
    
    layout->addStretch();
    
    m_statsGroup->setLayout(layout);
}

void MainWindow::setupStatusBar()
{
    m_statusLabel = new QLabel("Ready");
    m_interfaceLabel = new QLabel("Interface: None");
    
    statusBar()->addWidget(m_statusLabel, 1);
    statusBar()->addPermanentWidget(m_interfaceLabel);
}

void MainWindow::loadNetworkInterfaces()
{
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        spdlog::error("Error finding devices: {}", errbuf);
        return;
    }
    
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        QString name = QString::fromUtf8(d->name);
        QString description = d->description ? QString::fromUtf8(d->description) : "No description";
        m_interfaceCombo->addItem(QString("%1 (%2)").arg(name, description), name);
    }
    
    pcap_freealldevs(alldevs);
}

// ==================== Capture Control Slots ====================

void MainWindow::onStartCapture()
{
    if (m_is_capturing.load()) {
        QMessageBox::warning(this, "Warning", "Capture is already running!");
        return;
    }
    
    // Switch to live mode
    m_is_file_mode = false;
    onClearPackets();
    
    QString interface = m_interfaceCombo->currentData().toString();
    if (interface.isEmpty()) {
        QMessageBox::critical(this, "Error", "Please select a network interface!");
        return;
    }
    
    // Configure ingress
    IngressConfig config;
    config.interface = interface.toStdString();
    config.snaplen = 65535;
    config.timeout_ms = 1000;
    config.buffer_size = 10 * 1024 * 1024;
    config.promiscuous = m_promiscuousCheck->isChecked();
    
    m_ingress = std::make_unique<PacketIngress>(config);
    
    if (!m_ingress->initialize()) {
        QMessageBox::critical(this, "Error", "Failed to initialize packet capture!");
        m_ingress.reset();
        return;
    }
    
    // Initialize storage if needed
    if (m_saveToFileCheck->isChecked()) {
        StorageConfig storageConfig;
        storageConfig.output_dir = "./captures";
        storageConfig.file_prefix = "capture";
        storageConfig.enable_rotation = true;
        storageConfig.max_file_size_mb = 100;
        
        m_storage = std::make_unique<PacketStorage>(storageConfig);
        
        if (!m_storage->initialize()) {
            QMessageBox::warning(this, "Warning", "Failed to initialize storage. Continuing without saving.");
            m_storage.reset();
        }
    }
    
    // Start capture thread
    std::thread capture_thread([this]() {
        m_ingress->start([this](const ParsedPacket& packet) {
            this->handlePacket(packet);
        });
    });
    capture_thread.detach();
    
    // Update UI
    m_is_capturing.store(true);
    m_start_time = std::chrono::steady_clock::now();
    
    m_startButton->setEnabled(false);
    m_stopButton->setEnabled(true);
    m_pauseButton->setEnabled(true);
    m_startAction->setEnabled(false);
    m_stopAction->setEnabled(true);
    m_interfaceCombo->setEnabled(false);
    
    m_statusLabel->setText("Capturing packets...");
    m_interfaceLabel->setText(QString("Interface: %1").arg(interface));
    
    spdlog::info("Packet capture started on interface: {}", interface.toStdString());
}

void MainWindow::onStopCapture()
{
    if (!m_is_capturing.load()) {
        return;
    }
    
    m_is_capturing.store(false);
    
    if (m_ingress) {
        m_ingress->stop();
        m_ingress.reset();
    }
    
    if (m_storage) {
        m_storage.reset();
    }
    
    // Update UI
    m_startButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_pauseButton->setEnabled(false);
    m_startAction->setEnabled(true);
    m_stopAction->setEnabled(false);
    m_interfaceCombo->setEnabled(true);
    
    m_statusLabel->setText("Capture stopped");
    
    spdlog::info("Packet capture stopped");
}

void MainWindow::onPauseCapture()
{
    if (!m_is_capturing.load()) {
        return;
    }
    
    m_is_paused.store(!m_is_paused.load());
    
    if (m_is_paused.load()) {
        m_pauseButton->setText("Resume");
        m_statusLabel->setText("Capture paused");
    } else {
        m_pauseButton->setText("Pause");
        m_statusLabel->setText("Capturing packets...");
    }
}

void MainWindow::onClearPackets()
{
    std::lock_guard<std::mutex> lock(m_packets_mutex);
    m_packets.clear();
    m_packetTable->setRowCount(0);
    m_detailText->clear();
    
    m_total_packets.store(0);
    m_matched_packets.store(0);
    m_filtered_packets.store(0);
    m_total_bytes.store(0);
    
    if (m_is_file_mode) {
        m_index_manager->clear();
        m_is_file_mode = false;
    }
    
    updateStatistics();
}

void MainWindow::onSavePackets()
{
    QString filename = QFileDialog::getSaveFileName(this, "Save Packets", 
                                                     "./captures", 
                                                     "PCAP Files (*.pcap);;All Files (*)");
    if (filename.isEmpty()) {
        return;
    }
    
    // Ask user what to save
    QMessageBox::StandardButton reply = QMessageBox::question(
        this, 
        "Save Options",
        "Do you want to save:\n\n"
        "• All captured packets (Yes)\n"
        "• Only displayed packets (No)\n"
        "• Cancel (Cancel)",
        QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel
    );
    
    if (reply == QMessageBox::Cancel) {
        return;
    }
    
    bool save_all = (reply == QMessageBox::Yes);
    
    try {
        PcapWriter writer("./");
        if (!writer.open(filename.toStdString(), DLT_EN10MB)) {
            QMessageBox::critical(this, "Error", "Failed to create PCAP file!");
            return;
        }
        
        size_t saved_count = 0;
        
        if (m_is_file_mode) {
            // File mode - iterate through index
            for (size_t i = 0; i < m_index_manager->getPacketCount(); i++) {
                bool should_save = save_all;
                
                if (!save_all && m_filter_manager) {
                    // Check filter (lightweight)
                    const PacketIndex* idx = m_index_manager->getPacketIndex(i);
                    if (idx) {
                        // Simple filter check based on index
                        should_save = true; // TODO: implement lightweight filter
                    }
                }
                
                if (should_save) {
                    ParsedPacket packet;
                    if (m_index_manager->loadPacket(i, packet)) {
                        writer.writePacket(packet);
                        saved_count++;
                    }
                }
            }
        } else {
            // Live mode - iterate through packets
            std::lock_guard<std::mutex> lock(m_packets_mutex);
            
            for (const auto &packet : m_packets) {
                bool should_save = save_all;
                
                if (!save_all && m_filter_manager) {
                    auto stats = m_filter_manager->getStats();
                    if (!stats.current_filter.empty()) {
                        should_save = m_filter_manager->matchesDisplayFilter(packet);
                    }
                }
                
                if (should_save) {
                    writer.writePacket(packet);
                    saved_count++;
                }
            }
        }
        
        writer.close();
        
        QMessageBox::information(this, "Success", 
                                QString("Saved %1 packets to:\n%2")
                                .arg(saved_count)
                                .arg(filename));
        
        spdlog::info("Saved {} packets to {}", saved_count, filename.toStdString());
        
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Error", 
                             QString("Failed to save packets:\n%1").arg(e.what()));
    }
}

// ==================== Filter Control Slots ====================

void MainWindow::onApplyFilter()
{
    QString filterText = m_filterEdit->text().trimmed();
    
    if (filterText.isEmpty()) {
        onClearFilter();
        return;
    }
    
    if (!isValidFilter(filterText.toStdString())) {
        QMessageBox::warning(this, "Invalid Filter",
            QString("The filter expression '%1' is not supported.\n\n"
                   "Click 'Help' button to see supported syntax.")
            .arg(filterText));
        return;
    }

    try {
        // Set filter in manager
        if (!m_filter_manager->setDisplayFilter(filterText.toStdString())) {
            QMessageBox::critical(this, "Filter Error", "Invalid filter expression!");
            return;
        }
        
        // Apply filter based on mode
        if (m_is_file_mode) {
            // File mode: Use lightweight filter on index
            loadVisiblePackets();
        } else {
            // Live mode: Filter existing packets in memory
            updatePacketTable();
        }
        
        // Update status with correct counts
        size_t matched = m_matched_packets.load();
        size_t total = m_total_packets.load();
        double match_rate = total > 0 ? (matched * 100.0 / total) : 0.0;
        
        m_statusLabel->setText(QString("Filter applied: %1 (showing %2/%3 packets, %4%)")
                              .arg(filterText)
                              .arg(matched)
                              .arg(total)
                              .arg(match_rate, 0, 'f', 1));
        
        spdlog::info("Filter applied: {} - Mode: {} - Showing {}/{} packets ({:.1f}%)", 
                    filterText.toStdString(),
                    m_is_file_mode ? "file" : "live",
                    matched,
                    total,
                    match_rate);
        
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Filter Error", 
                             QString("Invalid filter expression:\n%1").arg(e.what()));
        spdlog::error("Filter error: {}", e.what());
    }
}

void MainWindow::onClearFilter()
{
    m_filterEdit->clear();
    m_quickFilterCombo->setCurrentIndex(0);
    
    if (m_is_file_mode) {
        loadVisiblePackets();
    } else {
        updatePacketTable();
    }
    
    updatePacketTable();
    
    m_statusLabel->setText(QString("Filter cleared - Showing all %1 packets")
                          .arg(m_total_packets.load()));
}

void MainWindow::onQuickFilter(const QString &text)
{
    if (text == "None") {
        m_filterEdit->clear();
        onClearFilter();
        return;
    }
    
    QString filter;
    if (text == "TCP") {
        filter = "tcp";
    } else if (text == "UDP") {
        filter = "udp";
    } else if (text == "ICMP") {
        filter = "icmp";
    } else if (text == "ARP") {
        filter = "arp";
    } else if (text == "HTTP (port 80)") {
        filter = "tcp.port == 80";
    } else if (text == "HTTPS (port 443)") {
        filter = "tcp.port == 443";
    } else if (text == "DNS (port 53)") {
        filter = "udp.port == 53";
    } else if (text == "SSH (port 22)") {
        filter = "tcp.port == 22";
    }
    
    m_filterEdit->setText(filter);
    onApplyFilter();
}

// ==================== File Operations ====================

void MainWindow::onLoadPcap()
{
    QString filename = QFileDialog::getOpenFileName(this, "Load PCAP File",
                                                     "./captures",
                                                     "PCAP Files (*.pcap *.pcapng);;All Files (*)");
    if (filename.isEmpty()) {
        return;
    }
    
    // Clear current data
    onClearPackets();
    
    // Build index with progress dialog
    QProgressDialog progress("Building packet index...", "Cancel", 0, 0, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    QApplication::processEvents();
    
    if (!m_index_manager->buildIndex(filename.toStdString())) {
        progress.close();
        QMessageBox::critical(this, "Error", "Failed to build packet index!");
        return;
    }
    
    progress.close();
    
    // Switch to file mode
    m_is_file_mode = true;
    m_total_packets.store(m_index_manager->getPacketCount());
    
    // Load visible packets
    loadVisiblePackets();
    
    QMessageBox::information(this, "Success", 
                            QString("Loaded %1 packets from:\n%2")
                            .arg(m_index_manager->getPacketCount())
                            .arg(filename));
    
    m_statusLabel->setText(QString("Loaded %1 packets (indexed mode)").arg(m_total_packets.load()));
    
    spdlog::info("Loaded PCAP file: {} ({} packets)", 
                 filename.toStdString(), 
                 m_index_manager->getPacketCount());
}

void MainWindow::onAbout()
{
    QMessageBox::about(this, "About Network Security AI",
        "<h2>Network Security AI</h2>"
        "<p>Version 1.0.0</p>"
        "<p>A powerful network packet capture and analysis tool.</p>"
        "<p><b>Features:</b></p>"
        "<ul>"
        "<li>Real-time packet capture</li>"
        "<li>Advanced filtering (Wireshark-like)</li>"
        "<li>Lazy loading for large PCAP files</li>"
        "<li>Detailed packet inspection</li>"
        "<li>Packet storage and export</li>"
        "</ul>"
        "<p>© 2024 NCKH Project</p>"
    );
}

void MainWindow::onExportStatistics()
{
    QString filename = QFileDialog::getSaveFileName(this, "Export Statistics",
                                                     "./statistics.txt",
                                                     "Text Files (*.txt);;All Files (*)");
    if (filename.isEmpty()) {
        return;
    }
    
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Failed to create file!");
        return;
    }
    
    QTextStream out(&file);
    out << "Network Security AI - Statistics Report\n";
    out << "========================================\n\n";
    out << "Total Packets: " << m_total_packets.load() << "\n";
    out << "Displayed Packets: " << m_matched_packets.load() << "\n";
    out << "Hidden Packets: " << m_filtered_packets.load() << "\n";
    out << "Total Bytes: " << formatBytes(m_total_bytes.load()) << "\n";
    out << "\nMode: " << (m_is_file_mode ? "File" : "Live Capture") << "\n";
    
    if (m_is_file_mode) {
        out << "File: " << QString::fromStdString(m_index_manager->getPcapFile()) << "\n";
    }
    
    file.close();
    
    QMessageBox::information(this, "Success", 
                            QString("Statistics exported to:\n%1").arg(filename));
}

// ==================== UI Update Functions ====================

void MainWindow::updateStatistics()
{
    // Total packets
    m_totalPacketsLabel->setText(QString("Total Packets: %1")
                                 .arg(m_total_packets.load()));
    
    // Displayed packets
    size_t matched = m_matched_packets.load();
    size_t total = m_total_packets.load();
    double match_rate = total > 0 ? (matched * 100.0 / total) : 0.0;
    
    m_matchedPacketsLabel->setText(QString("Displayed: %1 (%.1f%%)")
                                   .arg(matched)
                                   .arg(match_rate, 0, 'f', 1));
    
    // Hidden packets
    m_filteredPacketsLabel->setText(QString("Hidden: %1")
                                    .arg(m_filtered_packets.load()));
    
    m_totalBytesLabel->setText(QString("Total Bytes: %1")
                               .arg(formatBytes(m_total_bytes.load())));
    
    if (m_is_capturing.load()) {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - m_start_time);
        
        int hours = duration.count() / 3600;
        int minutes = (duration.count() % 3600) / 60;
        int seconds = duration.count() % 60;
        
        m_durationLabel->setText(QString("Duration: %1:%2:%3")
                                .arg(hours, 2, 10, QChar('0'))
                                .arg(minutes, 2, 10, QChar('0'))
                                .arg(seconds, 2, 10, QChar('0')));
        
        if (duration.count() > 0) {
            double rate = static_cast<double>(m_total_packets.load()) / duration.count();
            m_rateLabel->setText(QString("Rate: %1 pkt/s").arg(rate, 0, 'f', 2));
        }
    }
}

void MainWindow::updatePacketTable()
{
    m_packetTable->setRowCount(0);
    
    if (m_is_file_mode) {
        loadVisiblePackets();
    } else {
        // Live mode - filter existing packets
        std::lock_guard<std::mutex> lock(m_packets_mutex);
        
        size_t displayed = 0;
        for (size_t i = 0; i < m_packets.size(); i++) {
            bool should_display = true;
            
            if (m_filter_manager) {
                auto stats = m_filter_manager->getStats();
                if (!stats.current_filter.empty()) {
                    should_display = m_filter_manager->matchesDisplayFilter(m_packets[i]);
                }
            }
            
            if (should_display) {
                addLivePacketToTable(m_packets[i], i + 1);
                displayed++;
            }
        }
        
        m_matched_packets.store(displayed);
        m_filtered_packets.store(m_packets.size() - displayed);
    }
}

void MainWindow::loadVisiblePackets()
{
    if (!m_is_file_mode) return;
    
    m_packetTable->setRowCount(0);
    
    size_t total = m_index_manager->getPacketCount();
    size_t displayed = 0;
    size_t hidden = 0;
    
    // Get current filter
    std::string current_filter;
    if (m_filter_manager) {
        auto stats = m_filter_manager->getStats();
        current_filter = stats.current_filter;
    }
    
    spdlog::debug("Loading packets with filter: '{}'", current_filter);
    
    // Load and filter packets
    for (size_t i = 0; i < total; i++) {
        const PacketIndex* index = m_index_manager->getPacketIndex(i);
        if (!index) continue;
        
        bool should_display = true;
        
        // Apply lightweight filter on PacketIndex
        if (!current_filter.empty()) {
            should_display = m_index_manager->matchesSimpleFilter(i, current_filter);
        }
        
        if (should_display) {
            addPacketToTable(index, i + 1);
            displayed++;
        } else {
            hidden++;
        }
    }
    
    // Update counters
    m_matched_packets.store(displayed);
    m_filtered_packets.store(hidden);
    
    spdlog::info("Loaded packets: {} displayed, {} hidden out of {} total", 
                 displayed, hidden, total);
}

void MainWindow::addPacketToTable(const PacketIndex* index, size_t packet_num)
{
    int row = m_packetTable->rowCount();
    m_packetTable->insertRow(row);
    
    // No.
    QTableWidgetItem *numItem = new QTableWidgetItem(QString::number(packet_num));
    numItem->setData(Qt::UserRole, QVariant::fromValue(packet_num - 1));
    m_packetTable->setItem(row, 0, numItem);
    
    // Time
    auto time = QDateTime::fromMSecsSinceEpoch(index->timestamp_us / 1000);
    m_packetTable->setItem(row, 1, new QTableWidgetItem(time.toString("hh:mm:ss.zzz")));
    
    // Protocol
    QString protocol = QString::fromStdString(index->protocol);
    QTableWidgetItem *protoItem = new QTableWidgetItem(protocol);
    protoItem->setForeground(QColor(getProtocolColor(protocol)));
    m_packetTable->setItem(row, 2, protoItem);
    
    // Source
    QString source = QString::fromStdString(index->src_addr);
    if (index->src_port > 0) {
        source += QString(":%1").arg(index->src_port);
    }
    m_packetTable->setItem(row, 3, new QTableWidgetItem(source));
    
    // Destination
    QString dest = QString::fromStdString(index->dst_addr);
    if (index->dst_port > 0) {
        dest += QString(":%1").arg(index->dst_port);
    }
    m_packetTable->setItem(row, 4, new QTableWidgetItem(dest));
    
    // Length
    m_packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(index->packet_length)));
    
    // Info
    QString info;
    if (index->src_port > 0 && index->dst_port > 0) {
        info = QString("%1:%2 → %3:%4")
               .arg(QString::fromStdString(index->src_addr))
               .arg(index->src_port)
               .arg(QString::fromStdString(index->dst_addr))
               .arg(index->dst_port);
    } else {
        info = QString("%1 → %2")
               .arg(QString::fromStdString(index->src_addr))
               .arg(QString::fromStdString(index->dst_addr));
    }
    m_packetTable->setItem(row, 6, new QTableWidgetItem(info));
}

void MainWindow::addLivePacketToTable(const ParsedPacket &packet, size_t packet_num)
{
    int row = m_packetTable->rowCount();
    m_packetTable->insertRow(row);
    
    // No.
    QTableWidgetItem *numItem = new QTableWidgetItem(QString::number(packet_num));
    numItem->setData(Qt::UserRole, QVariant::fromValue(packet_num - 1));
    m_packetTable->setItem(row, 0, numItem);
    
    // Time
    auto time = QDateTime::fromMSecsSinceEpoch(packet.timestamp / 1000);
    m_packetTable->setItem(row, 1, new QTableWidgetItem(time.toString("hh:mm:ss.zzz")));
    
    // Protocol
    QString protocol;
    if (packet.has_tcp) protocol = "TCP";
    else if (packet.has_udp) protocol = "UDP";
    else if (packet.has_icmp) protocol = "ICMP";
    else if (packet.has_arp) protocol = "ARP";
    else if (packet.has_ipv6) protocol = "IPv6";
    else if (packet.has_ipv4) protocol = "IPv4";
    else protocol = "Ethernet";
    
    QTableWidgetItem *protoItem = new QTableWidgetItem(protocol);
    protoItem->setForeground(QColor(getProtocolColor(protocol)));
    m_packetTable->setItem(row, 2, protoItem);
    
    // Source
    QString source;
    if (packet.has_ipv4) {
        source = QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.src_ip));
        if (packet.has_tcp) {
            source += QString(":%1").arg(ntohs(packet.tcp.src_port));
        } else if (packet.has_udp) {
            source += QString(":%1").arg(ntohs(packet.udp.src_port));
        }
    } else if (packet.has_ipv6) {
        source = QString::fromStdString(PacketParser::ipv6ToString(packet.ipv6.src_ip));
    } else if (packet.has_ethernet) {
        source = QString::fromStdString(PacketParser::macToString(packet.ethernet.src_mac));
    }
    m_packetTable->setItem(row, 3, new QTableWidgetItem(source));
    
    // Destination
    QString dest;
    if (packet.has_ipv4) {
        dest = QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.dst_ip));
        if (packet.has_tcp) {
            dest += QString(":%1").arg(ntohs(packet.tcp.dst_port));
        } else if (packet.has_udp) {
            dest += QString(":%1").arg(ntohs(packet.udp.dst_port));
        }
    } else if (packet.has_ipv6) {
        dest = QString::fromStdString(PacketParser::ipv6ToString(packet.ipv6.dst_ip));
    } else if (packet.has_ethernet) {
        dest = QString::fromStdString(PacketParser::macToString(packet.ethernet.dst_mac));
    }
    m_packetTable->setItem(row, 4, new QTableWidgetItem(dest));
    
    // Length
    m_packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(packet.captured_length)));
    
    // Info
    QString info;
    if (packet.has_tcp) {
        info = QString("Seq=%1 Ack=%2")
               .arg(ntohl(packet.tcp.seq_number))
               .arg(ntohl(packet.tcp.ack_number));
        
        QStringList flags;
        if (packet.tcp.flags & 0x02) flags << "SYN";
        if (packet.tcp.flags & 0x10) flags << "ACK";
        if (packet.tcp.flags & 0x01) flags << "FIN";
        if (packet.tcp.flags & 0x04) flags << "RST";
        if (!flags.isEmpty()) {
            info += " [" + flags.join(",") + "]";
        }
    } else if (packet.has_udp) {
        info = QString("Len=%1").arg(ntohs(packet.udp.length));
    } else if (packet.has_icmp) {
        info = QString("Type=%1 Code=%2")
               .arg(packet.icmp.type)
               .arg(packet.icmp.code);
    }
    m_packetTable->setItem(row, 6, new QTableWidgetItem(info));
}

void MainWindow::onPacketSelected(int row, int column)
{
    Q_UNUSED(column);
    
    if (row < 0) return;
    
    QVariant data = m_packetTable->item(row, 0)->data(Qt::UserRole);
    size_t packet_index = data.toULongLong();
    
    if (m_is_file_mode) {
        // Load packet from file
        ParsedPacket packet;
        if (m_index_manager->loadPacket(packet_index, packet)) {
            displayPacketDetails(packet);
        }
    } else {
        // Get from memory
        std::lock_guard<std::mutex> lock(m_packets_mutex);
        if (packet_index < m_packets.size()) {
            displayPacketDetails(m_packets[packet_index]);
        }
    }
}

void MainWindow::onPacketDoubleClicked(int row, int column)
{
    Q_UNUSED(column);
    
    if (row < 0) return;
    
    QVariant data = m_packetTable->item(row, 0)->data(Qt::UserRole);
    size_t packet_index = data.toULongLong();
    
    ParsedPacket packet;
    bool loaded = false;
    
    if (m_is_file_mode) {
        loaded = m_index_manager->loadPacket(packet_index, packet);
    } else {
        std::lock_guard<std::mutex> lock(m_packets_mutex);
        if (packet_index < m_packets.size()) {
            packet = m_packets[packet_index];
            loaded = true;
        }
    }
    
    if (loaded) {
        PacketDetailDialog dialog(packet, this);
        dialog.exec();
    } else {
        QMessageBox::warning(this, "Error", "Failed to load packet details!");
    }
}

void MainWindow::onTableScrolled(int value)
{
    Q_UNUSED(value);
    // For future optimization: load packets on-demand when scrolling
}

void MainWindow::displayPacketDetails(const ParsedPacket &packet)
{
    QString details;
    
    details += "=== Packet Details ===\n\n";
    
    // Frame info
    details += QString("Frame: %1 bytes\n")
               .arg(packet.captured_length);
    details += QString("Capture Time: %1\n\n")
               .arg(QDateTime::fromMSecsSinceEpoch(packet.timestamp / 1000)
                    .toString("yyyy-MM-dd hh:mm:ss.zzz"));
    
    // Ethernet
    if (packet.has_ethernet) {
        details += "--- Ethernet II ---\n";
        details += QString("  Source: %1\n")
                   .arg(QString::fromStdString(PacketParser::macToString(packet.ethernet.src_mac)));
        details += QString("  Destination: %1\n")
                   .arg(QString::fromStdString(PacketParser::macToString(packet.ethernet.dst_mac)));
        details += QString("  Type: 0x%1\n\n")
                   .arg(ntohs(packet.ethernet.ether_type), 4, 16, QChar('0'));
    }
    
    // IPv4
    if (packet.has_ipv4) {
        details += "--- Internet Protocol Version 4 ---\n";
        details += QString("  Source: %1\n")
                   .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.src_ip)));
        details += QString("  Destination: %1\n")
                   .arg(QString::fromStdString(PacketParser::ipv4ToString(packet.ipv4.dst_ip)));
        details += QString("  Protocol: %1\n").arg(packet.ipv4.protocol);
        details += QString("  TTL: %1\n").arg(packet.ipv4.ttl);
        details += QString("  Total Length: %1\n\n").arg(ntohs(packet.ipv4.total_length));
    }
    
    // TCP
    if (packet.has_tcp) {
        details += "--- Transmission Control Protocol ---\n";
        details += QString("  Source Port: %1\n").arg(ntohs(packet.tcp.src_port));
        details += QString("  Destination Port: %1\n").arg(ntohs(packet.tcp.dst_port));
        details += QString("  Sequence Number: %1\n").arg(ntohl(packet.tcp.seq_number));
        details += QString("  Acknowledgment Number: %1\n").arg(ntohl(packet.tcp.ack_number));
        details += QString("  Window Size: %1\n").arg(ntohs(packet.tcp.window_size));
        details += QString("  Flags: 0x%1 ").arg(packet.tcp.flags, 2, 16, QChar('0'));
        
        QStringList flags;
        if (packet.tcp.flags & 0x01) flags << "FIN";
        if (packet.tcp.flags & 0x02) flags << "SYN";
        if (packet.tcp.flags & 0x04) flags << "RST";
        if (packet.tcp.flags & 0x08) flags << "PSH";
        if (packet.tcp.flags & 0x10) flags << "ACK";
        if (packet.tcp.flags & 0x20) flags << "URG";
        if (!flags.isEmpty()) {
            details += QString("[%1]").arg(flags.join(", "));
        }
        details += "\n\n";
    }
    
    // UDP
    if (packet.has_udp) {
        details += "--- User Datagram Protocol ---\n";
        details += QString("  Source Port: %1\n").arg(ntohs(packet.udp.src_port));
        details += QString("  Destination Port: %1\n").arg(ntohs(packet.udp.dst_port));
        details += QString("  Length: %1\n\n").arg(ntohs(packet.udp.length));
    }
    
    // Payload preview
    if (packet.payload_length > 0) {
        details += QString("--- Payload (%1 bytes) ---\n").arg(packet.payload_length);
        size_t preview_len = std::min(static_cast<size_t>(packet.payload_length), static_cast<size_t>(64));
        
        for (size_t i = 0; i < preview_len; i += 16) {
            details += QString("%1  ").arg(i, 4, 16, QChar('0'));
            
            for (size_t j = 0; j < 16 && (i + j) < preview_len; j++) {
                details += QString("%1 ").arg(static_cast<unsigned char>(packet.payload[i + j]), 2, 16, QChar('0'));
            }
            details += "\n";
        }
        
        if (packet.payload_length > 64) {
            details += QString("... (%1 more bytes)\n").arg(packet.payload_length - 64);
        }
    }
    
    m_detailText->setPlainText(details);
}

// ==================== Packet Callback ====================

void MainWindow::handlePacket(const ParsedPacket &packet)
{
    if (m_is_paused.load()) {
        return;
    }
    
    m_total_packets.fetch_add(1);
    m_total_bytes.fetch_add(packet.captured_length);
    
    // Store ALL packets
    {
        std::lock_guard<std::mutex> lock(m_packets_mutex);
        m_packets.push_back(packet);
    }
    
    // Save to file (all packets)
    if (m_storage) {
        m_storage->savePacket(packet);
    }
    
    // Filter for display only
    bool should_display = true;
    if (m_filter_manager) {
        auto stats = m_filter_manager->getStats();
        if (!stats.current_filter.empty()) {
            should_display = m_filter_manager->matches(packet);
            if (should_display) {
                m_matched_packets.fetch_add(1);
            } else {
                m_filtered_packets.fetch_add(1);
            }
        } else {
            m_matched_packets.fetch_add(1);
        }
    } else {
        m_matched_packets.fetch_add(1);
    }
    
    // Update GUI (only if matches filter)
    if (should_display) {
        QMetaObject::invokeMethod(this, [this, packet]() {
            size_t packet_num = m_total_packets.load();
            addLivePacketToTable(packet, packet_num);
            m_packetTable->scrollToBottom();
        }, Qt::QueuedConnection);
    }
}

// ==================== Helper Functions ====================

bool MainWindow::isValidFilter(const std::string& filter)
{
    if (filter.empty()) return true;
    
    // Simple validation
    std::string lower = filter;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for supported protocols
    if (lower == "tcp" || lower == "udp" || lower == "icmp" || 
        lower == "arp" || lower == "ipv4" || lower == "ipv6") {
        return true;
    }
    
    // Check for port filters
    if (lower.find("tcp.port") != std::string::npos ||
        lower.find("udp.port") != std::string::npos) {
        return true;
    }
    
    // Check for IP filters
    if (lower.find("ip.addr") != std::string::npos ||
        lower.find("ip.src") != std::string::npos ||
        lower.find("ip.dst") != std::string::npos) {
        return true;
    }
    
    // Check for logical operators
    if (lower.find("&&") != std::string::npos ||
        lower.find("||") != std::string::npos) {
        return true;
    }
    
    return false;
}

void MainWindow::showFilterHelp()
{
    QMessageBox::information(this, "Filter Syntax Help",
        "<h3>Supported Filter Syntax:</h3>"
        "<p><b>Protocol Filters:</b></p>"
        "<ul>"
        "<li><code>tcp</code> - TCP packets</li>"
        "<li><code>udp</code> - UDP packets</li>"
        "<li><code>icmp</code> - ICMP packets</li>"
        "<li><code>arp</code> - ARP packets</li>"
        "</ul>"
        "<p><b>Port Filters:</b></p>"
        "<ul>"
        "<li><code>tcp.port == 80</code> - TCP port 80</li>"
        "<li><code>udp.port == 53</code> - UDP port 53</li>"
        "</ul>"
        "<p><b>IP Address Filters:</b></p>"
        "<ul>"
        "<li><code>ip.addr == 192.168.1.1</code> - Any IP</li>"
        "<li><code>ip.src == 10.0.0.1</code> - Source IP</li>"
        "<li><code>ip.dst == 8.8.8.8</code> - Destination IP</li>"
        "</ul>"
        "<p><b>Logical Operators:</b></p>"
        "<ul>"
        "<li><code>tcp && tcp.port == 80</code> - AND</li>"
        "<li><code>tcp.port == 80 || tcp.port == 443</code> - OR</li>"
        "</ul>"
        "<p><b>Examples:</b></p>"
        "<ul>"
        "<li><code>tcp.port == 80</code> - HTTP traffic</li>"
        "<li><code>ip.addr == 192.168.1.1 && tcp</code> - TCP from/to specific IP</li>"
        "<li><code>tcp.port == 80 || tcp.port == 443</code> - HTTP or HTTPS</li>"
        "</ul>"
    );
}

QString MainWindow::formatBytes(uint64_t bytes)
{
    if (bytes < 1024) {
        return QString("%1 B").arg(bytes);
    } else if (bytes < 1024 * 1024) {
        return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 2);
    } else if (bytes < 1024ULL * 1024 * 1024) {
        return QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 2);
    } else {
        return QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }
}

QString MainWindow::getProtocolColor(const QString &protocol)
{
    if (protocol == "TCP") return "#4CAF50";
    if (protocol == "UDP") return "#2196F3";
    if (protocol == "ICMP") return "#FF9800";
    if (protocol == "ARP") return "#9C27B0";
    if (protocol == "IPv6") return "#00BCD4";
    return "#757575";
}
