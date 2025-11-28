// src/gui/main_window.cpp

#include "main_window.hpp"
#include <common/utils.hpp>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QSettings>
#include <QCloseEvent>
#include <QKeyEvent>
#include <QApplication>
#include <QDesktopServices>
#include <QUrl>
#include <QStatusBar>
#include <QMenuBar>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        // ==================== Constructor & Destructor ====================

        MainWindow::MainWindow(QWidget* parent)
            : QMainWindow(parent)
            , is_capturing_(false)
            , is_live_capture_(false)
            , selected_packet_index_(-1)
            , capture_start_time_(0)
            , capture_duration_(0.0)
            , packet_count_(0)
            , displayed_count_(0)
            , marked_count_(0)
            , bytes_captured_(0)
            , current_file_()
            , current_interface_()
            , current_filter_()
            , settings_()
            , packets_()
            , filtered_indices_()
            , packet_parser_(nullptr)
            , packet_filter_(nullptr)
            , packet_ingress_(nullptr)
            , main_splitter_(nullptr)
            , detail_splitter_(nullptr)
            , packet_list_(nullptr)
            , packet_detail_(nullptr)
            , packet_hex_(nullptr)
            , filter_bar_(nullptr)
            , status_bar_(nullptr)
            , file_menu_(nullptr)
            , edit_menu_(nullptr)
            , view_menu_(nullptr)
            , go_menu_(nullptr)
            , capture_menu_(nullptr)
            , analyze_menu_(nullptr)
            , statistics_menu_(nullptr)
            , tools_menu_(nullptr)
            , help_menu_(nullptr)
            , main_toolbar_(nullptr)
            , display_toolbar_(nullptr)
            , capture_dialog_(nullptr)
            , preferences_dialog_(nullptr)
            , action_open_(nullptr)
            , action_save_(nullptr)
            , action_save_as_(nullptr)
            , action_export_(nullptr)
            , action_close_(nullptr)
            , action_quit_(nullptr)
            , action_copy_(nullptr)
            , action_find_(nullptr)
            , action_find_next_(nullptr)
            , action_mark_packet_(nullptr)
            , action_mark_all_(nullptr)
            , action_unmark_all_(nullptr)
            , action_preferences_(nullptr)
            , action_zoom_in_(nullptr)
            , action_zoom_out_(nullptr)
            , action_reset_zoom_(nullptr)
            , action_fullscreen_(nullptr)
            , action_coloring_rules_(nullptr)
            , action_time_display_(nullptr)
            , action_name_resolution_(nullptr)
            , action_go_to_packet_(nullptr)
            , action_first_packet_(nullptr)
            , action_last_packet_(nullptr)
            , action_next_packet_(nullptr)
            , action_previous_packet_(nullptr)
            , action_start_capture_(nullptr)
            , action_stop_capture_(nullptr)
            , action_restart_capture_(nullptr)
            , action_capture_options_(nullptr)
            , action_capture_interfaces_(nullptr)
            , action_follow_tcp_(nullptr)
            , action_follow_udp_(nullptr)
            , action_expert_info_(nullptr)
            , capture_timer_(nullptr)
            , stats_timer_(nullptr)
            {
                try {
                    spdlog::info("MainWindow constructor started");
                    
                    // Initialize core components
                    packet_parser_ = std::make_unique<Common::PacketParser>();
                    packet_filter_ = std::make_unique<Layer1::Filter::PacketFilter>();
                    
                    // Setup UI
                    setupUI();
                    setupMenuBar();
                    setupToolBar();
                    setupStatusBar();
                    setupConnections();
                    
                    // Load settings
                    loadSettings();
                    applyTheme();
                    
                    // Create timers
                    capture_timer_ = new QTimer(this);
                    stats_timer_ = new QTimer(this);
                    stats_timer_->setInterval(UPDATE_INTERVAL_MS);
                    
                    connect(stats_timer_, &QTimer::timeout, this, &MainWindow::updateStatusBar);
                    stats_timer_->start();
                    
                    setWindowTitle(tr("Network Security Analyzer"));
                    resize(1280, 800);
                    
                    spdlog::info("MainWindow initialized successfully");
                    
                } catch (const std::exception& e) {
                    spdlog::error("MainWindow constructor exception: {}", e.what());
                    throw;
                } catch (...) {
                    spdlog::error("MainWindow constructor unknown exception");
                    throw;
                }
            }

        MainWindow::~MainWindow()
        {
            stopCapture();
            saveSettings();
            spdlog::info("MainWindow destroyed");
        }

        // ==================== UI Setup ====================

        void MainWindow::setupUI()
        {
            // Create central widget
            QWidget* central = new QWidget(this);
            setCentralWidget(central);

            QVBoxLayout* main_layout = new QVBoxLayout(central);
            main_layout->setContentsMargins(0, 0, 0, 0);
            main_layout->setSpacing(0);

            // Filter bar
            filter_bar_ = new FilterBarWidget(this);
            main_layout->addWidget(filter_bar_);

            // Main splitter (vertical)
            main_splitter_ = new QSplitter(Qt::Vertical, this);

            // Packet list
            packet_list_ = new PacketListWidget(this);
            main_splitter_->addWidget(packet_list_);

            // Detail splitter (horizontal)
            detail_splitter_ = new QSplitter(Qt::Horizontal, this);

            // Packet detail
            packet_detail_ = new PacketDetailWidget(this);
            detail_splitter_->addWidget(packet_detail_);

            // Packet hex
            packet_hex_ = new PacketHexWidget(this);
            detail_splitter_->addWidget(packet_hex_);

            detail_splitter_->setStretchFactor(0, 2);
            detail_splitter_->setStretchFactor(1, 1);

            main_splitter_->addWidget(detail_splitter_);
            main_splitter_->setStretchFactor(0, 3);
            main_splitter_->setStretchFactor(1, 2);

            main_layout->addWidget(main_splitter_);

            spdlog::debug("UI setup completed");
        }

        void MainWindow::setupMenuBar()
        {
            QMenuBar* menu_bar = menuBar();

            // ==================== File Menu ====================
            file_menu_ = menu_bar->addMenu(tr("&File"));

            action_open_ = file_menu_->addAction(tr("&Open..."));
            action_open_->setShortcut(QKeySequence::Open);
            action_open_->setIcon(QIcon::fromTheme("document-open"));
            connect(action_open_, &QAction::triggered, this, &MainWindow::onFileOpen);

            action_save_ = file_menu_->addAction(tr("&Save"));
            action_save_->setShortcut(QKeySequence::Save);
            action_save_->setIcon(QIcon::fromTheme("document-save"));
            action_save_->setEnabled(false);
            connect(action_save_, &QAction::triggered, this, &MainWindow::onFileSave);

            action_save_as_ = file_menu_->addAction(tr("Save &As..."));
            action_save_as_->setShortcut(QKeySequence::SaveAs);
            action_save_as_->setIcon(QIcon::fromTheme("document-save-as"));
            connect(action_save_as_, &QAction::triggered, this, &MainWindow::onFileSaveAs);

            file_menu_->addSeparator();

            action_export_ = file_menu_->addAction(tr("&Export..."));
            action_export_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
            action_export_->setIcon(QIcon::fromTheme("document-export"));
            connect(action_export_, &QAction::triggered, this, &MainWindow::onFileExport);

            file_menu_->addSeparator();

            action_close_ = file_menu_->addAction(tr("&Close"));
            action_close_->setShortcut(QKeySequence::Close);
            action_close_->setIcon(QIcon::fromTheme("window-close"));
            connect(action_close_, &QAction::triggered, this, &MainWindow::onFileClose);

            action_quit_ = file_menu_->addAction(tr("&Quit"));
            action_quit_->setShortcut(QKeySequence::Quit);
            action_quit_->setIcon(QIcon::fromTheme("application-exit"));
            connect(action_quit_, &QAction::triggered, this, &MainWindow::onFileQuit);

            // ==================== Edit Menu ====================
            edit_menu_ = menu_bar->addMenu(tr("&Edit"));

            action_copy_ = edit_menu_->addAction(tr("&Copy"));
            action_copy_->setShortcut(QKeySequence::Copy);
            action_copy_->setIcon(QIcon::fromTheme("edit-copy"));
            connect(action_copy_, &QAction::triggered, this, &MainWindow::onEditCopy);

            action_find_ = edit_menu_->addAction(tr("&Find Packet..."));
            action_find_->setShortcut(QKeySequence::Find);
            action_find_->setIcon(QIcon::fromTheme("edit-find"));
            connect(action_find_, &QAction::triggered, this, &MainWindow::onEditFind);

            action_find_next_ = edit_menu_->addAction(tr("Find &Next"));
            action_find_next_->setShortcut(QKeySequence::FindNext);
            connect(action_find_next_, &QAction::triggered, this, &MainWindow::onEditFindNext);

            edit_menu_->addSeparator();

            action_mark_packet_ = edit_menu_->addAction(tr("&Mark Packet"));
            action_mark_packet_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_M));
            connect(action_mark_packet_, &QAction::triggered, this, &MainWindow::onEditMarkPacket);

            action_mark_all_ = edit_menu_->addAction(tr("Mark &All Displayed"));
            action_mark_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_M));
            connect(action_mark_all_, &QAction::triggered, this, &MainWindow::onEditMarkAll);

            action_unmark_all_ = edit_menu_->addAction(tr("&Unmark All"));
            action_unmark_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::Key_M));
            connect(action_unmark_all_, &QAction::triggered, this, &MainWindow::onEditUnmarkAll);

            edit_menu_->addSeparator();

            action_preferences_ = edit_menu_->addAction(tr("&Preferences..."));
            action_preferences_->setShortcut(QKeySequence::Preferences);
            action_preferences_->setIcon(QIcon::fromTheme("preferences-system"));
            connect(action_preferences_, &QAction::triggered, this, &MainWindow::onEditPreferences);

            // ==================== View Menu ====================
            view_menu_ = menu_bar->addMenu(tr("&View"));

            action_zoom_in_ = view_menu_->addAction(tr("Zoom &In"));
            action_zoom_in_->setShortcut(QKeySequence::ZoomIn);
            action_zoom_in_->setIcon(QIcon::fromTheme("zoom-in"));
            connect(action_zoom_in_, &QAction::triggered, this, &MainWindow::onViewZoomIn);

            action_zoom_out_ = view_menu_->addAction(tr("Zoom &Out"));
            action_zoom_out_->setShortcut(QKeySequence::ZoomOut);
            action_zoom_out_->setIcon(QIcon::fromTheme("zoom-out"));
            connect(action_zoom_out_, &QAction::triggered, this, &MainWindow::onViewZoomOut);

            action_reset_zoom_ = view_menu_->addAction(tr("&Reset Zoom"));
            action_reset_zoom_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_0));
            connect(action_reset_zoom_, &QAction::triggered, this, &MainWindow::onViewResetZoom);

            view_menu_->addSeparator();

            action_fullscreen_ = view_menu_->addAction(tr("&Full Screen"));
            action_fullscreen_->setShortcut(Qt::Key_F11);
            action_fullscreen_->setCheckable(true);
            connect(action_fullscreen_, &QAction::triggered, this, &MainWindow::onViewFullScreen);

            view_menu_->addSeparator();

            action_coloring_rules_ = view_menu_->addAction(tr("&Coloring Rules..."));
            connect(action_coloring_rules_, &QAction::triggered, this, &MainWindow::onViewColoringRules);

            action_time_display_ = view_menu_->addAction(tr("&Time Display Format..."));
            connect(action_time_display_, &QAction::triggered, this, &MainWindow::onViewTimeDisplay);

            action_name_resolution_ = view_menu_->addAction(tr("&Name Resolution..."));
            connect(action_name_resolution_, &QAction::triggered, this, &MainWindow::onViewNameResolution);

            // ==================== Go Menu ====================
            go_menu_ = menu_bar->addMenu(tr("&Go"));

            action_go_to_packet_ = go_menu_->addAction(tr("&Go to Packet..."));
            action_go_to_packet_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
            connect(action_go_to_packet_, &QAction::triggered, this, &MainWindow::onGoToPacket);

            go_menu_->addSeparator();

            action_first_packet_ = go_menu_->addAction(tr("&First Packet"));
            action_first_packet_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Home));
            connect(action_first_packet_, &QAction::triggered, this, &MainWindow::onGoFirstPacket);

            action_last_packet_ = go_menu_->addAction(tr("&Last Packet"));
            action_last_packet_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_End));
            connect(action_last_packet_, &QAction::triggered, this, &MainWindow::onGoLastPacket);

            action_next_packet_ = go_menu_->addAction(tr("&Next Packet"));
            action_next_packet_->setShortcut(Qt::Key_Down);
            connect(action_next_packet_, &QAction::triggered, this, &MainWindow::onGoNextPacket);

            action_previous_packet_ = go_menu_->addAction(tr("&Previous Packet"));
            action_previous_packet_->setShortcut(Qt::Key_Up);
            connect(action_previous_packet_, &QAction::triggered, this, &MainWindow::onGoPreviousPacket);

            // ==================== Capture Menu ====================
            capture_menu_ = menu_bar->addMenu(tr("&Capture"));

            action_start_capture_ = capture_menu_->addAction(tr("&Start"));
            action_start_capture_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_K));
            action_start_capture_->setIcon(QIcon::fromTheme("media-record"));
            connect(action_start_capture_, &QAction::triggered, this, &MainWindow::onCaptureStart);

            action_stop_capture_ = capture_menu_->addAction(tr("S&top"));
            action_stop_capture_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
            action_stop_capture_->setIcon(QIcon::fromTheme("media-playback-stop"));
            action_stop_capture_->setEnabled(false);
            connect(action_stop_capture_, &QAction::triggered, this, &MainWindow::onCaptureStop);

            action_restart_capture_ = capture_menu_->addAction(tr("&Restart"));
            action_restart_capture_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_R));
            action_restart_capture_->setIcon(QIcon::fromTheme("view-refresh"));
            connect(action_restart_capture_, &QAction::triggered, this, &MainWindow::onCaptureRestart);

            capture_menu_->addSeparator();

            action_capture_options_ = capture_menu_->addAction(tr("&Options..."));
            action_capture_options_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_K));
            action_capture_options_->setIcon(QIcon::fromTheme("configure"));
            connect(action_capture_options_, &QAction::triggered, this, &MainWindow::onCaptureOptions);

            action_capture_interfaces_ = capture_menu_->addAction(tr("&Interfaces..."));
            connect(action_capture_interfaces_, &QAction::triggered, this, &MainWindow::onCaptureInterfaces);

            // ==================== Analyze Menu ====================
            analyze_menu_ = menu_bar->addMenu(tr("&Analyze"));

            action_follow_tcp_ = analyze_menu_->addAction(tr("Follow &TCP Stream"));
            connect(action_follow_tcp_, &QAction::triggered, this, &MainWindow::onAnalyzeFollowTCPStream);

            action_follow_udp_ = analyze_menu_->addAction(tr("Follow &UDP Stream"));
            connect(action_follow_udp_, &QAction::triggered, this, &MainWindow::onAnalyzeFollowUDPStream);

            analyze_menu_->addSeparator();

            action_expert_info_ = analyze_menu_->addAction(tr("&Expert Information"));
            connect(action_expert_info_, &QAction::triggered, this, &MainWindow::onAnalyzeExpertInfo);

            QAction* action_conversations = analyze_menu_->addAction(tr("&Conversations"));
            connect(action_conversations, &QAction::triggered, this, &MainWindow::onAnalyzeConversations);

            QAction* action_endpoints = analyze_menu_->addAction(tr("&Endpoints"));
            connect(action_endpoints, &QAction::triggered, this, &MainWindow::onAnalyzeEndpoints);

            // ==================== Statistics Menu ====================
            statistics_menu_ = menu_bar->addMenu(tr("&Statistics"));

            QAction* action_summary = statistics_menu_->addAction(tr("&Summary"));
            connect(action_summary, &QAction::triggered, this, &MainWindow::onStatisticsSummary);

            QAction* action_protocol_hierarchy = statistics_menu_->addAction(tr("&Protocol Hierarchy"));
            connect(action_protocol_hierarchy, &QAction::triggered, this, &MainWindow::onStatisticsProtocolHierarchy);

            // ==================== Tools Menu ====================
            tools_menu_ = menu_bar->addMenu(tr("&Tools"));

            QAction* action_firewall = tools_menu_->addAction(tr("&Firewall ACL Rules"));
            connect(action_firewall, &QAction::triggered, this, &MainWindow::onToolsFirewall);

            // ==================== Help Menu ====================
            help_menu_ = menu_bar->addMenu(tr("&Help"));

            QAction* action_contents = help_menu_->addAction(tr("&Contents"));
            action_contents->setShortcut(Qt::Key_F1);
            action_contents->setIcon(QIcon::fromTheme("help-contents"));
            connect(action_contents, &QAction::triggered, this, &MainWindow::onHelpContents);

            help_menu_->addSeparator();

            QAction* action_website = help_menu_->addAction(tr("&Website"));
            connect(action_website, &QAction::triggered, this, &MainWindow::onHelpWebsite);

            QAction* action_about = help_menu_->addAction(tr("&About"));
            action_about->setIcon(QIcon::fromTheme("help-about"));
            connect(action_about, &QAction::triggered, this, &MainWindow::onHelpAbout);

            spdlog::debug("Menu bar setup completed");
        }

        void MainWindow::setupToolBar()
        {
            // Main toolbar
            main_toolbar_ = addToolBar(tr("Main Toolbar"));
            main_toolbar_->setObjectName("MainToolbar");
            main_toolbar_->setMovable(false);

            main_toolbar_->addAction(action_open_);
            main_toolbar_->addAction(action_save_);
            main_toolbar_->addSeparator();
            main_toolbar_->addAction(action_start_capture_);
            main_toolbar_->addAction(action_stop_capture_);
            main_toolbar_->addAction(action_restart_capture_);
            main_toolbar_->addSeparator();
            main_toolbar_->addAction(action_capture_options_);

            // Display toolbar
            display_toolbar_ = addToolBar(tr("Display Toolbar"));
            display_toolbar_->setObjectName("DisplayToolbar");
            display_toolbar_->setMovable(false);

            display_toolbar_->addAction(action_zoom_in_);
            display_toolbar_->addAction(action_zoom_out_);
            display_toolbar_->addAction(action_reset_zoom_);

            spdlog::debug("Toolbars setup completed");
        }

        void MainWindow::setupStatusBar()
        {
            auto* real_sb = new QStatusBar(this);
            status_bar_ = new StatusBarWidget(real_sb); 
            real_sb->addPermanentWidget(status_bar_, 1);
            setStatusBar(real_sb);
        }

        void MainWindow::setupConnections()
        {
            // Filter bar
            connect(filter_bar_, &FilterBarWidget::filterApplied,
                    this, &MainWindow::onFilterApplied);
            connect(filter_bar_, &FilterBarWidget::filterChanged,
                    this, &MainWindow::onFilterChanged);

            // Packet list
            connect(packet_list_, &PacketListWidget::packetSelected,
                    this, &MainWindow::onPacketSelected);
            connect(packet_list_, &PacketListWidget::packetDoubleClicked,
                    this, &MainWindow::onPacketDoubleClicked);

            // Packet detail
            connect(packet_detail_, &PacketDetailWidget::bytesSelected,
                    packet_hex_, &PacketHexWidget::selectBytes);

            // Packet hex
            connect(packet_hex_, &PacketHexWidget::bytesSelected,
                    this, [this](int offset, int length) {
                        spdlog::debug("Hex bytes selected: offset={}, length={}", offset, length);
                    });

            spdlog::debug("Connections setup completed");
        }

        // ==================== Settings ====================

        void MainWindow::loadSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");

            // Window geometry
            restoreGeometry(settings.value("window/geometry").toByteArray());
            restoreState(settings.value("window/state").toByteArray());

            // Splitter sizes
            if (settings.contains("window/main_splitter")) {
                main_splitter_->restoreState(settings.value("window/main_splitter").toByteArray());
            }
            if (settings.contains("window/detail_splitter")) {
                detail_splitter_->restoreState(settings.value("window/detail_splitter").toByteArray());
            }

            // Application settings
            settings_.last_directory = settings.value("app/last_directory", QDir::homePath()).toString();
            settings_.last_interface = settings.value("app/last_interface").toString();
            settings_.auto_scroll = settings.value("app/auto_scroll", true).toBool();
            settings_.show_hex = settings.value("app/show_hex", true).toBool();
            settings_.resolve_names = settings.value("app/resolve_names", true).toBool();
            settings_.font_size = settings.value("app/font_size", 10).toInt();
            settings_.theme = settings.value("app/theme", "system").toString();

            // Recent files
            settings_.recent_files = settings.value("app/recent_files").toStringList();
            settings_.recent_filters = settings.value("app/recent_filters").toStringList();

            spdlog::info("Settings loaded");
        }

        void MainWindow::saveSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");

            // Window geometry
            settings.setValue("window/geometry", saveGeometry());
            settings.setValue("window/state", saveState());
            settings.setValue("window/main_splitter", main_splitter_->saveState());
            settings.setValue("window/detail_splitter", detail_splitter_->saveState());

            // Application settings
            settings.setValue("app/last_directory", settings_.last_directory);
            settings.setValue("app/last_interface", settings_.last_interface);
            settings.setValue("app/auto_scroll", settings_.auto_scroll);
            settings.setValue("app/show_hex", settings_.show_hex);
            settings.setValue("app/resolve_names", settings_.resolve_names);
            settings.setValue("app/font_size", settings_.font_size);
            settings.setValue("app/theme", settings_.theme);

            // Recent files
            settings.setValue("app/recent_files", settings_.recent_files);
            settings.setValue("app/recent_filters", settings_.recent_filters);

            spdlog::info("Settings saved");
        }

        void MainWindow::applyTheme()
        {
            // TODO: Implement theme application
            spdlog::debug("Theme applied: {}", settings_.theme.toStdString());
        }

        // ==================== Event Handlers ====================

        void MainWindow::closeEvent(QCloseEvent* event)
        {
            if (is_capturing_) {
                QMessageBox::StandardButton reply = QMessageBox::question(
                    this,
                    tr("Capture in Progress"),
                    tr("A capture is currently in progress. Do you want to stop it and exit?"),
                    QMessageBox::Yes | QMessageBox::No
                );

                if (reply == QMessageBox::No) {
                    event->ignore();
                    return;
                }

                stopCapture();
            }

            saveSettings();
            event->accept();
        }

        void MainWindow::keyPressEvent(QKeyEvent* event)
        {
            // Handle special key combinations
            if (event->key() == Qt::Key_Escape) {
                if (isFullScreen()) {
                    showNormal();
                    action_fullscreen_->setChecked(false);
                }
            }

            QMainWindow::keyPressEvent(event);
        }

        // ==================== File Menu Slots ====================

        void MainWindow::onFileOpen()
        {
            QString filename = QFileDialog::getOpenFileName(
                this,
                tr("Open Capture File"),
                settings_.last_directory,
                tr("Capture Files (*.pcap *.pcapng);;All Files (*)")
            );

            if (!filename.isEmpty()) {
                loadPcapFile(filename);
                settings_.last_directory = QFileInfo(filename).absolutePath();

                // Add to recent files
                settings_.recent_files.removeAll(filename);
                settings_.recent_files.prepend(filename);
                if (settings_.recent_files.size() > MAX_RECENT_FILES) {
                    settings_.recent_files.removeLast();
                }
            }
        }

        void MainWindow::onFileSave()
        {
            if (current_file_.isEmpty()) {
                onFileSaveAs();
            } else {
                savePcapFile(current_file_);
            }
        }

        void MainWindow::onFileSaveAs()
        {
            QString filename = QFileDialog::getSaveFileName(
                this,
                tr("Save Capture File"),
                settings_.last_directory,
                tr("PCAP Files (*.pcap);;PCAPNG Files (*.pcapng);;All Files (*)")
            );

            if (!filename.isEmpty()) {
                savePcapFile(filename);
                current_file_ = filename;
                settings_.last_directory = QFileInfo(filename).absolutePath();
                updateWindowTitle();
            }
        }

        void MainWindow::onFileExport()
        {
            QMessageBox::information(this, tr("Export"),
                tr("Export functionality coming soon!"));
        }

        void MainWindow::onFileClose()
        {
            if (is_capturing_) {
                stopCapture();
            }

            clearPackets();
            current_file_.clear();
            updateWindowTitle();
        }

        void MainWindow::onFileQuit()
        {
            close();
        }

        // ==================== Edit Menu Slots ====================

        void MainWindow::onEditCopy()
        {
            // TODO: Implement copy functionality
            spdlog::debug("Copy requested");
        }

        void MainWindow::onEditFind()
        {
            bool ok;
            QString text = QInputDialog::getText(
                this,
                tr("Find Packet"),
                tr("Enter search text:"),
                QLineEdit::Normal,
                "",
                &ok
            );

            if (ok && !text.isEmpty()) {
                spdlog::info("Searching for: {}", text.toStdString());
                // TODO: Implement search
            }
        }

        void MainWindow::onEditFindNext()
        {
            // TODO: Implement find next
            spdlog::debug("Find next requested");
        }

        void MainWindow::onEditMarkPacket()
        {
            int row = packet_list_->getSelectedRow();
            if (row >= 0) {
                packet_list_->markPacket(row);
                marked_count_.fetch_add(1);
            }
        }

        void MainWindow::onEditMarkAll()
        {
            packet_list_->markAll();
            marked_count_.store(displayed_count_.load());
        }

        void MainWindow::onEditUnmarkAll()
        {
            packet_list_->unmarkAll();
            marked_count_.store(0);
        }

        void MainWindow::onEditPreferences()
        {
            if (!preferences_dialog_) {
                preferences_dialog_ = new PreferencesDialog(this);
            }
            preferences_dialog_->exec();
        }

        // ==================== View Menu Slots ====================

        void MainWindow::onViewZoomIn()
        {
            settings_.font_size++;
            applyTheme();
        }

        void MainWindow::onViewZoomOut()
        {
            if (settings_.font_size > 6) {
                settings_.font_size--;
                applyTheme();
            }
        }

        void MainWindow::onViewResetZoom()
        {
            settings_.font_size = 10;
            applyTheme();
        }

        void MainWindow::onViewFullScreen()
        {
            if (isFullScreen()) {
                showNormal();
            } else {
                showFullScreen();
            }
        }

        void MainWindow::onViewColoringRules()
        {
            QMessageBox::information(this, tr("Coloring Rules"),
                tr("Coloring rules dialog coming soon!"));
        }

        void MainWindow::onViewTimeDisplay()
        {
            QMessageBox::information(this, tr("Time Display"),
                tr("Time display format dialog coming soon!"));
        }

        void MainWindow::onViewNameResolution()
        {
            QMessageBox::information(this, tr("Name Resolution"),
                tr("Name resolution dialog coming soon!"));
        }

        // ==================== Go Menu Slots ====================

        void MainWindow::onGoToPacket()
        {
            bool ok;
            int packet_num = QInputDialog::getInt(
                this,
                tr("Go to Packet"),
                tr("Packet number:"),
                1, 1, static_cast<int>(packets_.size()),
                1, &ok
            );

            if (ok) {
                packet_list_->selectRow(packet_num - 1);
            }
        }

        void MainWindow::onGoFirstPacket()
        {
            packet_list_->selectFirstPacket();
        }

        void MainWindow::onGoLastPacket()
        {
            packet_list_->selectLastPacket();
        }

        void MainWindow::onGoNextPacket()
        {
            packet_list_->selectNextPacket();
        }

        void MainWindow::onGoPreviousPacket()
        {
            packet_list_->selectPreviousPacket();
        }

        void MainWindow::onGoNextMarked()
        {
            // TODO: Implement
            spdlog::debug("Go to next marked packet");
        }

        void MainWindow::onGoPreviousMarked()
        {
            // TODO: Implement
            spdlog::debug("Go to previous marked packet");
        }

        // ==================== Capture Menu Slots ====================

        void MainWindow::onCaptureStart()
        {
            if (!capture_dialog_) {
                capture_dialog_ = new CaptureDialog(this);
            }

            if (capture_dialog_->exec() == QDialog::Accepted) {
                auto options = capture_dialog_->getOptions();
                startCapture(options.interface);
            }
        }

        void MainWindow::onCaptureStop()
        {
            stopCapture();
        }

        void MainWindow::onCaptureRestart()
        {
            if (is_capturing_) {
                QString interface = current_interface_;
                stopCapture();
                clearPackets();
                startCapture(interface.toStdString());
            }
        }

        void MainWindow::onCaptureOptions()
        {
            if (!capture_dialog_) {
                capture_dialog_ = new CaptureDialog(this);
            }
            capture_dialog_->show();
        }

        void MainWindow::onCaptureInterfaces()
        {
            QMessageBox::information(this, tr("Interfaces"),
                tr("Interface management dialog coming soon!"));
        }

        // ==================== Analyze Menu Slots ====================

        void MainWindow::onAnalyzeDisplayFilters()
        {
            QMessageBox::information(this, tr("Display Filters"),
                tr("Display filters dialog coming soon!"));
        }

        void MainWindow::onAnalyzeCaptureFilters()
        {
            QMessageBox::information(this, tr("Capture Filters"),
                tr("Capture filters dialog coming soon!"));
        }

        void MainWindow::onAnalyzeFollowTCPStream()
        {
            int row = packet_list_->getSelectedRow();
            if (row < 0 || static_cast<size_t>(row) >= packets_.size()) {
                QMessageBox::warning(this, tr("Follow TCP Stream"),
                    tr("Please select a TCP packet first."));
                return;
            }

            const auto& packet = packets_[row].parsed;
            if (!packet.has_tcp) {
                QMessageBox::warning(this, tr("Follow TCP Stream"),
                    tr("Selected packet is not a TCP packet."));
                return;
            }

            spdlog::info("Following TCP stream");
            // TODO: Implement TCP stream following
        }

        void MainWindow::onAnalyzeFollowUDPStream()
        {
            int row = packet_list_->getSelectedRow();
            if (row < 0 || static_cast<size_t>(row) >= packets_.size()) {
                QMessageBox::warning(this, tr("Follow UDP Stream"),
                    tr("Please select a UDP packet first."));
                return;
            }

            const auto& packet = packets_[row].parsed;
            if (!packet.has_udp) {
                QMessageBox::warning(this, tr("Follow UDP Stream"),
                    tr("Selected packet is not a UDP packet."));
                return;
            }

            spdlog::info("Following UDP stream");
            // TODO: Implement UDP stream following
        }

        void MainWindow::onAnalyzeExpertInfo()
        {
            QMessageBox::information(this, tr("Expert Information"),
                tr("Expert information dialog coming soon!"));
        }

        void MainWindow::onAnalyzeConversations()
        {
            QMessageBox::information(this, tr("Conversations"),
                tr("Conversations dialog coming soon!"));
        }

        void MainWindow::onAnalyzeEndpoints()
        {
            QMessageBox::information(this, tr("Endpoints"),
                tr("Endpoints dialog coming soon!"));
        }

        void MainWindow::onAnalyzeProtocolHierarchy()
        {
            QMessageBox::information(this, tr("Protocol Hierarchy"),
                tr("Protocol hierarchy dialog coming soon!"));
        }

        // ==================== Statistics Menu Slots ====================

        void MainWindow::onStatisticsSummary()
        {
            uint64_t total_packets = packet_count_.load();
            uint64_t displayed = displayed_count_.load();
            uint64_t marked = marked_count_.load();
            uint64_t bytes = bytes_captured_.load();

            QString summary = QString(
                "Capture Summary\n"
                "===============\n\n"
                "Total Packets: %1\n"
                "Displayed: %2\n"
                "Marked: %3\n"
                "Dropped: %4\n\n"
                "Capture Duration: %5 seconds\n"
                "Average Rate: %6 packets/sec\n"
                "Total Bytes: %7 (%8 MB)\n"
            ).arg(total_packets)
             .arg(displayed)
             .arg(marked)
             .arg(0)
             .arg(capture_duration_, 0, 'f', 2)
             .arg(capture_duration_ > 0 ? total_packets / capture_duration_ : 0, 0, 'f', 2)
             .arg(bytes)
             .arg(bytes / (1024.0 * 1024.0), 0, 'f', 2);

            QMessageBox::information(this, tr("Capture Summary"), summary);
        }

        void MainWindow::onStatisticsProtocolHierarchy()
        {
            QMessageBox::information(this, tr("Protocol Hierarchy"),
                tr("Protocol hierarchy statistics coming soon!"));
        }

        void MainWindow::onStatisticsConversations()
        {
            QMessageBox::information(this, tr("Conversations"),
                tr("Conversation statistics coming soon!"));
        }

        void MainWindow::onStatisticsEndpoints()
        {
            QMessageBox::information(this, tr("Endpoints"),
                tr("Endpoint statistics coming soon!"));
        }

        void MainWindow::onStatisticsIOGraph()
        {
            QMessageBox::information(this, tr("I/O Graph"),
                tr("I/O graph coming soon!"));
        }

        void MainWindow::onStatisticsFlowGraph()
        {
            QMessageBox::information(this, tr("Flow Graph"),
                tr("Flow graph coming soon!"));
        }

        void MainWindow::onStatisticsHTTP()
        {
            QMessageBox::information(this, tr("HTTP Statistics"),
                tr("HTTP statistics coming soon!"));
        }

        void MainWindow::onStatisticsDNS()
        {
            QMessageBox::information(this, tr("DNS Statistics"),
                tr("DNS statistics coming soon!"));
        }

        // ==================== Tools Menu Slots ====================

        void MainWindow::onToolsFirewall()
        {
            QMessageBox::information(this, tr("Firewall ACL Rules"),
                tr("Firewall ACL rules generator coming soon!"));
        }

        void MainWindow::onToolsCredentials()
        {
            QMessageBox::information(this, tr("Credentials"),
                tr("Credentials extraction coming soon!"));
        }

        void MainWindow::onToolsLua()
        {
            QMessageBox::information(this, tr("Lua"),
                tr("Lua scripting coming soon!"));
        }

        // ==================== Help Menu Slots ====================

        void MainWindow::onHelpContents()
        {
            QMessageBox::information(this, tr("Help"),
                tr("Help documentation coming soon!"));
        }

        void MainWindow::onHelpWebsite()
        {
            QDesktopServices::openUrl(QUrl("https://github.com/yourusername/network-security-analyzer"));
        }

        void MainWindow::onHelpAbout()
        {
            QMessageBox::about(this, tr("About Network Security Analyzer"),
                tr("<h3>Network Security Analyzer v1.0.0</h3>"
                   "<p>A powerful network packet analysis tool.</p>"
                   "<p>Built with Qt and libpcap.</p>"
                   "<p>Copyright © 2024</p>"));
        }

        // ==================== Packet Handling ====================

        void MainWindow::onPacketCaptured(const Common::ParsedPacket& packet)
        {
            processPacket(packet);
        }

        void MainWindow::onPacketSelected(int row)
        {
            if (row < 0 || static_cast<size_t>(row) >= packets_.size()) {
                return;
            }

            selected_packet_index_ = row;
            const auto& packet_data = packets_[row];

            // Update detail view
            packet_detail_->displayPacket(packet_data.parsed, packet_data.raw_data);

            // Update hex view
            packet_hex_->displayData(packet_data.raw_data);
        }

        void MainWindow::onPacketDoubleClicked(int row)
        {
            onPacketSelected(row);
            // TODO: Show detailed packet dialog
            spdlog::debug("Packet {} double-clicked", row);
        }

        void MainWindow::onFilterChanged(const QString& filter)
        {
            current_filter_ = filter;
        }

        void MainWindow::onFilterApplied()
        {
            applyFilter();
        }

        // ==================== UI Updates ====================

        void MainWindow::updateStatusBar()
        {
            uint64_t packet_count = packet_count_.load();
            uint64_t displayed_count = displayed_count_.load();
            uint64_t marked_count = marked_count_.load();

            status_bar_->setPacketCount(packet_count, displayed_count);
            status_bar_->setMarkedCount(marked_count);

            if (is_capturing_) {
                uint64_t bytes = bytes_captured_.load();
                double duration = capture_duration_;
                status_bar_->updateCaptureStats(packet_count, bytes, duration);
            }
        }

        void MainWindow::updateWindowTitle()
        {
            QString title = "Network Security Analyzer";

            if (!current_file_.isEmpty()) {
                title += " - " + QFileInfo(current_file_).fileName();
            }

            if (is_capturing_) {
                title += " [Capturing]";
            }

            setWindowTitle(title);
        }

        void MainWindow::updatePacketCount()
        {
            updateStatusBar();
        }

        void MainWindow::updateCaptureTime()
        {
            if (is_capturing_ && capture_start_time_ > 0) {
                uint64_t current_time = Common::Utils::getCurrentTimestampUs();
                capture_duration_ = (current_time - capture_start_time_) / 1000000.0;

                uint64_t packet_count = packet_count_.load();
                uint64_t bytes = bytes_captured_.load();
                status_bar_->updateCaptureStats(packet_count, bytes, capture_duration_);
            }
        }

        // ==================== Capture Management ====================

        void MainWindow::startCapture(const std::string& interface)
        {
            if (is_capturing_) {
                spdlog::warn("Already capturing");
                return;
            }

            try {
                Layer1::IngressConfig config;
                config.interface = interface;
                config.promiscuous = true;
                config.snaplen = 65535;
                config.timeout_ms = 1000;
                config.buffer_size = 2 * 1024 * 1024;
                config.bpf_filter = current_filter_.toStdString();

                packet_ingress_ = std::make_unique<Layer1::PacketIngress>(config);

                if (!packet_ingress_->initialize()) {
                    throw std::runtime_error("Failed to initialize packet capture");
                }

                bool started = packet_ingress_->start([this](const Common::ParsedPacket& parsed) {
                    QMetaObject::invokeMethod(this, [this, parsed]() {
                        onPacketCaptured(parsed);
                    }, Qt::QueuedConnection);
                });

                if (!started) {
                    throw std::runtime_error("Failed to start packet capture");
                }

                is_capturing_ = true;
                is_live_capture_ = true;
                current_interface_ = QString::fromStdString(interface);
                capture_start_time_ = Common::Utils::getCurrentTimestampUs();

                status_bar_->setCaptureStatus("Capturing on " + current_interface_);
                capture_timer_->start(1000);

                action_start_capture_->setEnabled(false);
                action_stop_capture_->setEnabled(true);

                updateWindowTitle();

                spdlog::info("Started capture on interface: {}", interface);
            }
            catch (const std::exception& e) {
                spdlog::error("Failed to start capture: {}", e.what());
                QMessageBox::critical(this, tr("Capture Error"),
                    tr("Failed to start capture:\n%1").arg(e.what()));
            }
        }

        void MainWindow::stopCapture()
        {
            if (!is_capturing_) {
                return;
            }

            try {
                if (packet_ingress_) {
                    packet_ingress_->stop();
                    packet_ingress_.reset();
                }

                is_capturing_ = false;
                capture_timer_->stop();

                status_bar_->setCaptureStatus("Capture stopped");

                action_start_capture_->setEnabled(true);
                action_stop_capture_->setEnabled(false);

                updateWindowTitle();

                spdlog::info("Stopped capture");
            }
            catch (const std::exception& e) {
                spdlog::error("Error stopping capture: {}", e.what());
            }
        }

        void MainWindow::clearPackets()
        {
            packets_.clear();
            filtered_indices_.clear();

            packet_list_->clearPackets();
            packet_detail_->clearDisplay();
            packet_hex_->clearDisplay();

            packet_count_.store(0);
            displayed_count_.store(0);
            marked_count_.store(0);
            bytes_captured_.store(0);
            capture_duration_ = 0.0;

            selected_packet_index_ = -1;

            updateStatusBar();
            updateWindowTitle();

            spdlog::info("Packets cleared");
        }

        void MainWindow::loadPcapFile(const QString& filename)
        {
            spdlog::info("Loading PCAP file: {}", filename.toStdString());

            clearPackets();

            try {
                // TODO: Implement PCAP file loading
                current_file_ = filename;
                is_live_capture_ = false;
                updateWindowTitle();

                QMessageBox::information(this, tr("Load File"),
                    tr("PCAP file loading coming soon!"));
            }
            catch (const std::exception& e) {
                spdlog::error("Failed to load file: {}", e.what());
                QMessageBox::critical(this, tr("Load Error"),
                    tr("Failed to load file:\n%1").arg(e.what()));
            }
        }

        void MainWindow::savePcapFile(const QString& filename)
        {
            spdlog::info("Saving PCAP file: {}", filename.toStdString());

            try {
                // TODO: Implement PCAP file saving
                QMessageBox::information(this, tr("Save File"),
                    tr("PCAP file saving coming soon!"));
            }
            catch (const std::exception& e) {
                spdlog::error("Failed to save file: {}", e.what());
                QMessageBox::critical(this, tr("Save Error"),
                    tr("Failed to save file:\n%1").arg(e.what()));
            }
        }

        // ==================== Packet Processing ====================

        void MainWindow::processPacket(const Common::ParsedPacket& packet)
        {
            PacketData packet_data;
            packet_data.parsed = packet;
            packet_data.raw_data = std::vector<uint8_t>(
                packet.raw_data,
                packet.raw_data + packet.packet_size
            );
            packet_data.timestamp = packet.timestamp;
            packet_data.index = packets_.size();
            packet_data.marked = false;
            packet_data.filtered = false;

            packets_.push_back(packet_data);
            packet_count_.fetch_add(1);
            bytes_captured_.fetch_add(packet.packet_size);

            // Apply filter if active
            if (!current_filter_.isEmpty()) {
                // TODO: Apply filter
                packet_data.filtered = false;
            }

            // Update display
            if (!packet_data.filtered) {
                packet_list_->addPacket(packet, packet_data.raw_data);
                displayed_count_.fetch_add(1);
            }

            // Limit memory usage
            if (packets_.size() > MAX_PACKETS_IN_MEMORY) {
                packets_.erase(packets_.begin());
            }
        }

        void MainWindow::applyFilter()
        {
            QString filter = filter_bar_->getFilter();

            if (filter.isEmpty()) {
                updatePacketList();
                return;
            }

            spdlog::info("Applying filter: {}", filter.toStdString());

            try {
                // TODO: Implement filter application
                updatePacketList();

                filter_bar_->addToHistory(filter);
            }
            catch (const std::exception& e) {
                spdlog::error("Filter error: {}", e.what());
                QMessageBox::critical(this, tr("Filter Error"),
                    tr("Invalid filter:\n%1").arg(e.what()));
            }
        }

        void MainWindow::updatePacketList()
        {
            packet_list_->clearPackets();
            displayed_count_.store(0);

            for (const auto& packet_data : packets_) {
                if (current_filter_.isEmpty() || !packet_data.filtered) {
                    packet_list_->addPacket(packet_data.parsed, packet_data.raw_data);
                    displayed_count_.fetch_add(1);
                }
            }

            updateStatusBar();
        }

    } // namespace GUI
} // namespace NetworkSecurity
