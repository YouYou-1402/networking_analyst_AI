// src/gui/widgets/packet_list_widget.cpp

#include "packet_list_widget.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QApplication>
#include <QClipboard>
#include <QKeyEvent>
#include <QSettings>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        // ==================== Constructor & Destructor ====================

        PacketListWidget::PacketListWidget(QWidget* parent)
            : QWidget(parent)
            , table_view_(nullptr)
            , model_(nullptr)
            , status_label_(nullptr)
            , context_menu_(nullptr)
            , header_menu_(nullptr)
            , filter_menu_(nullptr)
            , follow_menu_(nullptr)
            , export_menu_(nullptr)
            , color_rules_(nullptr)
            , coloring_enabled_(true)
            , time_format_(PacketTableModel::TIME_RELATIVE)
            , auto_scroll_(true)
            , selected_row_(-1)
            , update_timer_(nullptr)
        {
            setupUI();
            setupColorRules();
            setupConnections();
            loadSettings();
            
            spdlog::info("PacketListWidget initialized");
        }

        PacketListWidget::~PacketListWidget()
        {
            saveSettings();
            
            // Delete color rules (we own it)
            if (color_rules_) {
                delete color_rules_;
                color_rules_ = nullptr;
            }
            
            spdlog::info("PacketListWidget destroyed");
        }

        // ==================== UI Setup ====================

        void PacketListWidget::setupUI()
        {
            QVBoxLayout* main_layout = new QVBoxLayout(this);
            main_layout->setContentsMargins(0, 0, 0, 0);
            main_layout->setSpacing(0);

            // Setup table view
            setupTableView();
            main_layout->addWidget(table_view_);

            // Setup status bar
            setupStatusBar();
            main_layout->addWidget(status_label_);

            // Setup context menus
            setupContextMenu();
            setupHeaderMenu();
        }

        void PacketListWidget::setupTableView()
        {
            table_view_ = new QTableView(this);
            
            // Selection behavior
            table_view_->setSelectionBehavior(QAbstractItemView::SelectRows);
            table_view_->setSelectionMode(QAbstractItemView::SingleSelection);
            
            // Appearance
            table_view_->setAlternatingRowColors(true);
            table_view_->setShowGrid(true);
            table_view_->setSortingEnabled(false);  // Disable for now
            table_view_->setWordWrap(false);
            
            // Headers
            table_view_->verticalHeader()->setVisible(false);
            table_view_->verticalHeader()->setDefaultSectionSize(24);
            table_view_->horizontalHeader()->setStretchLastSection(true);
            table_view_->horizontalHeader()->setHighlightSections(false);
            
            // Context menus
            table_view_->setContextMenuPolicy(Qt::CustomContextMenu);
            table_view_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

            // ==================== WIRESHARK-STYLE STYLESHEET ====================
            table_view_->setStyleSheet(
                "QTableView {"
                "    background-color: #FFFFFF;"
                "    alternate-background-color: #F5F5F5;"
                "    color: #000000;"
                "    selection-background-color: #B4D5FE;"
                "    selection-color: #000000;"
                "    gridline-color: #E0E0E0;"
                "    border: 1px solid #C0C0C0;"
                "    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;"
                "    font-size: 9pt;"
                "    outline: none;"
                "}"
                
                "QTableView::item {"
                "    padding: 4px 8px;"
                "    border: none;"
                "}"
                
                "QTableView::item:selected {"
                "    background-color: #B4D5FE;"
                "    color: #000000;"
                "}"
                
                "QTableView::item:hover {"
                "    background-color: #E5F3FF;"
                "}"
                
                "QTableView::item:selected:hover {"
                "    background-color: #9CC7F7;"
                "}"
                
                "QTableView::item:focus {"
                "    background-color: #B4D5FE;"
                "    border: 1px solid #4A90E2;"
                "    outline: none;"
                "}"
                
                "QHeaderView::section {"
                "    background-color: #ECECEC;"
                "    color: #2C2C2C;"
                "    padding: 6px 8px;"
                "    border: none;"
                "    border-right: 1px solid #D0D0D0;"
                "    border-bottom: 2px solid #A0A0A0;"
                "    font-weight: 600;"
                "    font-size: 9pt;"
                "}"
                
                "QHeaderView::section:hover {"
                "    background-color: #DCDCDC;"
                "}"
                
                "QHeaderView::section:pressed {"
                "    background-color: #B4D5FE;"
                "}"
                
                "QScrollBar:vertical {"
                "    background-color: #F0F0F0;"
                "    width: 14px;"
                "    border: none;"
                "}"
                
                "QScrollBar::handle:vertical {"
                "    background-color: #C0C0C0;"
                "    min-height: 30px;"
                "    border-radius: 7px;"
                "    margin: 2px;"
                "}"
                
                "QScrollBar::handle:vertical:hover {"
                "    background-color: #A0A0A0;"
                "}"
                
                "QScrollBar::add-line:vertical,"
                "QScrollBar::sub-line:vertical {"
                "    height: 0px;"
                "}"
                
                "QScrollBar:horizontal {"
                "    background-color: #F0F0F0;"
                "    height: 14px;"
                "    border: none;"
                "}"
                
                "QScrollBar::handle:horizontal {"
                "    background-color: #C0C0C0;"
                "    min-width: 30px;"
                "    border-radius: 7px;"
                "    margin: 2px;"
                "}"
                
                "QScrollBar::handle:horizontal:hover {"
                "    background-color: #A0A0A0;"
                "}"
                
                "QScrollBar::add-line:horizontal,"
                "QScrollBar::sub-line:horizontal {"
                "    width: 0px;"
                "}"
            );

            // Create model
            model_ = new PacketTableModel(this);
            table_view_->setModel(model_);

            // Set column widths
            table_view_->setColumnWidth(PacketTableModel::COL_NUMBER, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_TIME, 120);
            table_view_->setColumnWidth(PacketTableModel::COL_SOURCE, 180);
            table_view_->setColumnWidth(PacketTableModel::COL_DESTINATION, 180);
            table_view_->setColumnWidth(PacketTableModel::COL_PROTOCOL, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_LENGTH, 80);
            // Info column will stretch
        }

        void PacketListWidget::setupStatusBar()
        {
            status_label_ = new QLabel(this);
            status_label_->setStyleSheet(
                "QLabel {"
                "    background-color: #F0F0F0;"
                "    color: #000000;"
                "    padding: 4px 8px;"
                "    border-top: 1px solid #C0C0C0;"
                "    font-size: 9pt;"
                "}"
            );
            status_label_->setText(tr("Packets: 0"));
        }

        void PacketListWidget::setupContextMenu()
        {
            context_menu_ = new QMenu(this);

            // ==================== Marking ====================
            action_mark_ = context_menu_->addAction(QIcon::fromTheme("bookmark-new"), 
                                                   tr("Mark Packet"));
            action_mark_->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_M));
            
            action_unmark_ = context_menu_->addAction(tr("Unmark Packet"));
            
            action_toggle_mark_ = context_menu_->addAction(tr("Toggle Mark"));
            action_toggle_mark_->setShortcut(QKeySequence(Qt::Key_M));
            
            context_menu_->addSeparator();
            
            action_mark_all_ = context_menu_->addAction(tr("Mark All"));
            action_mark_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_M));
            
            action_unmark_all_ = context_menu_->addAction(tr("Unmark All"));

            context_menu_->addSeparator();

            // ==================== Filtering ====================
            filter_menu_ = context_menu_->addMenu(QIcon::fromTheme("view-filter"), 
                                                 tr("Apply as Filter"));
            
            action_apply_filter_ = filter_menu_->addAction(tr("Selected"));
            action_apply_filter_->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_F));
            
            action_prepare_filter_ = filter_menu_->addAction(tr("Not Selected"));
            action_prepare_filter_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_F));
            
            filter_menu_->addSeparator();
            
            action_apply_column_ = filter_menu_->addAction(tr("As Column"));

            context_menu_->addSeparator();

            // ==================== Follow Stream ====================
            follow_menu_ = context_menu_->addMenu(QIcon::fromTheme("go-jump"), 
                                                 tr("Follow"));
            
            action_follow_tcp_ = follow_menu_->addAction(tr("TCP Stream"));
            action_follow_tcp_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::SHIFT | Qt::Key_T));
            
            action_follow_udp_ = follow_menu_->addAction(tr("UDP Stream"));
            action_follow_udp_->setShortcut(QKeySequence(Qt::CTRL | Qt::ALT | Qt::SHIFT | Qt::Key_U));

            context_menu_->addSeparator();

            // ==================== Copy & Export ====================
            action_copy_ = context_menu_->addAction(QIcon::fromTheme("edit-copy"), 
                                                   tr("Copy"));
            action_copy_->setShortcut(QKeySequence::Copy);
            
            action_copy_all_ = context_menu_->addAction(tr("Copy All"));
            action_copy_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));

            context_menu_->addSeparator();

            export_menu_ = context_menu_->addMenu(QIcon::fromTheme("document-save"), 
                                                 tr("Export"));
            
            action_export_ = export_menu_->addAction(tr("Selected Packet..."));
            action_export_->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_E));
            
            action_export_all_ = export_menu_->addAction(tr("All Packets..."));
            action_export_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_E));
            
            action_export_marked_ = export_menu_->addAction(tr("Marked Packets..."));

            context_menu_->addSeparator();

            // ==================== Details ====================
            action_show_details_ = context_menu_->addAction(QIcon::fromTheme("document-properties"), 
                                                           tr("Packet Details"));
            action_show_details_->setShortcut(QKeySequence(Qt::Key_Return));
            
            action_show_bytes_ = context_menu_->addAction(QIcon::fromTheme("utilities-terminal"), 
                                                         tr("Packet Bytes"));
            action_show_bytes_->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_B));
        }

        void PacketListWidget::setupHeaderMenu()
        {
            header_menu_ = new QMenu(this);

            // Column visibility
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                QString column_name = model_->headerData(col, Qt::Horizontal).toString();
                QAction* action = header_menu_->addAction(column_name);
                action->setCheckable(true);
                action->setChecked(true);
                action->setData(col);
                
                connect(action, &QAction::toggled, this, [this, col](bool checked) {
                    setColumnVisible(col, checked);
                });
            }

            header_menu_->addSeparator();

            // Auto-size
            QAction* action_auto_size = header_menu_->addAction(tr("Auto-size Columns"));
            connect(action_auto_size, &QAction::triggered, this, &PacketListWidget::autoSizeColumns);

            // Reset
            QAction* action_reset = header_menu_->addAction(tr("Reset Columns"));
            connect(action_reset, &QAction::triggered, this, &PacketListWidget::resetColumns);
        }

        void PacketListWidget::setupColorRules()
        {
            // Create color rules instance (owned by this widget)
            color_rules_ = new ColorRules();
            
            // Load default rules
            color_rules_->loadDefaults();
            
            // Set to model
            if (model_) {
                model_->setColorRules(color_rules_);
                model_->setColoringEnabled(coloring_enabled_);
            }
            
            spdlog::info("Color rules initialized with {} rules", 
                        color_rules_->getRuleCount());
        }

        void PacketListWidget::setupConnections()
        {
            // Selection changes
            connect(table_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
                    this, &PacketListWidget::onSelectionChanged);
            
            // Double click
            connect(table_view_, &QTableView::doubleClicked,
                    this, &PacketListWidget::onDoubleClicked);
            
            // Context menus
            connect(table_view_, &QTableView::customContextMenuRequested,
                    this, &PacketListWidget::onCellContextMenu);
            connect(table_view_->horizontalHeader(), &QHeaderView::customContextMenuRequested,
                    this, &PacketListWidget::onHeaderContextMenu);

            // ==================== Action Connections ====================
            
            // Marking
            connect(action_mark_, &QAction::triggered, 
                    this, &PacketListWidget::onMarkPacket);
            connect(action_unmark_, &QAction::triggered, 
                    this, &PacketListWidget::onUnmarkPacket);
            connect(action_toggle_mark_, &QAction::triggered, 
                    this, &PacketListWidget::onToggleMarkPacket);
            connect(action_mark_all_, &QAction::triggered, 
                    this, &PacketListWidget::onMarkAllPackets);
            connect(action_unmark_all_, &QAction::triggered, 
                    this, &PacketListWidget::onUnmarkAllPackets);

            // Filtering
            connect(action_apply_filter_, &QAction::triggered, 
                    this, &PacketListWidget::onApplyAsFilter);
            connect(action_prepare_filter_, &QAction::triggered, 
                    this, &PacketListWidget::onPrepareFilter);
            connect(action_apply_column_, &QAction::triggered, 
                    this, &PacketListWidget::onApplyAsColumn);

            // Following
            connect(action_follow_tcp_, &QAction::triggered, 
                    this, &PacketListWidget::onFollowTCPStream);
            connect(action_follow_udp_, &QAction::triggered, 
                    this, &PacketListWidget::onFollowUDPStream);

            // Copy & Export
            connect(action_copy_, &QAction::triggered, 
                    this, &PacketListWidget::onCopyPacket);
            connect(action_copy_all_, &QAction::triggered, 
                    this, &PacketListWidget::onCopyAllPackets);
            connect(action_export_, &QAction::triggered, 
                    this, &PacketListWidget::onExportPacket);
            connect(action_export_all_, &QAction::triggered, 
                    this, &PacketListWidget::onExportAllPackets);

            // Details
            connect(action_show_details_, &QAction::triggered, 
                    this, &PacketListWidget::onShowPacketDetails);
            connect(action_show_bytes_, &QAction::triggered, 
                    this, &PacketListWidget::onShowPacketBytes);

            // Model changes
            connect(model_, &PacketTableModel::packetAdded,
                    this, &PacketListWidget::onPacketAdded);
            connect(model_, &PacketTableModel::packetsChanged,
                    this, &PacketListWidget::onPacketsChanged);
            connect(model_, &PacketTableModel::filterChanged,
                    this, &PacketListWidget::onFilterChanged);

            // Update timer
            update_timer_ = new QTimer(this);
            update_timer_->setInterval(500);  // Update every 500ms
            connect(update_timer_, &QTimer::timeout, 
                    this, &PacketListWidget::updateStatusBar);
            update_timer_->start();
        }

        // ==================== Packet Management ====================

        void PacketListWidget::addPacket(const Common::ParsedPacket& packet, 
                                        const std::vector<uint8_t>& raw_data)
        {
            model_->addPacket(packet, raw_data);
            
            // Auto-scroll to bottom
            if (auto_scroll_) {
                scrollToBottom();
            }
        }

        void PacketListWidget::clearPackets()
        {
            model_->clearPackets();
            selected_row_ = -1;
            
            emit packetsCleared();
            
            spdlog::info("Packets cleared");
        }

        void PacketListWidget::removePacket(int row)
        {
            model_->removePacket(row);
            
            if (selected_row_ == row) {
                selected_row_ = -1;
            } else if (selected_row_ > row) {
                selected_row_--;
            }
        }

        void PacketListWidget::updatePacket(int row)
        {
            model_->updatePacket(row);
        }

        // ==================== Selection ====================

        int PacketListWidget::getSelectedRow() const
        {
            QModelIndexList selected = table_view_->selectionModel()->selectedRows();
            if (selected.isEmpty()) {
                return -1;
            }
            return selected.first().row();
        }

        Common::ParsedPacket PacketListWidget::getSelectedPacket() const
        {
            int row = getSelectedRow();
            if (row >= 0) {
                return model_->getPacket(row).parsed;
            }
            return Common::ParsedPacket();
        }

        std::vector<uint8_t> PacketListWidget::getSelectedRawData() const
        {
            int row = getSelectedRow();
            if (row >= 0) {
                return model_->getPacket(row).raw_data;
            }
            return std::vector<uint8_t>();
        }

        void PacketListWidget::selectRow(int row)
        {
            if (row >= 0 && row < model_->rowCount()) {
                table_view_->selectRow(row);
                table_view_->scrollTo(model_->index(row, 0));
                selected_row_ = row;
            }
        }

        void PacketListWidget::selectFirstPacket()
        {
            if (model_->rowCount() > 0) {
                selectRow(0);
            }
        }

        void PacketListWidget::selectLastPacket()
        {
            int last = model_->rowCount() - 1;
            if (last >= 0) {
                selectRow(last);
            }
        }

        void PacketListWidget::selectNextPacket()
        {
            int current = getSelectedRow();
            if (current >= 0 && current < model_->rowCount() - 1) {
                selectRow(current + 1);
            }
        }

        void PacketListWidget::selectPreviousPacket()
        {
            int current = getSelectedRow();
            if (current > 0) {
                selectRow(current - 1);
            }
        }

        void PacketListWidget::clearSelection()
        {
            table_view_->clearSelection();
            selected_row_ = -1;
        }

        // ==================== Filtering ====================

        void PacketListWidget::setFilter(const QString& filter)
        {
            model_->setFilter(filter);
        }

        QString PacketListWidget::getFilter() const
        {
            return model_->getFilter();
        }

        void PacketListWidget::applyFilter()
        {
            model_->applyFilter();
            emit filterChanged(model_->getFilter());
        }

        void PacketListWidget::clearFilter()
        {
            model_->clearFilter();
            emit filterChanged(QString());
        }

        bool PacketListWidget::isFiltering() const
        {
            return model_->isFiltering();
        }

        // ==================== Marking ====================

        void PacketListWidget::markSelectedPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                model_->markPacket(row, true);
            }
        }

        void PacketListWidget::unmarkSelectedPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                model_->unmarkPacket(row);
            }
        }

        void PacketListWidget::toggleMarkSelectedPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                model_->toggleMark(row);
            }
        }

        void PacketListWidget::markAllPackets()
        {
            model_->markAll();
        }

        void PacketListWidget::unmarkAllPackets()
        {
            model_->unmarkAll();
        }

        bool PacketListWidget::isSelectedMarked() const
        {
            int row = getSelectedRow();
            if (row >= 0) {
                return model_->isMarked(row);
            }
            return false;
        }

        int PacketListWidget::getMarkedCount() const
        {
            return model_->getMarkedCount();
        }


        void PacketListWidget::markPacket(int row)
        {
            if (row >= 0 && row < model_->rowCount()) {
                model_->markPacket(row, true);
                spdlog::debug("Marked packet at row {}", row);
            }
        }

        void PacketListWidget::unmarkPacket(int row)
        {
            if (row >= 0 && row < model_->rowCount()) {
                model_->unmarkPacket(row);
                spdlog::debug("Unmarked packet at row {}", row);
            }
        }

        void PacketListWidget::markAll()
        {
            markAllPackets();
        }

        void PacketListWidget::unmarkAll()
        {
            unmarkAllPackets();
        }

        void PacketListWidget::toggleMark(int row)
        {
            if (row >= 0 && row < model_->rowCount()) {
                model_->toggleMark(row);
                spdlog::debug("Toggled mark for packet at row {}", row);
            }
        }
        // ==================== Display Settings ====================

        void PacketListWidget::setTimeFormat(PacketTableModel::TimeFormat format)
        {
            time_format_ = format;
            model_->setTimeFormat(format);
        }

        PacketTableModel::TimeFormat PacketListWidget::getTimeFormat() const
        {
            return time_format_;
        }

        void PacketListWidget::setColumnVisible(int column, bool visible)
        {
            if (visible) {
                table_view_->showColumn(column);
            } else {
                table_view_->hideColumn(column);
            }
            model_->setColumnVisible(column, visible);
        }

        bool PacketListWidget::isColumnVisible(int column) const
        {
            return !table_view_->isColumnHidden(column);
        }

        void PacketListWidget::resetColumns()
        {
            model_->resetColumns();
            
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                table_view_->showColumn(col);
            }
            
            autoSizeColumns();
        }

        void PacketListWidget::setAutoScroll(bool enabled)
        {
            auto_scroll_ = enabled;
        }

        bool PacketListWidget::isAutoScrollEnabled() const
        {
            return auto_scroll_;
        }

        // ==================== Color Rules ====================

        void PacketListWidget::setColorRules(ColorRules* rules)
        {
            if (!rules) {
                return;
            }

            // Delete old rules if we own them
            if (color_rules_) {
                delete color_rules_;
            }

            color_rules_ = rules;

            if (model_) {
                model_->setColorRules(color_rules_);
                model_->refreshColors();
            }

            spdlog::info("Color rules updated with {} rules", 
                        color_rules_->getRuleCount());
        }

        ColorRules* PacketListWidget::getColorRules() const
        {
            return color_rules_;
        }

        void PacketListWidget::setColoringEnabled(bool enabled)
        {
            coloring_enabled_ = enabled;
            
            if (model_) {
                model_->setColoringEnabled(enabled);
            }
        }

        bool PacketListWidget::isColoringEnabled() const
        {
            return coloring_enabled_;
        }

        void PacketListWidget::refreshColors()
        {
            if (model_) {
                model_->refreshColors();
            }
        }

        void PacketListWidget::loadDefaultColorRules()
        {
            if (color_rules_) {
                color_rules_->loadDefaults();
                
                if (model_) {
                    model_->refreshColors();
                }
                
                spdlog::info("Loaded {} default color rules", 
                            color_rules_->getRuleCount());
            }
        }

        void PacketListWidget::loadColorRulesFromFile(const QString& filename)
        {
            if (color_rules_) {
                if (color_rules_->loadFromFile(filename)) {
                    if (model_) {
                        model_->refreshColors();
                    }
                    
                    QMessageBox::information(this, tr("Success"),
                        tr("Color rules loaded successfully from:\n%1").arg(filename));
                } else {
                    QMessageBox::warning(this, tr("Error"),
                        tr("Failed to load color rules from:\n%1").arg(filename));
                }
            }
        }

        void PacketListWidget::saveColorRulesToFile(const QString& filename)
        {
            if (color_rules_) {
                if (color_rules_->saveToFile(filename)) {
                    QMessageBox::information(this, tr("Success"),
                        tr("Color rules saved successfully to:\n%1").arg(filename));
                } else {
                    QMessageBox::warning(this, tr("Error"),
                        tr("Failed to save color rules to:\n%1").arg(filename));
                }
            }
        }

        // ==================== Export ====================

        void PacketListWidget::copySelectedPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                const PacketEntry& entry = model_->getPacket(row);
                QString text = formatPacketForClipboard(entry);
                QApplication::clipboard()->setText(text);
                
                spdlog::info("Copied packet {} to clipboard", row);
            }
        }

        void PacketListWidget::copyAllPackets()
        {
            QString text = formatAllPacketsForClipboard();
            QApplication::clipboard()->setText(text);
            
            spdlog::info("Copied {} packets to clipboard", model_->getPacketCount());
        }

        void PacketListWidget::exportSelectedPacket(const QString& filename)
        {
            int row = getSelectedRow();
            if (row < 0) {
                return;
            }

            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to open file for writing:\n%1").arg(filename));
                return;
            }

            QTextStream out(&file);
            const PacketEntry& entry = model_->getPacket(row);
            out << formatPacketForClipboard(entry);
            
            file.close();
            
            spdlog::info("Exported packet {} to {}", row, filename.toStdString());
        }

        void PacketListWidget::exportAllPackets(const QString& filename)
        {
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to open file for writing:\n%1").arg(filename));
                return;
            }

            QTextStream out(&file);
            out << formatAllPacketsForClipboard();
            
            file.close();
            
            spdlog::info("Exported {} packets to {}", 
                        model_->getPacketCount(), filename.toStdString());
        }

        void PacketListWidget::exportMarkedPackets(const QString& filename)
        {
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to open file for writing:\n%1").arg(filename));
                return;
            }

            QTextStream out(&file);
            
            int exported = 0;
            for (int row = 0; row < model_->rowCount(); row++) {
                if (model_->isMarked(row)) {
                    const PacketEntry& entry = model_->getPacket(row);
                    out << formatPacketForClipboard(entry);
                    out << "\n---\n\n";
                    exported++;
                }
            }
            
            file.close();
            
            spdlog::info("Exported {} marked packets to {}", 
                        exported, filename.toStdString());
        }

        // ==================== Statistics ====================

        int PacketListWidget::getPacketCount() const
        {
            return model_->getPacketCount();
        }

        int PacketListWidget::getTotalPacketCount() const
        {
            return model_->getTotalPacketCount();
        }

        PacketTableModel::Statistics PacketListWidget::getStatistics() const
        {
            return model_->getStatistics();
        }

        // ==================== Model Access ====================

        PacketTableModel* PacketListWidget::getModel() const
        {
            return model_;
        }

        QTableView* PacketListWidget::getTableView() const
        {
            return table_view_;
        }

        // ==================== Public Slots ====================

        void PacketListWidget::scrollToTop()
        {
            if (model_->rowCount() > 0) {
                table_view_->scrollTo(model_->index(0, 0));
            }
        }

        void PacketListWidget::scrollToBottom()
        {
            int last = model_->rowCount() - 1;
            if (last >= 0) {
                table_view_->scrollTo(model_->index(last, 0));
            }
        }

        void PacketListWidget::scrollToPacket(int row)
        {
            if (row >= 0 && row < model_->rowCount()) {
                table_view_->scrollTo(model_->index(row, 0));
            }
        }

        void PacketListWidget::showColumn(int column)
        {
            setColumnVisible(column, true);
        }

        void PacketListWidget::hideColumn(int column)
        {
            setColumnVisible(column, false);
        }

        void PacketListWidget::resizeColumnsToContents()
        {
            table_view_->resizeColumnsToContents();
        }

        void PacketListWidget::autoSizeColumns()
        {
            // Set reasonable default widths
            table_view_->setColumnWidth(PacketTableModel::COL_NUMBER, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_TIME, 120);
            table_view_->setColumnWidth(PacketTableModel::COL_SOURCE, 180);
            table_view_->setColumnWidth(PacketTableModel::COL_DESTINATION, 180);
            table_view_->setColumnWidth(PacketTableModel::COL_PROTOCOL, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_LENGTH, 80);
            // Info column stretches automatically
        }

        // ==================== Private Slots ====================

        void PacketListWidget::onSelectionChanged(const QItemSelection& selected, 
                                                  const QItemSelection& deselected)
        {
            Q_UNUSED(deselected);

            if (!selected.indexes().isEmpty()) {
                int row = selected.indexes().first().row();
                selected_row_ = row;
                emit packetSelected(row);
            } else {
                selected_row_ = -1;
            }
        }

        void PacketListWidget::onDoubleClicked(const QModelIndex& index)
        {
            if (index.isValid()) {
                emit packetDoubleClicked(index.row());
            }
        }

        void PacketListWidget::onCellContextMenu(const QPoint& pos)
        {
            QModelIndex index = table_view_->indexAt(pos);
            
            if (index.isValid()) {
                // Update action states
                bool has_selection = (getSelectedRow() >= 0);
                bool is_marked = isSelectedMarked();
                
                action_mark_->setEnabled(has_selection && !is_marked);
                action_unmark_->setEnabled(has_selection && is_marked);
                action_toggle_mark_->setEnabled(has_selection);
                
                action_apply_filter_->setEnabled(has_selection);
                action_prepare_filter_->setEnabled(has_selection);
                action_apply_column_->setEnabled(has_selection);
                
                const PacketEntry& entry = model_->getPacket(index.row());
                action_follow_tcp_->setEnabled(entry.parsed.has_tcp);
                action_follow_udp_->setEnabled(entry.parsed.has_udp);
                
                action_copy_->setEnabled(has_selection);
                action_export_->setEnabled(has_selection);
                
                action_show_details_->setEnabled(has_selection);
                action_show_bytes_->setEnabled(has_selection);
                
                // Show menu
                context_menu_->exec(table_view_->viewport()->mapToGlobal(pos));
            }
        }

        void PacketListWidget::onHeaderContextMenu(const QPoint& pos)
        {
            // Update checkboxes
            for (QAction* action : header_menu_->actions()) {
                if (action->isSeparator()) {
                    continue;
                }
                
                int col = action->data().toInt();
                action->setChecked(!table_view_->isColumnHidden(col));
            }
            
            header_menu_->exec(table_view_->horizontalHeader()->mapToGlobal(pos));
        }

        // ==================== Action Handlers ====================

        void PacketListWidget::onMarkPacket()
        {
            markSelectedPacket();
        }

        void PacketListWidget::onUnmarkPacket()
        {
            unmarkSelectedPacket();
        }

        void PacketListWidget::onToggleMarkPacket()
        {
            toggleMarkSelectedPacket();
        }

        void PacketListWidget::onMarkAllPackets()
        {
            markAllPackets();
        }

        void PacketListWidget::onUnmarkAllPackets()
        {
            unmarkAllPackets();
        }

        void PacketListWidget::onApplyAsFilter()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                const PacketEntry& entry = model_->getPacket(row);
                
                // Create filter based on protocol
                QString filter;
                if (entry.parsed.has_tcp) {
                    filter = QString("tcp.port == %1").arg(entry.parsed.tcp.dst_port);
                } else if (entry.parsed.has_udp) {
                    filter = QString("udp.port == %1").arg(entry.parsed.udp.dst_port);
                } else if (entry.parsed.has_ipv4) {
                    filter = QString("ip.addr == %1")
                        .arg(model_->data(model_->index(row, PacketTableModel::COL_SOURCE)).toString());
                }
                
                if (!filter.isEmpty()) {
                    setFilter(filter);
                    applyFilter();
                }
            }
        }

        void PacketListWidget::onPrepareFilter()
        {
            // TODO: Implement prepare filter (open filter dialog)
            spdlog::info("Prepare filter not yet implemented");
        }

        void PacketListWidget::onApplyAsColumn()
        {
            // TODO: Implement apply as column
            spdlog::info("Apply as column not yet implemented");
        }

        void PacketListWidget::onFollowTCPStream()
        {
            // TODO: Implement follow TCP stream
            spdlog::info("Follow TCP stream not yet implemented");
        }

        void PacketListWidget::onFollowUDPStream()
        {
            // TODO: Implement follow UDP stream
            spdlog::info("Follow UDP stream not yet implemented");
        }

        void PacketListWidget::onCopyPacket()
        {
            copySelectedPacket();
        }

        void PacketListWidget::onCopyAllPackets()
        {
            copyAllPackets();
        }

        void PacketListWidget::onExportPacket()
        {
            QString filename = QFileDialog::getSaveFileName(this,
                tr("Export Packet"),
                QString(),
                tr("Text Files (*.txt);;All Files (*)"));
            
            if (!filename.isEmpty()) {
                exportSelectedPacket(filename);
            }
        }

        void PacketListWidget::onExportAllPackets()
        {
            QString filename = QFileDialog::getSaveFileName(this,
                tr("Export All Packets"),
                QString(),
                tr("Text Files (*.txt);;All Files (*)"));
            
            if (!filename.isEmpty()) {
                exportAllPackets(filename);
            }
        }

        void PacketListWidget::onShowPacketDetails()
        {
            // TODO: Open packet details dialog
            spdlog::info("Show packet details not yet implemented");
        }

        void PacketListWidget::onShowPacketBytes()
        {
            // TODO: Open packet bytes dialog
            spdlog::info("Show packet bytes not yet implemented");
        }

        void PacketListWidget::onPacketAdded(int row)
        {
            Q_UNUSED(row);
            updateAutoScroll();
        }

        void PacketListWidget::onPacketsChanged()
        {
            updateStatusBar();
            emit statisticsChanged();
        }

        void PacketListWidget::onFilterChanged()
        {
            updateStatusBar();
        }

        void PacketListWidget::updateStatusBar()
        {
            auto stats = model_->getStatistics();
            
            QString status;
            if (model_->isFiltering()) {
                status = tr("Packets: %1 / %2 (Displayed / Total)")
                    .arg(stats.filtered_packets)
                    .arg(stats.total_packets);
            } else {
                status = tr("Packets: %1").arg(stats.total_packets);
            }
            
            if (stats.marked_packets > 0) {
                status += tr(" | Marked: %1").arg(stats.marked_packets);
            }
            
            if (stats.total_bytes > 0) {
                double mb = stats.total_bytes / (1024.0 * 1024.0);
                status += tr(" | Size: %1 MB").arg(mb, 0, 'f', 2);
            }
            
            status_label_->setText(status);
        }

        void PacketListWidget::updateColumnVisibility()
        {
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                bool visible = model_->isColumnVisible(col);
                if (visible) {
                    table_view_->showColumn(col);
                } else {
                    table_view_->hideColumn(col);
                }
            }
        }

        void PacketListWidget::updateSelection()
        {
            if (selected_row_ >= 0 && selected_row_ < model_->rowCount()) {
                table_view_->selectRow(selected_row_);
            }
        }

        void PacketListWidget::updateAutoScroll()
        {
            if (auto_scroll_) {
                scrollToBottom();
            }
        }

        // ==================== Helper Methods ====================

        QString PacketListWidget::formatPacketForClipboard(const PacketEntry& entry) const
        {
            QString text;
            text += QString("Packet #%1\n").arg(entry.index + 1);
            text += QString("Time: %1\n")
                .arg(model_->data(model_->index(entry.index, PacketTableModel::COL_TIME)).toString());
            text += QString("Source: %1\n")
                .arg(model_->data(model_->index(entry.index, PacketTableModel::COL_SOURCE)).toString());
            text += QString("Destination: %1\n")
                .arg(model_->data(model_->index(entry.index, PacketTableModel::COL_DESTINATION)).toString());
            text += QString("Protocol: %1\n")
                .arg(model_->data(model_->index(entry.index, PacketTableModel::COL_PROTOCOL)).toString());
            text += QString("Length: %1 bytes\n")
                .arg(entry.parsed.packet_size);
            text += QString("Info: %1\n")
                .arg(model_->data(model_->index(entry.index, PacketTableModel::COL_INFO)).toString());
            
            return text;
        }

        QString PacketListWidget::formatAllPacketsForClipboard() const
        {
            QString text;
            
            // Header
            text += QString("%1\t%2\t%3\t%4\t%5\t%6\t%7\n")
                .arg("No.")
                .arg("Time")
                .arg("Source")
                .arg("Destination")
                .arg("Protocol")
                .arg("Length")
                .arg("Info");
            
            text += QString("-").repeated(100) + "\n";
            
            // Packets
            for (int row = 0; row < model_->rowCount(); row++) {
                text += QString("%1\t%2\t%3\t%4\t%5\t%6\t%7\n")
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_NUMBER)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_TIME)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_SOURCE)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_DESTINATION)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_PROTOCOL)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_LENGTH)).toString())
                    .arg(model_->data(model_->index(row, PacketTableModel::COL_INFO)).toString());
            }
            
            return text;
        }

        // ==================== Settings ====================

        void PacketListWidget::loadSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            settings.beginGroup("PacketListWidget");
            
            // Time format
            time_format_ = static_cast<PacketTableModel::TimeFormat>(
                settings.value("time_format", PacketTableModel::TIME_RELATIVE).toInt());
            model_->setTimeFormat(time_format_);
            
            // Auto-scroll
            auto_scroll_ = settings.value("auto_scroll", true).toBool();
            
            // Coloring
            coloring_enabled_ = settings.value("coloring_enabled", true).toBool();
            model_->setColoringEnabled(coloring_enabled_);
            
            settings.endGroup();
            
            // Load column settings
            loadColumnSettings();
            
            spdlog::info("Settings loaded");
        }

        void PacketListWidget::saveSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            settings.beginGroup("PacketListWidget");
            
            settings.setValue("time_format", static_cast<int>(time_format_));
            settings.setValue("auto_scroll", auto_scroll_);
            settings.setValue("coloring_enabled", coloring_enabled_);
            
            settings.endGroup();
            
            // Save column settings
            saveColumnSettings();
            
            spdlog::info("Settings saved");
        }

        void PacketListWidget::loadColumnSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            settings.beginGroup("PacketListWidget/Columns");
            
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                QString key = QString("col_%1_width").arg(col);
                int width = settings.value(key, -1).toInt();
                
                if (width > 0) {
                    table_view_->setColumnWidth(col, width);
                }
                
                key = QString("col_%1_visible").arg(col);
                bool visible = settings.value(key, true).toBool();
                setColumnVisible(col, visible);
            }
            
            settings.endGroup();
        }

        void PacketListWidget::saveColumnSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            settings.beginGroup("PacketListWidget/Columns");
            
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                QString key = QString("col_%1_width").arg(col);
                settings.setValue(key, table_view_->columnWidth(col));
                
                key = QString("col_%1_visible").arg(col);
                settings.setValue(key, !table_view_->isColumnHidden(col));
            }
            
            settings.endGroup();
        }

    } // namespace GUI
} // namespace NetworkSecurity
