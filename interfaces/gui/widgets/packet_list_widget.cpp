// src/gui/widgets/packet_list_widget.cpp

#include "packet_list_widget.hpp"
#include "models/packet_table_model.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QApplication>
#include <QClipboard>
#include <QKeyEvent>
#include <QSettings>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        PacketListWidget::PacketListWidget(QWidget* parent)
            : QWidget(parent),
              time_format_(0),
              coloring_enabled_(true),
              auto_scroll_(true),
              selected_row_(-1)
        {
            setupUI();
            setupContextMenu();
            loadColumnSettings();
        }

        PacketListWidget::~PacketListWidget()
        {
            saveColumnSettings();
        }

        void PacketListWidget::setupUI()
        {
            QVBoxLayout* layout = new QVBoxLayout(this);
            layout->setContentsMargins(0, 0, 0, 0);

            // Create table view
            table_view_ = new QTableView(this);
            table_view_->setSelectionBehavior(QAbstractItemView::SelectRows);
            table_view_->setSelectionMode(QAbstractItemView::SingleSelection);
            table_view_->setAlternatingRowColors(true);
            table_view_->setShowGrid(true);
            table_view_->setSortingEnabled(true);
            table_view_->setContextMenuPolicy(Qt::CustomContextMenu);
            table_view_->verticalHeader()->setVisible(false);
            table_view_->horizontalHeader()->setStretchLastSection(true);
            table_view_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

            // Create model
            model_ = new PacketTableModel(this);
            table_view_->setModel(model_);

            // Configure columns
            table_view_->setColumnWidth(PacketTableModel::COL_NUMBER, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_TIME, 120);
            table_view_->setColumnWidth(PacketTableModel::COL_SOURCE, 150);
            table_view_->setColumnWidth(PacketTableModel::COL_DESTINATION, 150);
            table_view_->setColumnWidth(PacketTableModel::COL_PROTOCOL, 80);
            table_view_->setColumnWidth(PacketTableModel::COL_LENGTH, 80);

            layout->addWidget(table_view_);

            // Connect signals
            connect(table_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
                    this, &PacketListWidget::onSelectionChanged);
            connect(table_view_, &QTableView::doubleClicked,
                    this, &PacketListWidget::onDoubleClicked);
            connect(table_view_, &QTableView::customContextMenuRequested,
                    this, &PacketListWidget::onCellContextMenu);
            connect(table_view_->horizontalHeader(), &QHeaderView::customContextMenuRequested,
                    this, &PacketListWidget::onHeaderContextMenu);
        }

        void PacketListWidget::setupContextMenu()
        {
            context_menu_ = new QMenu(this);

            // Mark/Unmark
            action_mark_ = context_menu_->addAction(tr("Mark Packet"));
            action_mark_->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_M));
            connect(action_mark_, &QAction::triggered, this, &PacketListWidget::onMarkPacket);

            action_unmark_ = context_menu_->addAction(tr("Unmark Packet"));
            connect(action_unmark_, &QAction::triggered, this, &PacketListWidget::onUnmarkPacket);

            context_menu_->addSeparator();

            // Filter submenu
            filter_menu_ = context_menu_->addMenu(tr("Apply as Filter"));
            
            action_apply_filter_ = filter_menu_->addAction(tr("Selected"));
            connect(action_apply_filter_, &QAction::triggered, this, &PacketListWidget::onApplyAsFilter);

            action_prepare_filter_ = filter_menu_->addAction(tr("Not Selected"));
            connect(action_prepare_filter_, &QAction::triggered, this, &PacketListWidget::onPrepareFilter);

            context_menu_->addSeparator();

            // Follow stream submenu
            follow_menu_ = context_menu_->addMenu(tr("Follow"));
            
            action_follow_tcp_ = follow_menu_->addAction(tr("TCP Stream"));
            connect(action_follow_tcp_, &QAction::triggered, this, &PacketListWidget::onFollowStream);

            action_follow_udp_ = follow_menu_->addAction(tr("UDP Stream"));
            connect(action_follow_udp_, &QAction::triggered, this, &PacketListWidget::onFollowStream);

            context_menu_->addSeparator();

            // Copy
            action_copy_ = context_menu_->addAction(tr("Copy"));
            action_copy_->setShortcut(QKeySequence::Copy);
            action_copy_->setIcon(QIcon::fromTheme("edit-copy"));
            connect(action_copy_, &QAction::triggered, this, &PacketListWidget::onCopyPacket);

            // Export
            action_export_ = context_menu_->addAction(tr("Export Packet..."));
            connect(action_export_, &QAction::triggered, this, &PacketListWidget::onExportPacket);

            // Setup header menu
            header_menu_ = new QMenu(this);
            for (int i = 0; i < PacketTableModel::COL_COUNT; i++) {
                QString column_name = model_->headerData(i, Qt::Horizontal).toString();
                QAction* action = header_menu_->addAction(column_name);
                action->setCheckable(true);
                action->setChecked(true);
                action->setData(i);
            }
        }

        // ==================== Packet Management ====================

        void PacketListWidget::addPacket(const Common::ParsedPacket& packet,
                                        const std::vector<uint8_t>& raw_data)
        {
            model_->addPacket(packet, raw_data);

            // Auto scroll to bottom
            if (auto_scroll_) {
                table_view_->scrollToBottom();
            }
        }

        void PacketListWidget::clearPackets()
        {
            model_->clearPackets();
            selected_row_ = -1;
        }

        void PacketListWidget::updatePacket(int index)
        {
            model_->updatePacket(index);
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
            selectRow(0);
        }

        void PacketListWidget::selectLastPacket()
        {
            selectRow(model_->rowCount() - 1);
        }

        void PacketListWidget::selectNextPacket()
        {
            int current = getSelectedRow();
            if (current < model_->rowCount() - 1) {
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

        // ==================== Filtering ====================

        void PacketListWidget::applyFilter(const QString& filter)
        {
            model_->setFilter(filter);
            model_->applyFilter();
        }

        void PacketListWidget::clearFilter()
        {
            model_->clearFilter();
        }

        // ==================== Marking ====================

        void PacketListWidget::markPacket(int index)
        {
            model_->markPacket(index, true);
        }

        void PacketListWidget::unmarkPacket(int index)
        {
            model_->markPacket(index, false);
        }

        void PacketListWidget::markAll()
        {
            model_->markAll();
        }

        void PacketListWidget::unmarkAll()
        {
            model_->unmarkAll();
        }

        bool PacketListWidget::isMarked(int index) const
        {
            return model_->isMarked(index);
        }

        // ==================== Display ====================

        void PacketListWidget::setColumnVisible(int column, bool visible)
        {
            table_view_->setColumnHidden(column, !visible);
            model_->setColumnVisible(column, visible);
        }

        void PacketListWidget::setTimeFormat(int format)
        {
            time_format_ = format;
            model_->setTimeFormat(static_cast<PacketTableModel::TimeFormat>(format));
        }

        void PacketListWidget::setColoringEnabled(bool enabled)
        {
            coloring_enabled_ = enabled;
            model_->setColoringEnabled(enabled);
        }

        void PacketListWidget::applyColoringRules()
        {
            model_->setColoringEnabled(coloring_enabled_);
        }

        // ==================== Export ====================

        void PacketListWidget::copySelectedPacket()
        {
            int row = getSelectedRow();
            if (row < 0) {
                return;
            }

            QString summary = getPacketSummary(row);
            QApplication::clipboard()->setText(summary);
            spdlog::debug("Copied packet {} to clipboard", row);
        }

        void PacketListWidget::copyAllPackets()
        {
            QString all_packets;
            for (int i = 0; i < model_->rowCount(); i++) {
                all_packets += getPacketSummary(i) + "\n";
            }
            QApplication::clipboard()->setText(all_packets);
            spdlog::debug("Copied all packets to clipboard");
        }

        QString PacketListWidget::getPacketSummary(int index) const
        {
            QString summary;
            for (int col = 0; col < PacketTableModel::COL_COUNT; col++) {
                QModelIndex idx = model_->index(index, col);
                summary += model_->data(idx, Qt::DisplayRole).toString();
                if (col < PacketTableModel::COL_COUNT - 1) {
                    summary += "\t";
                }
            }
            return summary;
        }

        // ==================== Event Handlers ====================

        void PacketListWidget::contextMenuEvent(QContextMenuEvent* event)
        {
            int row = getSelectedRow();
            if (row >= 0) {
                context_menu_->exec(event->globalPos());
            }
        }

        void PacketListWidget::keyPressEvent(QKeyEvent* event)
        {
            switch (event->key()) {
                case Qt::Key_Up:
                    selectPreviousPacket();
                    event->accept();
                    break;

                case Qt::Key_Down:
                    selectNextPacket();
                    event->accept();
                    break;

                case Qt::Key_Home:
                    selectFirstPacket();
                    event->accept();
                    break;

                case Qt::Key_End:
                    selectLastPacket();
                    event->accept();
                    break;

                case Qt::Key_M:
                    if (event->modifiers() & Qt::ControlModifier) {
                        onMarkPacket();
                        event->accept();
                    }
                    break;

                case Qt::Key_C:
                    if (event->modifiers() & Qt::ControlModifier) {
                        copySelectedPacket();
                        event->accept();
                    }
                    break;

                default:
                    QWidget::keyPressEvent(event);
                    break;
            }
        }

        // ==================== Slots ====================

        void PacketListWidget::onSelectionChanged(const QItemSelection& selected,
                                                 const QItemSelection& deselected)
        {
            Q_UNUSED(deselected);

            if (!selected.indexes().isEmpty()) {
                int row = selected.indexes().first().row();
                selected_row_ = row;
                emit packetSelected(row);
            }
        }

        void PacketListWidget::onDoubleClicked(const QModelIndex& index)
        {
            emit packetDoubleClicked(index.row());
        }

        void PacketListWidget::onHeaderContextMenu(const QPoint& pos)
        {
            header_menu_->exec(table_view_->horizontalHeader()->mapToGlobal(pos));
        }

        void PacketListWidget::onCellContextMenu(const QPoint& pos)
        {
            int row = table_view_->indexAt(pos).row();
            if (row >= 0) {
                // Update menu items based on packet type
                const auto* packet = model_->getPacket(row);
                if (packet) {
                    action_follow_tcp_->setEnabled(packet->has_tcp);
                    action_follow_udp_->setEnabled(packet->has_udp);
                    action_mark_->setVisible(!isMarked(row));
                    action_unmark_->setVisible(isMarked(row));
                }

                context_menu_->exec(table_view_->viewport()->mapToGlobal(pos));
            }
        }

        void PacketListWidget::onMarkPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                markPacket(row);
            }
        }

        void PacketListWidget::onUnmarkPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                unmarkPacket(row);
            }
        }

        void PacketListWidget::onApplyAsFilter()
        {
            int row = getSelectedRow();
            if (row < 0) {
                return;
            }

            const auto* packet = model_->getPacket(row);
            if (!packet) {
                return;
            }

            // Build filter based on packet
            QString filter;
            if (packet->has_tcp) {
                filter = QString("tcp.stream == %1").arg(packet->tcp.analysis.stream_index);
            } else if (packet->has_udp) {
                filter = QString("udp.stream == %1").arg(packet->udp.stream_index);
            } else if (packet->has_ipv4) {
                filter = QString("ip.addr == %1").arg(
                    QString::fromStdString(std::to_string(packet->ipv4.src_ip)));
            }

            if (!filter.isEmpty()) {
                emit filterRequested(filter);
            }
        }

        void PacketListWidget::onPrepareFilter()
        {
            // Similar to onApplyAsFilter but with negation
            int row = getSelectedRow();
            if (row < 0) {
                return;
            }

            const auto* packet = model_->getPacket(row);
            if (!packet) {
                return;
            }

            QString filter;
            if (packet->has_tcp) {
                filter = QString("!(tcp.stream == %1)").arg(packet->tcp.analysis.stream_index);
            } else if (packet->has_udp) {
                filter = QString("!(udp.stream == %1)").arg(packet->udp.stream_index);
            }

            if (!filter.isEmpty()) {
                emit filterRequested(filter);
            }
        }

        void PacketListWidget::onFollowStream()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                // Emit signal to main window to handle stream following
                spdlog::info("Follow stream requested for packet {}", row);
            }
        }

        void PacketListWidget::onCopyPacket()
        {
            copySelectedPacket();
        }

        void PacketListWidget::onExportPacket()
        {
            int row = getSelectedRow();
            if (row >= 0) {
                // TODO: Implement packet export
                spdlog::info("Export packet {} requested", row);
            }
        }

        void PacketListWidget::loadColumnSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            // Restore column widths
            for (int i = 0; i < PacketTableModel::COL_COUNT; i++) {
                QString key = QString("packet_list/column_%1_width").arg(i);
                if (settings.contains(key)) {
                    int width = settings.value(key).toInt();
                    table_view_->setColumnWidth(i, width);
                }
            }

            // Restore column visibility
            for (int i = 0; i < PacketTableModel::COL_COUNT; i++) {
                QString key = QString("packet_list/column_%1_visible").arg(i);
                if (settings.contains(key)) {
                    bool visible = settings.value(key).toBool();
                    setColumnVisible(i, visible);
                }
            }
        }

        void PacketListWidget::saveColumnSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            // Save column widths
            for (int i = 0; i < PacketTableModel::COL_COUNT; i++) {
                QString key = QString("packet_list/column_%1_width").arg(i);
                settings.setValue(key, table_view_->columnWidth(i));
            }

            // Save column visibility
            for (int i = 0; i < PacketTableModel::COL_COUNT; i++) {
                QString key = QString("packet_list/column_%1_visible").arg(i);
                settings.setValue(key, !table_view_->isColumnHidden(i));
            }
        }

        // ==================== Missing Methods Implementation ====================

        void PacketTableModel::updatePacket(int index)
        {
            if (index >= 0 && index < static_cast<int>(packets_.size())) {
                QModelIndex topLeft = createIndex(index, 0);
                QModelIndex bottomRight = createIndex(index, COL_COUNT - 1);
                emit dataChanged(topLeft, bottomRight);
            }
        }

        const Common::ParsedPacket* PacketTableModel::getPacket(int index) const
        {
            if (index >= 0 && index < static_cast<int>(packets_.size())) {
                return &packets_[index].parsed;
            }
            return nullptr;
        }

        const std::vector<uint8_t>* PacketTableModel::getRawData(int index) const
        {
            if (index >= 0 && index < static_cast<int>(packets_.size())) {
                return &packets_[index].raw_data;
            }
            return nullptr;
        }

        int PacketTableModel::getPacketCount() const
        {
            return packets_.size();
        }

        int PacketTableModel::getDisplayedCount() const
        {
            if (current_filter_.isEmpty()) {
                return packets_.size();
            }
            return filtered_indices_.size();
        }

        // ==================== Marking ====================

        void PacketTableModel::markPacket(int index, bool marked)
        {
            if (index >= 0 && index < static_cast<int>(packets_.size())) {
                packets_[index].marked = marked;
                updatePacket(index);
                spdlog::debug("Packet {} marked: {}", index, marked);
            }
        }

        void PacketTableModel::markAll()
        {
            beginResetModel();
            for (auto& packet : packets_) {
                packet.marked = true;
            }
            endResetModel();
            spdlog::info("All packets marked");
        }

        void PacketTableModel::unmarkAll()
        {
            beginResetModel();
            for (auto& packet : packets_) {
                packet.marked = false;
            }
            endResetModel();
            spdlog::info("All packets unmarked");
        }

        bool PacketTableModel::isMarked(int index) const
        {
            if (index >= 0 && index < static_cast<int>(packets_.size())) {
                return packets_[index].marked;
            }
            return false;
        }

        // ==================== Filtering ====================

        void PacketTableModel::setFilter(const QString& filter)
        {
            current_filter_ = filter;
            spdlog::info("Filter set: {}", filter.toStdString());
        }

        void PacketTableModel::clearFilter()
        {
            current_filter_.clear();
            filtered_indices_.clear();
            
            beginResetModel();
            for (auto& packet : packets_) {
                packet.filtered = false;
            }
            endResetModel();
            
            spdlog::info("Filter cleared");
        }

        void PacketTableModel::applyFilter()
        {
            if (current_filter_.isEmpty()) {
                clearFilter();
                return;
            }

            beginResetModel();
            filtered_indices_.clear();

            // TODO: Implement proper filter parsing and matching
            // For now, simple string matching in protocol/info
            for (size_t i = 0; i < packets_.size(); i++) {
                bool matches = false;
                
                // Simple filter matching (you should implement proper BPF-like filter)
                QString protocol = formatProtocol(packets_[i]);
                QString info = formatInfo(packets_[i]);
                
                if (protocol.contains(current_filter_, Qt::CaseInsensitive) ||
                    info.contains(current_filter_, Qt::CaseInsensitive)) {
                    matches = true;
                }

                packets_[i].filtered = !matches;
                
                if (matches) {
                    filtered_indices_.push_back(i);
                }
            }

            endResetModel();
            
            spdlog::info("Filter applied: {} packets match", filtered_indices_.size());
        }

        // ==================== Display Settings ====================

        void PacketTableModel::setTimeFormat(TimeFormat format)
        {
            time_format_ = format;
            
            // Update time column
            if (!packets_.empty()) {
                QModelIndex topLeft = createIndex(0, COL_TIME);
                QModelIndex bottomRight = createIndex(packets_.size() - 1, COL_TIME);
                emit dataChanged(topLeft, bottomRight);
            }
            
            spdlog::debug("Time format changed to {}", static_cast<int>(format));
        }

        PacketTableModel::TimeFormat PacketTableModel::getTimeFormat() const
        {
            return time_format_;
        }

        void PacketTableModel::setColoringEnabled(bool enabled)
        {
            coloring_enabled_ = enabled;
            
            // Update all rows
            if (!packets_.empty()) {
                QModelIndex topLeft = createIndex(0, 0);
                QModelIndex bottomRight = createIndex(packets_.size() - 1, COL_COUNT - 1);
                emit dataChanged(topLeft, bottomRight);
            }
            
            spdlog::debug("Coloring enabled: {}", enabled);
        }

        bool PacketTableModel::isColoringEnabled() const
        {
            return coloring_enabled_;
        }

        void PacketTableModel::setColumnVisible(int column, bool visible)
        {
            if (column >= 0 && column < COL_COUNT) {
                column_visible_[column] = visible;
                spdlog::debug("Column {} visibility: {}", column, visible);
            }
        }

        bool PacketTableModel::isColumnVisible(int column) const
        {
            if (column >= 0 && column < COL_COUNT) {
                return column_visible_[column];
            }
            return false;
        }

        // ==================== Color Rules ====================

        ColorRules* PacketTableModel::getColorRules() const
        {
            return color_rules_.get();
        }

        void PacketTableModel::setColorRules(std::unique_ptr<ColorRules> rules)
        {
            color_rules_ = std::move(rules);
            
            // Reapply colors to all packets
            if (coloring_enabled_) {
                beginResetModel();
                for (auto& entry : packets_) {
                    QColor fg, bg;
                    if (color_rules_->matchPacket(entry.parsed, fg, bg)) {
                        entry.color = bg;
                    }
                }
                endResetModel();
            }
            
            spdlog::info("Color rules updated");
        }


    } // namespace GUI
} // namespace NetworkSecurity
