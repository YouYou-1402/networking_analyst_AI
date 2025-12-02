// src/gui/widgets/packet_detail_widget.cpp

#include "packet_detail_widget.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QApplication>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>
#include <QScrollBar>
#include <QToolTip>
#include <QPainter>
#include <QTextBlock>
#include <QMouseEvent>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        // ==================== HexDumpWidget Implementation ====================

        HexDumpWidget::HexDumpWidget(QWidget* parent)
            : QTextEdit(parent)
            , highlighted_offset_(-1)
            , highlighted_length_(0)
            , hover_offset_(-1)
        {
            setReadOnly(true);
            setLineWrapMode(QTextEdit::NoWrap);
            setFont(QFont("Consolas", 9));
            setMouseTracking(true);
            
            // Setup formats
            normal_format_.setBackground(Qt::white);
            normal_format_.setForeground(Qt::black);
            
            highlight_format_.setBackground(QColor(180, 213, 254)); // Light blue
            highlight_format_.setForeground(Qt::black);
            highlight_format_.setFontWeight(QFont::Bold);
            
            hover_format_.setBackground(QColor(229, 243, 255)); // Very light blue
            hover_format_.setForeground(Qt::black);
            
            setStyleSheet(
                "QTextEdit {"
                "    background-color: #FFFFFF;"
                "    color: #000000;"
                "    border: 1px solid #C0C0C0;"
                "    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;"
                "    font-size: 9pt;"
                "    selection-background-color: #B4D5FE;"
                "}"
            );
        }

        void HexDumpWidget::setRawData(const std::vector<uint8_t>& data)
        {
            raw_data_ = data;
            buildHexDump();
        }

        void HexDumpWidget::clearData()
        {
            raw_data_.clear();
            clear();
            highlighted_offset_ = -1;
            highlighted_length_ = 0;
            hover_offset_ = -1;
        }

        void HexDumpWidget::buildHexDump()
        {
            if (raw_data_.empty()) {
                clear();
                return;
            }

            QString html;
            html += "<pre style='margin: 0; padding: 5px; font-family: Consolas, monospace; font-size: 9pt;'>";
            
            // Header
            html += "<span style='color: #0000FF; font-weight: bold;'>";
            html += "Offset(h)  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ";
            html += "Decoded text\n";
            html += "</span>";
            
            // Data rows
            for (size_t offset = 0; offset < raw_data_.size(); offset += BYTES_PER_LINE) {
                // Offset
                html += QString("<span style='color: #808080;'>%1  </span>")
                    .arg(offset, 8, 16, QChar('0')).toUpper();
                
                // Hex bytes
                size_t line_len = std::min(size_t(BYTES_PER_LINE), raw_data_.size() - offset);
                for (size_t i = 0; i < BYTES_PER_LINE; i++) {
                    if (i < line_len) {
                        html += QString("<span id='byte_%1'>%2</span> ")
                            .arg(offset + i)
                            .arg(raw_data_[offset + i], 2, 16, QChar('0')).toUpper();
                    } else {
                        html += "   ";
                    }
                }
                
                html += " ";
                
                // ASCII representation
                for (size_t i = 0; i < line_len; i++) {
                    uint8_t byte = raw_data_[offset + i];
                    QChar c = (byte >= 32 && byte <= 126) ? QChar(byte) : QChar('.');
                    html += QString("<span id='ascii_%1'>%2</span>")
                        .arg(offset + i)
                        .arg(c);
                }
                
                html += "\n";
            }
            
            html += "</pre>";
            
            setHtml(html);
        }

        void HexDumpWidget::highlightBytes(int offset, int length)
        {
            if (offset < 0 || length <= 0 || raw_data_.empty()) {
                clearHighlight();
                return;
            }

            highlighted_offset_ = offset;
            highlighted_length_ = length;
            
            // Rebuild with highlighting
            QTextCursor cursor = textCursor();
            cursor.movePosition(QTextCursor::Start);
            
            // Calculate position in text
            // Format: "Offset(h)  00 01 02 03...\n" + data lines
            int header_lines = 1;
            int line_number = offset / BYTES_PER_LINE;
            int byte_in_line = offset % BYTES_PER_LINE;
            
            // Move to correct line
            for (int i = 0; i < header_lines + line_number; i++) {
                cursor.movePosition(QTextCursor::Down);
            }
            
            // Move to correct position in line
            // Offset(8) + "  "(2) + (byte_pos * 3)
            int char_pos = 10 + (byte_in_line * 3);
            cursor.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor, char_pos);
            
            // Select bytes
            int remaining = length;
            while (remaining > 0 && cursor.position() < document()->characterCount()) {
                cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 2);
                remaining--;
                
                if (remaining > 0) {
                    cursor.movePosition(QTextCursor::Right, QTextCursor::KeepAnchor, 1); // Space
                }
                
                // Handle line wrap
                if ((offset + length - remaining) % BYTES_PER_LINE == 0 && remaining > 0) {
                    cursor.movePosition(QTextCursor::Down);
                    cursor.movePosition(QTextCursor::Right, QTextCursor::MoveAnchor, 10);
                }
            }
            
            // Apply format
            cursor.mergeCharFormat(highlight_format_);
            
            // Scroll to visible
            setTextCursor(cursor);
            ensureCursorVisible();
        }

        void HexDumpWidget::clearHighlight()
        {
            highlighted_offset_ = -1;
            highlighted_length_ = 0;
            
            // Reset all formatting
            QTextCursor cursor = textCursor();
            cursor.select(QTextCursor::Document);
            cursor.setCharFormat(normal_format_);
        }

        void HexDumpWidget::mouseMoveEvent(QMouseEvent* event)
        {
            QTextEdit::mouseMoveEvent(event);
            
            int offset = getOffsetAtPosition(event->pos());
            if (offset >= 0 && offset != hover_offset_) {
                updateHoverHighlight(offset);
                
                // Show tooltip
                QString tooltip = QString("Offset: 0x%1 (%2)\nValue: 0x%3 (%4)")
                    .arg(offset, 4, 16, QChar('0'))
                    .arg(offset)
                    .arg(raw_data_[offset], 2, 16, QChar('0'))
                    .arg(raw_data_[offset]);
                QToolTip::showText(event->globalPosition().toPoint(), tooltip);
                
                emit bytesHovered(offset, 1);
            }
        }

        void HexDumpWidget::leaveEvent(QEvent* event)
        {
            QTextEdit::leaveEvent(event);
            hover_offset_ = -1;
            QToolTip::hideText();
        }

        int HexDumpWidget::getOffsetAtPosition(const QPoint& pos)
        {
            QTextCursor cursor = cursorForPosition(pos);
            int line = cursor.blockNumber();
            
            if (line <= 0) { // Header line
                return -1;
            }
            
            line--; // Adjust for header
            
            QString line_text = cursor.block().text();
            int col = cursor.positionInBlock();
            
            // Check if in hex area (after offset)
            if (col < 10) {
                return -1;
            }
            
            int hex_area_col = col - 10;
            int byte_in_line = hex_area_col / 3;
            
            if (byte_in_line >= BYTES_PER_LINE) {
                return -1;
            }
            
            int offset = line * BYTES_PER_LINE + byte_in_line;
            
            if (offset >= static_cast<int>(raw_data_.size())) {
                return -1;
            }
            
            return offset;
        }

        void HexDumpWidget::updateHoverHighlight(int offset)
        {
            hover_offset_ = offset;
            // Could implement hover highlighting here if needed
        }

        // ==================== PacketDetailWidget Implementation ====================

        PacketDetailWidget::PacketDetailWidget(QWidget* parent)
            : QWidget(parent)
            , splitter_(nullptr)
            , tree_widget_(nullptr)
            , hex_widget_(nullptr)
            , context_menu_(nullptr)
            , expand_menu_(nullptr)
            , filter_menu_(nullptr)
            , copy_menu_(nullptr)
            , export_menu_(nullptr)
            , current_packet_(nullptr)
            , selected_item_(nullptr)
            , show_hex_data_(true)
            , auto_expand_(true)
            , search_case_sensitive_(false)
            , search_current_index_(-1)
        {
            setupUI();
            
            spdlog::info("PacketDetailWidget initialized with split view");
        }

        PacketDetailWidget::~PacketDetailWidget()
        {
            spdlog::info("PacketDetailWidget destroyed");
        }

        // ==================== UI Setup ====================

        void PacketDetailWidget::setupUI()
        {
            QVBoxLayout* layout = new QVBoxLayout(this);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(0);

            setupSplitter();
            setupTreeWidget();
            setupHexWidget();
            setupContextMenu();
            applyWiresharkStyle();
            
            layout->addWidget(splitter_);
        }

        void PacketDetailWidget::setupSplitter()
        {
            splitter_ = new QSplitter(Qt::Horizontal, this);
            splitter_->setChildrenCollapsible(false);
            splitter_->setHandleWidth(4);
            
            splitter_->setStyleSheet(
                "QSplitter::handle {"
                "    background-color: #D0D0D0;"
                "    border: 1px solid #A0A0A0;"
                "}"
                "QSplitter::handle:hover {"
                "    background-color: #B0B0B0;"
                "}"
            );
        }

        void PacketDetailWidget::setupTreeWidget()
        {
            tree_widget_ = new QTreeWidget(this);
            
            // Headers
            tree_widget_->setHeaderLabels(QStringList() << tr("Field") << tr("Value"));
            tree_widget_->setColumnCount(2);
            
            // Appearance
            tree_widget_->setAlternatingRowColors(true);
            tree_widget_->setRootIsDecorated(true);
            tree_widget_->setIndentation(20);
            tree_widget_->setAnimated(true);
            tree_widget_->setUniformRowHeights(false);
            tree_widget_->setWordWrap(false);
            
            // Selection
            tree_widget_->setSelectionMode(QAbstractItemView::SingleSelection);
            tree_widget_->setSelectionBehavior(QAbstractItemView::SelectRows);
            
            // Context menu
            tree_widget_->setContextMenuPolicy(Qt::CustomContextMenu);
            
            // Header
            tree_widget_->header()->setStretchLastSection(true);
            tree_widget_->header()->setSectionResizeMode(0, QHeaderView::Interactive);
            tree_widget_->header()->setSectionResizeMode(1, QHeaderView::Stretch);
            tree_widget_->setColumnWidth(0, 300);

            // Enable mouse tracking for hover
            tree_widget_->setMouseTracking(true);
            tree_widget_->viewport()->setMouseTracking(true);

            // Connections
            connect(tree_widget_, &QTreeWidget::itemClicked,
                    this, &PacketDetailWidget::onItemClicked);
            connect(tree_widget_, &QTreeWidget::itemDoubleClicked,
                    this, &PacketDetailWidget::onItemDoubleClicked);
            connect(tree_widget_, &QTreeWidget::itemExpanded,
                    this, &PacketDetailWidget::onItemExpanded);
            connect(tree_widget_, &QTreeWidget::itemCollapsed,
                    this, &PacketDetailWidget::onItemCollapsed);
            connect(tree_widget_, &QTreeWidget::customContextMenuRequested,
                    this, &PacketDetailWidget::onItemContextMenu);
            connect(tree_widget_, &QTreeWidget::itemSelectionChanged,
                    this, &PacketDetailWidget::onItemSelectionChanged);
            connect(tree_widget_, &QTreeWidget::itemEntered,
                    this, &PacketDetailWidget::onTreeItemHovered);
            
            splitter_->addWidget(tree_widget_);
        }

        void PacketDetailWidget::setupHexWidget()
        {
            hex_widget_ = new HexDumpWidget(this);
            
            connect(hex_widget_, &HexDumpWidget::bytesHovered,
                    this, &PacketDetailWidget::onHexBytesHovered);
            
            splitter_->addWidget(hex_widget_);
            
            // Set initial sizes (60% tree, 40% hex)
            splitter_->setSizes(QList<int>() << 600 << 400);
        }

        void PacketDetailWidget::applyWiresharkStyle()
        {
            tree_widget_->setStyleSheet(
                "QTreeWidget {"
                "    background-color: #FFFFFF;"
                "    alternate-background-color: #F5F5F5;"
                "    color: #000000;"
                "    selection-background-color: #B4D5FE;"
                "    selection-color: #000000;"
                "    border: 1px solid #C0C0C0;"
                "    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;"
                "    font-size: 9pt;"
                "    outline: none;"
                "}"
                
                "QTreeWidget::item {"
                "    padding: 3px 5px;"
                "    border: none;"
                "    min-height: 20px;"
                "}"
                
                "QTreeWidget::item:selected {"
                "    background-color: #B4D5FE;"
                "    color: #000000;"
                "}"
                
                "QTreeWidget::item:hover {"
                "    background-color: #E5F3FF;"
                "}"
                
                "QTreeWidget::item:selected:hover {"
                "    background-color: #9CC7F7;"
                "}"
                
                "QHeaderView::section {"
                "    background-color: #ECECEC;"
                "    color: #2C2C2C;"
                "    padding: 5px 8px;"
                "    border: none;"
                "    border-right: 1px solid #D0D0D0;"
                "    border-bottom: 2px solid #A0A0A0;"
                "    font-weight: 600;"
                "    font-size: 9pt;"
                "}"
            );
        }

        void PacketDetailWidget::setupContextMenu()
        {
            context_menu_ = new QMenu(this);

            // ==================== Expand/Collapse ====================
            expand_menu_ = context_menu_->addMenu(QIcon::fromTheme("view-list-tree"), 
                                                 tr("Expand"));
            
            action_expand_all_ = expand_menu_->addAction(tr("Expand All"));
            action_expand_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
            connect(action_expand_all_, &QAction::triggered, this, &PacketDetailWidget::onExpandAll);
            
            action_expand_subtree_ = expand_menu_->addAction(tr("Expand Subtree"));
            action_expand_subtree_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_E));
            connect(action_expand_subtree_, &QAction::triggered, this, &PacketDetailWidget::onExpandSubtree);
            
            expand_menu_->addSeparator();
            
            action_collapse_all_ = expand_menu_->addAction(tr("Collapse All"));
            action_collapse_all_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_E));
            connect(action_collapse_all_, &QAction::triggered, this, &PacketDetailWidget::onCollapseAll);
            
            action_collapse_subtree_ = expand_menu_->addAction(tr("Collapse Subtree"));
            action_collapse_subtree_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_C));
            connect(action_collapse_subtree_, &QAction::triggered, this, &PacketDetailWidget::onCollapseSubtree);

            context_menu_->addSeparator();

            // ==================== Filter ====================
            filter_menu_ = context_menu_->addMenu(QIcon::fromTheme("view-filter"), 
                                                 tr("Apply as Filter"));
            
            action_apply_filter_ = filter_menu_->addAction(tr("Selected"));
            connect(action_apply_filter_, &QAction::triggered, this, &PacketDetailWidget::onApplyAsFilter);
            
            action_prepare_filter_ = filter_menu_->addAction(tr("Not Selected"));
            connect(action_prepare_filter_, &QAction::triggered, this, &PacketDetailWidget::onPrepareFilter);

            context_menu_->addSeparator();

            // ==================== Copy ====================
            copy_menu_ = context_menu_->addMenu(QIcon::fromTheme("edit-copy"), 
                                               tr("Copy"));
            
            action_copy_field_ = copy_menu_->addAction(tr("Field Name"));
            connect(action_copy_field_, &QAction::triggered, this, &PacketDetailWidget::onCopyField);
            
            action_copy_value_ = copy_menu_->addAction(tr("Value"));
            connect(action_copy_value_, &QAction::triggered, this, &PacketDetailWidget::onCopyValue);
            
            action_copy_both_ = copy_menu_->addAction(tr("Field and Value"));
            connect(action_copy_both_, &QAction::triggered, this, &PacketDetailWidget::onCopyBoth);
            
            copy_menu_->addSeparator();
            
            action_copy_bytes_hex_ = copy_menu_->addAction(tr("Bytes (Hex)"));
            connect(action_copy_bytes_hex_, &QAction::triggered, this, &PacketDetailWidget::onCopyBytesHex);
            
            action_copy_bytes_text_ = copy_menu_->addAction(tr("Bytes (Text)"));
            connect(action_copy_bytes_text_, &QAction::triggered, this, &PacketDetailWidget::onCopyBytesText);

            context_menu_->addSeparator();

            // ==================== Export ====================
            export_menu_ = context_menu_->addMenu(QIcon::fromTheme("document-save"), 
                                                 tr("Export"));
            
            action_export_bytes_ = export_menu_->addAction(tr("Selected Bytes..."));
            connect(action_export_bytes_, &QAction::triggered, this, &PacketDetailWidget::onExportBytes);
            
            action_export_packet_ = export_menu_->addAction(tr("Packet Details..."));
            connect(action_export_packet_, &QAction::triggered, this, &PacketDetailWidget::onExportPacket);
        }

        // ==================== Display ====================

        void PacketDetailWidget::displayPacket(const Common::ParsedPacket& packet,
                                              const std::vector<uint8_t>& raw_data)
        {
            try {
                tree_widget_->clear();
                hex_widget_->clearData();
                selected_item_ = nullptr;
                
                current_packet_ = &packet;
                current_raw_data_ = raw_data;

                // Build tree structure
                buildPacketTree(packet, raw_data);
                
                // Display hex dump
                hex_widget_->setRawData(raw_data);
                
                spdlog::debug("Displayed packet details with hex dump");
            } catch (const std::exception& e) {
                spdlog::error("displayPacket exception: {}", e.what());
                clearDisplay();
            }
        }

        void PacketDetailWidget::clearDisplay()
        {
            tree_widget_->clear();
            hex_widget_->clearData();
            current_packet_ = nullptr;
            current_raw_data_.clear();
            selected_item_ = nullptr;
            
            spdlog::debug("Cleared packet details");
        }

        void PacketDetailWidget::refresh()
        {
            if (current_packet_ && !current_raw_data_.empty()) {
                displayPacket(*current_packet_, current_raw_data_);
            }
        }

        void PacketDetailWidget::setSplitterRatio(double ratio)
        {
            if (ratio < 0.0 || ratio > 1.0) {
                return;
            }
            
            int total_width = splitter_->width();
            int left_width = static_cast<int>(total_width * ratio);
            int right_width = total_width - left_width;
            
            splitter_->setSizes(QList<int>() << left_width << right_width);
        }

        // ==================== Slots ====================

        void PacketDetailWidget::onItemClicked(QTreeWidgetItem* item, int column)
        {
            Q_UNUSED(column);
            
            selected_item_ = item;

            int offset = item->data(0, Qt::UserRole).toInt();
            int length = item->data(0, Qt::UserRole + 1).toInt();

            if (offset >= 0 && length > 0) {
                // Highlight in hex dump
                hex_widget_->highlightBytes(offset, length);
                emit bytesSelected(offset, length);
            } else {
                hex_widget_->clearHighlight();
            }

            emit fieldSelected(item->text(0), item->text(1));
        }

        void PacketDetailWidget::onTreeItemHovered(QTreeWidgetItem* item, int column)
        {
            Q_UNUSED(column);
            
            if (!item) {
                return;
            }

            int offset = item->data(0, Qt::UserRole).toInt();
            int length = item->data(0, Qt::UserRole + 1).toInt();

            if (offset >= 0 && length > 0) {
                // Could show temporary highlight on hover
                // For now, just show tooltip
                QString tooltip = QString("Offset: 0x%1, Length: %2 bytes")
                    .arg(offset, 4, 16, QChar('0'))
                    .arg(length);
                item->setToolTip(0, tooltip);
            }
        }

        void PacketDetailWidget::onHexBytesHovered(int offset, int length)
        {
            // Find corresponding tree item and highlight it
            // This is the reverse direction: hex -> tree
            Q_UNUSED(offset);
            Q_UNUSED(length);
            
            // Could implement tree item highlighting based on hex hover
            // For now, just emit signal
        }

        void PacketDetailWidget::onItemDoubleClicked(QTreeWidgetItem* item, int column)
        {
            Q_UNUSED(column);
            
            if (item->childCount() > 0) {
                item->setExpanded(!item->isExpanded());
            }
        }

        void PacketDetailWidget::onItemExpanded(QTreeWidgetItem* item)
        {
            emit protocolExpanded(item->text(0));
        }

        void PacketDetailWidget::onItemCollapsed(QTreeWidgetItem* item)
        {
            emit protocolCollapsed(item->text(0));
        }

        void PacketDetailWidget::onItemContextMenu(const QPoint& pos)
        {
            QTreeWidgetItem* item = tree_widget_->itemAt(pos);
            
            if (item) {
                selected_item_ = item;
                
                bool has_children = (item->childCount() > 0);
                action_expand_subtree_->setEnabled(has_children);
                action_collapse_subtree_->setEnabled(has_children);
                
                bool has_bytes = (getSelectedLength() > 0);
                action_copy_bytes_hex_->setEnabled(has_bytes);
                action_copy_bytes_text_->setEnabled(has_bytes);
                action_export_bytes_->setEnabled(has_bytes);
                
                context_menu_->exec(tree_widget_->viewport()->mapToGlobal(pos));
            }
        }

        void PacketDetailWidget::onItemSelectionChanged()
        {
            QList<QTreeWidgetItem*> selected = tree_widget_->selectedItems();
            
            if (!selected.isEmpty()) {
                selected_item_ = selected.first();
            } else {
                selected_item_ = nullptr;
                hex_widget_->clearHighlight();
            }
        }


        // ==================== Build Packet Tree ====================

        void PacketDetailWidget::buildPacketTree(const Common::ParsedPacket& packet,
                                                const std::vector<uint8_t>& raw_data)
        {
            Q_UNUSED(raw_data);
            int offset = 0;

            // Frame information
            addFrameInfo(packet);

            // Ethernet
            if (packet.has_ethernet) {
                offset = 0;
                addEthernetInfo(packet, offset);
                offset += 14;  // Ethernet header size
                
                if (packet.ethernet.has_vlan) {
                    addVLANInfo(packet, offset);
                    offset += 4;  // VLAN tag size
                }
            }

            // ARP
            if (packet.has_arp) {
                addARPInfo(packet, offset);
                return;  // ARP packets don't have IP layer
            }

            // IPv4
            if (packet.has_ipv4) {
                addIPv4Info(packet, offset);
                offset += packet.ipv4.ihl * 4;
            }

            // IPv6
            if (packet.has_ipv6) {
                addIPv6Info(packet, offset);
                offset += 40;  // IPv6 header size
            }

            // TCP
            if (packet.has_tcp) {
                addTCPInfo(packet, offset);
                offset += packet.tcp.data_offset * 4;
            }

            // UDP
            if (packet.has_udp) {
                addUDPInfo(packet, offset);
                offset += 8;  // UDP header size
            }

            // ICMP
            if (packet.has_icmp) {
                addICMPInfo(packet, offset);
                offset += 8;  // ICMP header size
            }

            // ICMPv6
            if (packet.has_icmpv6) {
                addICMPv6Info(packet, offset);
                offset += 8;  // ICMPv6 header size
            }

            // Application layer
            if (packet.app_protocol != Common::AppProtocol::UNKNOWN) {
                addApplicationInfo(packet, offset);
            }

            // Payload
            if (packet.payload_length > 0) {
                addPayloadInfo(packet, offset);
            }
        }
        // ==================== Protocol Layers (Part 2/3) ====================

        QTreeWidgetItem* PacketDetailWidget::addFrameInfo(const Common::ParsedPacket& packet)
        {
            QString summary = QString("Frame %1: %2 bytes on wire (%3 bytes captured)")
                .arg(packet.frame_metadata.frame_number)
                .arg(packet.frame_metadata.frame_len)
                .arg(packet.frame_metadata.frame_cap_len);
            
            auto* frame = createItem(summary, QString(), 0, packet.frame_metadata.frame_cap_len);
            frame->setIcon(0, QIcon::fromTheme("network-wired"));

            addChildItem(frame, "Interface", "wlan0");  // TODO: Get from capture
            addChildItem(frame, "Encapsulation type", "Ethernet (1)");
            addChildItem(frame, "Arrival Time", formatTime(packet.timestamp / 1000000.0));
            addChildItem(frame, "Frame Number", QString::number(packet.frame_metadata.frame_number));
            addChildItem(frame, "Frame Length", QString("%1 bytes").arg(packet.frame_metadata.frame_len));
            addChildItem(frame, "Capture Length", QString("%1 bytes").arg(packet.frame_metadata.frame_cap_len));
            
            if (packet.frame_metadata.frame_time_relative > 0) {
                addChildItem(frame, "Time since reference", 
                           formatTime(packet.frame_metadata.frame_time_relative));
            }
            
            if (packet.frame_metadata.frame_time_delta > 0) {
                addChildItem(frame, "Time since previous frame", 
                           formatTime(packet.frame_metadata.frame_time_delta));
            }
            
            if (!packet.frame_metadata.frame_protocols.empty()) {
                addChildItem(frame, "Protocols in frame", 
                           QString::fromStdString(packet.frame_metadata.frame_protocols));
            }

            tree_widget_->addTopLevelItem(frame);
            
            if (auto_expand_) {
                frame->setExpanded(true);
            }
            
            return frame;
        }

        QTreeWidgetItem* PacketDetailWidget::addEthernetInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString dst_mac = formatMAC(packet.ethernet.dst_mac);
            QString src_mac = formatMAC(packet.ethernet.src_mac);
            QString ether_type = getEtherTypeString(ntohs(packet.ethernet.ether_type));
            
            QString summary = QString("Ethernet II, Src: %1, Dst: %2")
                .arg(src_mac)
                .arg(dst_mac);
            
            auto* eth = createItem(summary, QString(), offset, 14);
            eth->setIcon(0, QIcon::fromTheme("network-wired"));

            addChildItem(eth, "Destination", dst_mac, offset, 6);
            addChildItem(eth, "Source", src_mac, offset + 6, 6);
            addChildItem(eth, "Type", QString("%1 (0x%2)")
                .arg(ether_type)
                .arg(ntohs(packet.ethernet.ether_type), 4, 16, QChar('0')), 
                offset + 12, 2);

            tree_widget_->addTopLevelItem(eth);
            
            if (auto_expand_) {
                eth->setExpanded(true);
            }
            
            return eth;
        }

        QTreeWidgetItem* PacketDetailWidget::addVLANInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString summary = QString("802.1Q Virtual LAN, PRI: %1, ID: %2")
                .arg(packet.ethernet.vlan_priority)
                .arg(packet.ethernet.vlan_id);
            
            auto* vlan = createItem(summary, QString(), offset, 4);
            vlan->setIcon(0, QIcon::fromTheme("network-wired"));

            // uint16_t tci = (packet.ethernet.vlan_priority << 13) | 
            //               (packet.ethernet.vlan_cfi << 12) | 
            //               packet.ethernet.vlan_id;
            
            addChildItem(vlan, "Priority", QString::number(packet.ethernet.vlan_priority));
            addChildItem(vlan, "CFI", QString::number(packet.ethernet.vlan_cfi));
            addChildItem(vlan, "ID", QString::number(packet.ethernet.vlan_id));
            addChildItem(vlan, "Type", QString("0x%1")
                .arg(ntohs(packet.ethernet.ether_type), 4, 16, QChar('0')));

            tree_widget_->addTopLevelItem(vlan);
            vlan->setExpanded(true);
            
            return vlan;
        }

        QTreeWidgetItem* PacketDetailWidget::addARPInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString opcode_str = getARPOpcodeString(packet.arp.opcode);
            QString sender_ip = formatIPv4(packet.arp.sender_ip);
            QString target_ip = formatIPv4(packet.arp.target_ip);
            
            QString summary = QString("Address Resolution Protocol (%1)")
                .arg(opcode_str);
            
            auto* arp = createItem(summary, QString(), offset, 28);
            arp->setIcon(0, QIcon::fromTheme("network-transmit-receive"));

            addChildItem(arp, "Hardware type", "Ethernet (1)");
            addChildItem(arp, "Protocol type", "IPv4 (0x0800)");
            addChildItem(arp, "Hardware size", "6");
            addChildItem(arp, "Protocol size", "4");
            addChildItem(arp, "Opcode", QString("%1 (%2)")
                .arg(opcode_str)
                .arg(packet.arp.opcode));
            
            addChildItem(arp, "Sender MAC address", formatMAC(packet.arp.sender_mac));
            addChildItem(arp, "Sender IP address", sender_ip);
            addChildItem(arp, "Target MAC address", formatMAC(packet.arp.target_mac));
            addChildItem(arp, "Target IP address", target_ip);

            if (packet.arp.is_gratuitous) {
                auto* info = createItem("Info", "Gratuitous ARP");
                info->setForeground(0, QColor(Qt::blue));
                arp->addChild(info);
            }
            
            if (packet.arp.is_probe) {
                auto* info = createItem("Info", "ARP Probe");
                info->setForeground(0, QColor(Qt::blue));
                arp->addChild(info);
            }

            tree_widget_->addTopLevelItem(arp);
            arp->setExpanded(true);
            
            return arp;
        }

        QTreeWidgetItem* PacketDetailWidget::addIPv4Info(const Common::ParsedPacket& packet, int offset)
        {
            QString src_ip = formatIPv4(packet.ipv4.src_ip);
            QString dst_ip = formatIPv4(packet.ipv4.dst_ip);
            QString protocol = getIPProtocolString(packet.ipv4.protocol);
            
            QString summary = QString("Internet Protocol Version 4, Src: %1, Dst: %2")
                .arg(src_ip)
                .arg(dst_ip);
            
            int header_len = packet.ipv4.ihl * 4;
            auto* ip = createItem(summary, QString(), offset, header_len);
            ip->setIcon(0, QIcon::fromTheme("network-transmit"));

            addChildItem(ip, "Version", QString::number(packet.ipv4.version));
            addChildItem(ip, "Header Length", QString("%1 bytes (%2)")
                .arg(header_len)
                .arg(packet.ipv4.ihl));
            
            // DSCP and ECN
            auto* dscp_ecn = createItem("Differentiated Services Field", 
                QString("0x%1").arg(packet.ipv4.dscp << 2 | packet.ipv4.ecn, 2, 16, QChar('0')));
            addChildItem(dscp_ecn, "DSCP", QString("0x%1 (%2)")
                .arg(packet.ipv4.dscp, 2, 16, QChar('0'))
                .arg(packet.ipv4.dscp));
            addChildItem(dscp_ecn, "ECN", QString("0x%1 (%2)")
                .arg(packet.ipv4.ecn, 1, 16, QChar('0'))
                .arg(packet.ipv4.ecn));
            ip->addChild(dscp_ecn);
            
            addChildItem(ip, "Total Length", QString("%1 bytes").arg(packet.ipv4.total_length));
            addChildItem(ip, "Identification", QString("0x%1 (%2)")
                .arg(packet.ipv4.identification, 4, 16, QChar('0'))
                .arg(packet.ipv4.identification));
            
            // Flags
            auto* flags = createItem("Flags", QString("0x%1").arg(packet.ipv4.flags, 1, 16, QChar('0')));
            addChildItem(flags, "Reserved bit", packet.ipv4.flag_reserved ? "Set" : "Not set");
            addChildItem(flags, "Don't fragment", packet.ipv4.flag_df ? "Set" : "Not set");
            addChildItem(flags, "More fragments", packet.ipv4.flag_mf ? "Set" : "Not set");
            ip->addChild(flags);
            
            addChildItem(ip, "Fragment Offset", QString::number(packet.ipv4.fragment_offset));
            addChildItem(ip, "Time to Live", QString::number(packet.ipv4.ttl));
            addChildItem(ip, "Protocol", QString("%1 (%2)")
                .arg(protocol)
                .arg(packet.ipv4.protocol));
            addChildItem(ip, "Header Checksum", QString("0x%1")
                .arg(packet.ipv4.checksum, 4, 16, QChar('0')));
            addChildItem(ip, "Source Address", src_ip);
            addChildItem(ip, "Destination Address", dst_ip);

            tree_widget_->addTopLevelItem(ip);
            ip->setExpanded(true);
            
            return ip;
        }

        QTreeWidgetItem* PacketDetailWidget::addIPv6Info(const Common::ParsedPacket& packet, int offset)
        {
            QString src_ip = formatIPv6(packet.ipv6.src_ip);
            QString dst_ip = formatIPv6(packet.ipv6.dst_ip);
            
            QString summary = QString("Internet Protocol Version 6, Src: %1, Dst: %2")
                .arg(src_ip)
                .arg(dst_ip);
            
            auto* ip = createItem(summary, QString(), offset, 40);
            ip->setIcon(0, QIcon::fromTheme("network-transmit"));

            addChildItem(ip, "Version", QString::number(packet.ipv6.version));
            addChildItem(ip, "Traffic Class", QString("0x%1")
                .arg(packet.ipv6.traffic_class, 2, 16, QChar('0')));
            addChildItem(ip, "Flow Label", QString("0x%1")
                .arg(packet.ipv6.flow_label, 5, 16, QChar('0')));
            addChildItem(ip, "Payload Length", QString("%1 bytes")
                .arg(packet.ipv6.payload_length));
            addChildItem(ip, "Next Header", QString("%1 (%2)")
                .arg(getIPProtocolString(packet.ipv6.next_header))
                .arg(packet.ipv6.next_header));
            addChildItem(ip, "Hop Limit", QString::number(packet.ipv6.hop_limit));
            addChildItem(ip, "Source Address", src_ip);
            addChildItem(ip, "Destination Address", dst_ip);

            tree_widget_->addTopLevelItem(ip);
            ip->setExpanded(true);
            
            return ip;
        }

        QTreeWidgetItem* PacketDetailWidget::addTCPInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString flags = getTCPFlagsString(packet);
            
            QString summary = QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2, Seq: %3, Ack: %4, Len: %5")
                .arg(packet.tcp.src_port)
                .arg(packet.tcp.dst_port)
                .arg(packet.tcp.seq_number)
                .arg(packet.tcp.ack_number)
                .arg(packet.tcp.payload_length);
            
            int header_len = packet.tcp.data_offset * 4;
            auto* tcp = createItem(summary, QString(), offset, header_len);
            tcp->setIcon(0, QIcon::fromTheme("network-transmit-receive"));

            addChildItem(tcp, "Source Port", formatPort(packet.tcp.src_port));
            addChildItem(tcp, "Destination Port", formatPort(packet.tcp.dst_port));
            addChildItem(tcp, "Stream index", QString::number(packet.tcp.analysis.stream_index));
            
            addChildItem(tcp, "Sequence Number", QString("%1 (relative)")
                .arg(packet.tcp.seq_number));
            addChildItem(tcp, "Acknowledgment Number", QString("%1 (relative)")
                .arg(packet.tcp.ack_number));
            
            addChildItem(tcp, "Header Length", QString("%1 bytes (%2)")
                .arg(header_len)
                .arg(packet.tcp.data_offset));
            
            // Flags
            auto* flags_item = createItem("Flags", QString("0x%1 (%2)")
                .arg(packet.tcp.flags, 3, 16, QChar('0'))
                .arg(flags));
            
            addChildItem(flags_item, "Congestion Window Reduced", 
                       packet.tcp.flag_cwr ? "Set" : "Not set");
            addChildItem(flags_item, "ECN-Echo", 
                       packet.tcp.flag_ece ? "Set" : "Not set");
            addChildItem(flags_item, "Urgent", 
                       packet.tcp.flag_urg ? "Set" : "Not set");
            addChildItem(flags_item, "Acknowledgment", 
                       packet.tcp.flag_ack ? "Set" : "Not set");
            addChildItem(flags_item, "Push", 
                       packet.tcp.flag_psh ? "Set" : "Not set");
            addChildItem(flags_item, "Reset", 
                       packet.tcp.flag_rst ? "Set" : "Not set");
            addChildItem(flags_item, "Syn", 
                       packet.tcp.flag_syn ? "Set" : "Not set");
            addChildItem(flags_item, "Fin", 
                       packet.tcp.flag_fin ? "Set" : "Not set");
            tcp->addChild(flags_item);
            
            addChildItem(tcp, "Window", QString::number(packet.tcp.window_size));
            addChildItem(tcp, "Checksum", QString("0x%1")
                .arg(packet.tcp.checksum, 4, 16, QChar('0')));
            addChildItem(tcp, "Urgent Pointer", QString::number(packet.tcp.urgent_pointer));

            // TCP Options
            if (packet.tcp.has_options) {
                auto* options = createItem("Options", QString("(%1 bytes)")
                    .arg(header_len - 20));
                
                if (packet.tcp.opt_mss.has_value()) {
                    addChildItem(options, "Maximum Segment Size", 
                               QString("%1 bytes").arg(packet.tcp.opt_mss->value));
                }
                
                if (packet.tcp.opt_window_scale.has_value()) {
                    addChildItem(options, "Window Scale", 
                               QString::number(packet.tcp.opt_window_scale->shift_count));
                }
                
                if (packet.tcp.opt_sack.has_value()) {
                    addChildItem(options, "SACK Permitted", "Yes");
                }
                
                if (packet.tcp.opt_timestamp.has_value()) {
                    auto* ts = createItem("Timestamps");
                    addChildItem(ts, "TSval", QString::number(packet.tcp.opt_timestamp->tsval));
                    addChildItem(ts, "TSecr", QString::number(packet.tcp.opt_timestamp->tsecr));
                    options->addChild(ts);
                }
                
                tcp->addChild(options);
            }

            // TCP Analysis
            if (packet.tcp.analysis.is_retransmission ||
                packet.tcp.analysis.is_dup_ack ||
                packet.tcp.analysis.is_zero_window ||
                packet.tcp.analysis.is_out_of_order) {
                
                auto* analysis = createItem("TCP Analysis Flags");
                analysis->setForeground(0, QColor(Qt::red));
                
                if (packet.tcp.analysis.is_retransmission) {
                    auto* item = createItem("This is a TCP retransmission");
                    item->setForeground(0, QColor(Qt::red));
                    analysis->addChild(item);
                }
                
                if (packet.tcp.analysis.is_fast_retransmission) {
                    auto* item = createItem("This is a TCP fast retransmission");
                    item->setForeground(0, QColor(Qt::red));
                    analysis->addChild(item);
                }
                
                if (packet.tcp.analysis.is_dup_ack) {
                    auto* item = createItem("This is a TCP duplicate ACK");
                    item->setForeground(0, QColor(255, 140, 0));  // Orange
                    analysis->addChild(item);
                }
                
                if (packet.tcp.analysis.is_zero_window) {
                    auto* item = createItem("This is a TCP zero window");
                    item->setForeground(0, QColor(Qt::red));
                    analysis->addChild(item);
                }
                
                if (packet.tcp.analysis.is_out_of_order) {
                    auto* item = createItem("This is an out-of-order segment");
                    item->setForeground(0, QColor(255, 140, 0));
                    analysis->addChild(item);
                }
                
                if (packet.tcp.analysis.is_keep_alive) {
                    auto* item = createItem("This is a TCP keep-alive");
                    item->setForeground(0, QColor(Qt::blue));
                    analysis->addChild(item);
                }
                
                tcp->addChild(analysis);
            }

            // Payload length
            if (packet.tcp.payload_length > 0) {
                addChildItem(tcp, "TCP Segment Data", 
                           QString("%1 bytes").arg(packet.tcp.payload_length));
            }

            tree_widget_->addTopLevelItem(tcp);
            tcp->setExpanded(true);
            
            return tcp;
        }

        QTreeWidgetItem* PacketDetailWidget::addUDPInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString summary = QString("User Datagram Protocol, Src Port: %1, Dst Port: %2")
                .arg(packet.udp.src_port)
                .arg(packet.udp.dst_port);
            
            auto* udp = createItem(summary, QString(), offset, 8);
            udp->setIcon(0, QIcon::fromTheme("network-transmit-receive"));

            addChildItem(udp, "Source Port", formatPort(packet.udp.src_port));
            addChildItem(udp, "Destination Port", formatPort(packet.udp.dst_port));
            addChildItem(udp, "Length", QString("%1 bytes").arg(packet.udp.length));
            addChildItem(udp, "Checksum", QString("0x%1")
                .arg(packet.udp.checksum, 4, 16, QChar('0')));
            addChildItem(udp, "Stream index", QString::number(packet.udp.stream_index));

            tree_widget_->addTopLevelItem(udp);
            udp->setExpanded(true);
            
            return udp;
        }

        QTreeWidgetItem* PacketDetailWidget::addICMPInfo(const Common::ParsedPacket& packet, int offset)
        {
            QString type_str = getICMPTypeString(packet.icmp.type);
            
            QString summary = QString("Internet Control Message Protocol, Type: %1, Code: %2")
                .arg(type_str)
                .arg(packet.icmp.code);
            
            auto* icmp = createItem(summary, QString(), offset, 8);
            icmp->setIcon(0, QIcon::fromTheme("network-transmit-receive"));

            addChildItem(icmp, "Type", QString("%1 (%2)")
                .arg(type_str)
                .arg(packet.icmp.type));
            addChildItem(icmp, "Code", QString::number(packet.icmp.code));
            addChildItem(icmp, "Checksum", QString("0x%1")
                .arg(packet.icmp.checksum, 4, 16, QChar('0')));

            // Echo request/reply specific fields
            if (packet.icmp.type == 0 || packet.icmp.type == 8) {
                addChildItem(icmp, "Identifier", QString("0x%1 (%2)")
                    .arg(packet.icmp.identifier, 4, 16, QChar('0'))
                    .arg(packet.icmp.identifier));
                addChildItem(icmp, "Sequence Number", QString::number(packet.icmp.sequence));
            }

            if (packet.icmp.is_response_to) {
                addChildItem(icmp, "Response time", 
                           QString("%1 ms").arg(packet.icmp.response_time * 1000, 0, 'f', 3));
            }

            tree_widget_->addTopLevelItem(icmp);
            icmp->setExpanded(true);
            
            return icmp;
        }

        QTreeWidgetItem* PacketDetailWidget::addICMPv6Info(const Common::ParsedPacket& packet, int offset)
        {
            QString type_str = getICMPv6TypeString(packet.icmpv6.type);
            
            QString summary = QString("Internet Control Message Protocol v6, Type: %1, Code: %2")
                .arg(type_str)
                .arg(packet.icmpv6.code);
            
            auto* icmpv6 = createItem(summary, QString(), offset, 8);
            icmpv6->setIcon(0, QIcon::fromTheme("network-transmit-receive"));

            addChildItem(icmpv6, "Type", QString("%1 (%2)")
                .arg(type_str)
                .arg(packet.icmpv6.type));
            addChildItem(icmpv6, "Code", QString::number(packet.icmpv6.code));
            addChildItem(icmpv6, "Checksum", QString("0x%1")
                .arg(packet.icmpv6.checksum, 4, 16, QChar('0')));

            tree_widget_->addTopLevelItem(icmpv6);
            icmpv6->setExpanded(true);
            
            return icmpv6;
        }

        QTreeWidgetItem* PacketDetailWidget::addApplicationInfo(const Common::ParsedPacket& packet, int offset)
        {
            Q_UNUSED(offset);
            QString protocol_name;
            
            switch (packet.app_protocol) {
                case Common::AppProtocol::HTTP:
                    protocol_name = "Hypertext Transfer Protocol";
                    break;
                case Common::AppProtocol::HTTPS:
                    protocol_name = "Transport Layer Security";
                    break;
                case Common::AppProtocol::DNS:
                    protocol_name = "Domain Name System";
                    break;
                case Common::AppProtocol::SSH:
                    protocol_name = "Secure Shell";
                    break;
                case Common::AppProtocol::FTP:
                    protocol_name = "File Transfer Protocol";
                    break;
                case Common::AppProtocol::SMTP:
                    protocol_name = "Simple Mail Transfer Protocol";
                    break;
                case Common::AppProtocol::TELNET:
                    protocol_name = "Telnet";
                    break;
                case Common::AppProtocol::DHCP:
                    protocol_name = "Dynamic Host Configuration Protocol";
                    break;
                default:
                    protocol_name = "Application Data";
                    break;
            }

            auto* app = createItem(protocol_name);
            app->setIcon(0, QIcon::fromTheme("application-x-executable"));
            
            if (packet.payload_length > 0) {
                addChildItem(app, "Length", QString("%1 bytes").arg(packet.payload_length));
            }

            tree_widget_->addTopLevelItem(app);
            app->setExpanded(true);
            
            return app;
        }

        QTreeWidgetItem* PacketDetailWidget::addPayloadInfo(const Common::ParsedPacket& packet, int offset)
        {
            if (current_raw_data_.empty() || packet.payload_length == 0) {
                return nullptr;
            }

            QString summary = QString("Data (%1 bytes)")
                .arg(packet.payload_length);
            
            auto* payload = createItem(summary, QString(), offset, packet.payload_length);
            payload->setIcon(0, QIcon::fromTheme("text-x-generic"));

            // Show hex dump if enabled
            if (show_hex_data_ && offset + packet.payload_length <= current_raw_data_.size()) {
                const uint8_t* data = current_raw_data_.data() + offset;
                size_t show_bytes = std::min(packet.payload_length, size_t(256));
                
                QString hex_preview = formatBytesOneLine(data, show_bytes);
                if (packet.payload_length > 256) {
                    hex_preview += "...";
                }
                
                addChildItem(payload, "Data", hex_preview);
                
                // Add full hex dump as child items (16 bytes per line)
                for (size_t i = 0; i < show_bytes; i += 16) {
                    size_t line_len = std::min(size_t(16), show_bytes - i);
                    QString line = formatBytes(data + i, line_len, true);
                    addChildItem(payload, QString("0x%1").arg(offset + i, 4, 16, QChar('0')), line);
                }
            }

            tree_widget_->addTopLevelItem(payload);
            
            return payload;
        }

        // ==================== Helper Methods (Part 3/3) ====================

        QTreeWidgetItem* PacketDetailWidget::createItem(const QString& name, 
                                                       const QString& value,
                                                       int offset,
                                                       int length)
        {
            QTreeWidgetItem* item = new QTreeWidgetItem();
            item->setText(0, name);
            item->setText(1, value);
            
            // Store offset and length in item data
            item->setData(0, Qt::UserRole, offset);
            item->setData(0, Qt::UserRole + 1, length);
            
            return item;
        }

        void PacketDetailWidget::addChildItem(QTreeWidgetItem* parent,
                                             const QString& name,
                                             const QString& value,
                                             int offset,
                                             int length)
        {
            if (!parent) {
                return;
            }

            QTreeWidgetItem* item = createItem(name, value, offset, length);
            parent->addChild(item);
        }

        void PacketDetailWidget::addBitfieldItem(QTreeWidgetItem* parent,
                                                const QString& name,
                                                uint32_t value,
                                                int bit_offset,
                                                int bit_length,
                                                int byte_offset)
        {
            if (!parent) {
                return;
            }

            QString value_str = QString("0x%1 (%2)")
                .arg(value, (bit_length + 3) / 4, 16, QChar('0'))
                .arg(value);
            
            addChildItem(parent, name, value_str, byte_offset, (bit_length + 7) / 8);
        }

        void PacketDetailWidget::addHexDumpItem(QTreeWidgetItem* parent,
                                               const QString& name,
                                               const uint8_t* data,
                                               size_t length,
                                               int offset)
        {
            if (!parent || !data || length == 0) {
                return;
            }

            QString hex_str = formatBytes(data, length, true);
            addChildItem(parent, name, hex_str, offset, length);
        }

        // ==================== Formatting Methods ====================

        QString PacketDetailWidget::formatBytes(const uint8_t* data, size_t length, bool with_ascii) const
        {
            if (!data || length == 0) {
                return QString();
            }

            QString result;
            
            for (size_t i = 0; i < length; i++) {
                result += QString("%1").arg(data[i], 2, 16, QChar('0'));
                
                if (i < length - 1) {
                    result += " ";
                }
            }
            
            if (with_ascii) {
                result += "  |";
                for (size_t i = 0; i < length; i++) {
                    char c = data[i];
                    result += (c >= 32 && c <= 126) ? QChar(c) : QChar('.');
                }
                result += "|";
            }
            
            return result;
        }

        QString PacketDetailWidget::formatBytesOneLine(const uint8_t* data, size_t length) const
        {
            if (!data || length == 0) {
                return QString();
            }

            QString result;
            size_t show_len = std::min(length, size_t(32));
            
            for (size_t i = 0; i < show_len; i++) {
                result += QString("%1").arg(data[i], 2, 16, QChar('0'));
                if (i < show_len - 1) {
                    result += " ";
                }
            }
            
            if (length > show_len) {
                result += "...";
            }
            
            return result;
        }

        QString PacketDetailWidget::formatMAC(const uint8_t* mac) const
        {
            if (!mac) {
                return "00:00:00:00:00:00";
            }

            return QString("%1:%2:%3:%4:%5:%6")
                .arg(mac[0], 2, 16, QChar('0'))
                .arg(mac[1], 2, 16, QChar('0'))
                .arg(mac[2], 2, 16, QChar('0'))
                .arg(mac[3], 2, 16, QChar('0'))
                .arg(mac[4], 2, 16, QChar('0'))
                .arg(mac[5], 2, 16, QChar('0'));
        }

        QString PacketDetailWidget::formatIPv4(uint32_t ip) const
        {
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char str[INET_ADDRSTRLEN];
            
            if (inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN)) {
                return QString(str);
            }
            
            return "0.0.0.0";
        }

        QString PacketDetailWidget::formatIPv6(const uint8_t* ipv6) const
        {
            if (!ipv6) {
                return "::";
            }

            char str[INET6_ADDRSTRLEN];
            
            if (inet_ntop(AF_INET6, ipv6, str, INET6_ADDRSTRLEN)) {
                return QString(str);
            }
            
            return "::";
        }

        QString PacketDetailWidget::formatPort(uint16_t port) const
        {
            // Well-known ports
            static const QMap<uint16_t, QString> well_known_ports = {
                {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"},
                {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"},
                {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"}, {443, "HTTPS"},
                {445, "SMB"}, {3389, "RDP"}, {8080, "HTTP-ALT"}
            };

            if (well_known_ports.contains(port)) {
                return QString("%1 (%2)").arg(port).arg(well_known_ports[port]);
            }
            
            return QString::number(port);
        }

        QString PacketDetailWidget::formatProtocol(uint8_t protocol) const
        {
            return getIPProtocolString(protocol);
        }

        QString PacketDetailWidget::formatFlags(uint8_t flags, const QStringList& flag_names) const
        {
            QStringList set_flags;
            
            for (int i = 0; i < flag_names.size() && i < 8; i++) {
                if (flags & (1 << i)) {
                    set_flags.append(flag_names[i]);
                }
            }
            
            return set_flags.isEmpty() ? "None" : set_flags.join(", ");
        }

        QString PacketDetailWidget::formatTime(double seconds) const
        {
            if (seconds < 0.001) {
                return QString("%1 µs").arg(seconds * 1000000, 0, 'f', 3);
            } else if (seconds < 1.0) {
                return QString("%1 ms").arg(seconds * 1000, 0, 'f', 3);
            } else {
                return QString("%1 s").arg(seconds, 0, 'f', 6);
            }
        }

        QString PacketDetailWidget::formatSize(size_t bytes) const
        {
            if (bytes < 1024) {
                return QString("%1 bytes").arg(bytes);
            } else if (bytes < 1024 * 1024) {
                return QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 2);
            } else {
                return QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 2);
            }
        }

        // ==================== Protocol Helpers ====================

        QString PacketDetailWidget::getTCPFlagsString(const Common::ParsedPacket& packet) const
        {
            QStringList flags;
            
            if (packet.tcp.flag_fin) flags << "FIN";
            if (packet.tcp.flag_syn) flags << "SYN";
            if (packet.tcp.flag_rst) flags << "RST";
            if (packet.tcp.flag_psh) flags << "PSH";
            if (packet.tcp.flag_ack) flags << "ACK";
            if (packet.tcp.flag_urg) flags << "URG";
            if (packet.tcp.flag_ece) flags << "ECE";
            if (packet.tcp.flag_cwr) flags << "CWR";
            
            return flags.isEmpty() ? "None" : flags.join(", ");
        }

        QString PacketDetailWidget::getICMPTypeString(uint8_t type) const
        {
            static const QMap<uint8_t, QString> icmp_types = {
                {0, "Echo Reply"},
                {3, "Destination Unreachable"},
                {4, "Source Quench"},
                {5, "Redirect"},
                {8, "Echo Request"},
                {9, "Router Advertisement"},
                {10, "Router Solicitation"},
                {11, "Time Exceeded"},
                {12, "Parameter Problem"},
                {13, "Timestamp Request"},
                {14, "Timestamp Reply"},
                {15, "Information Request"},
                {16, "Information Reply"}
            };

            return icmp_types.value(type, QString("Unknown (%1)").arg(type));
        }

        QString PacketDetailWidget::getICMPv6TypeString(uint8_t type) const
        {
            static const QMap<uint8_t, QString> icmpv6_types = {
                {1, "Destination Unreachable"},
                {2, "Packet Too Big"},
                {3, "Time Exceeded"},
                {4, "Parameter Problem"},
                {128, "Echo Request"},
                {129, "Echo Reply"},
                {133, "Router Solicitation"},
                {134, "Router Advertisement"},
                {135, "Neighbor Solicitation"},
                {136, "Neighbor Advertisement"},
                {137, "Redirect Message"}
            };

            return icmpv6_types.value(type, QString("Unknown (%1)").arg(type));
        }

        QString PacketDetailWidget::getARPOpcodeString(uint16_t opcode) const
        {
            switch (opcode) {
                case 1: return "request";
                case 2: return "reply";
                default: return QString("unknown (%1)").arg(opcode);
            }
        }

        QString PacketDetailWidget::getEtherTypeString(uint16_t ether_type) const
        {
            static const QMap<uint16_t, QString> ether_types = {
                {0x0800, "IPv4"},
                {0x0806, "ARP"},
                {0x8100, "802.1Q VLAN"},
                {0x86DD, "IPv6"},
                {0x8863, "PPPoE Discovery"},
                {0x8864, "PPPoE Session"},
                {0x88CC, "LLDP"}
            };

            return ether_types.value(ether_type, QString("Unknown"));
        }

        QString PacketDetailWidget::getIPProtocolString(uint8_t protocol) const
        {
            static const QMap<uint8_t, QString> ip_protocols = {
                {1, "ICMP"},
                {2, "IGMP"},
                {6, "TCP"},
                {17, "UDP"},
                {41, "IPv6"},
                {47, "GRE"},
                {50, "ESP"},
                {51, "AH"},
                {58, "ICMPv6"},
                {89, "OSPF"},
                {132, "SCTP"}
            };

            return ip_protocols.value(protocol, QString::number(protocol));
        }

        // ==================== Navigation ====================

        void PacketDetailWidget::expandAll()
        {
            tree_widget_->expandAll();
            spdlog::debug("Expanded all items");
        }

        void PacketDetailWidget::collapseAll()
        {
            tree_widget_->collapseAll();
            spdlog::debug("Collapsed all items");
        }

        void PacketDetailWidget::expandItem(QTreeWidgetItem* item)
        {
            if (item) {
                item->setExpanded(true);
            }
        }

        void PacketDetailWidget::collapseItem(QTreeWidgetItem* item)
        {
            if (item) {
                item->setExpanded(false);
            }
        }

        void PacketDetailWidget::expandProtocol(const QString& protocol)
        {
            for (int i = 0; i < tree_widget_->topLevelItemCount(); i++) {
                QTreeWidgetItem* item = tree_widget_->topLevelItem(i);
                if (item->text(0).contains(protocol, Qt::CaseInsensitive)) {
                    item->setExpanded(true);
                }
            }
        }

        void PacketDetailWidget::collapseProtocol(const QString& protocol)
        {
            for (int i = 0; i < tree_widget_->topLevelItemCount(); i++) {
                QTreeWidgetItem* item = tree_widget_->topLevelItem(i);
                if (item->text(0).contains(protocol, Qt::CaseInsensitive)) {
                    item->setExpanded(false);
                }
            }
        }

        // ==================== Selection ====================

        QByteArray PacketDetailWidget::getSelectedBytes() const
        {
            if (!selected_item_ || current_raw_data_.empty()) {
                return QByteArray();
            }

            int offset = selected_item_->data(0, Qt::UserRole).toInt();
            int length = selected_item_->data(0, Qt::UserRole + 1).toInt();

            if (offset < 0 || length <= 0 || 
                offset + length > static_cast<int>(current_raw_data_.size())) {
                return QByteArray();
            }

            return QByteArray(reinterpret_cast<const char*>(current_raw_data_.data() + offset), 
                            length);
        }


        QString PacketDetailWidget::getSelectedField() const
        {
            if (!selected_item_) {
                return QString();
            }

            return selected_item_->text(0);
        }

        QString PacketDetailWidget::getSelectedValue() const
        {
            if (!selected_item_) {
                return QString();
            }

            return selected_item_->text(1);
        }

        int PacketDetailWidget::getSelectedOffset() const
        {
            if (!selected_item_) {
                return -1;
            }

            return selected_item_->data(0, Qt::UserRole).toInt();
        }

        int PacketDetailWidget::getSelectedLength() const
        {
            if (!selected_item_) {
                return 0;
            }

            return selected_item_->data(0, Qt::UserRole + 1).toInt();
        }

        QTreeWidgetItem* PacketDetailWidget::getSelectedItem() const
        {
            return selected_item_;
        }

        // ==================== Search ====================

        void PacketDetailWidget::findText(const QString& text, bool case_sensitive)
        {
            search_text_ = text;
            search_case_sensitive_ = case_sensitive;
            search_results_.clear();
            search_current_index_ = -1;

            if (text.isEmpty()) {
                return;
            }

            Qt::CaseSensitivity cs = case_sensitive ? Qt::CaseSensitive : Qt::CaseInsensitive;

            // Search all items
            QTreeWidgetItemIterator it(tree_widget_);
            while (*it) {
                if ((*it)->text(0).contains(text, cs) || 
                    (*it)->text(1).contains(text, cs)) {
                    search_results_.append(*it);
                }
                ++it;
            }

            if (!search_results_.isEmpty()) {
                search_current_index_ = 0;
                tree_widget_->setCurrentItem(search_results_[0]);
                tree_widget_->scrollToItem(search_results_[0]);
            }

            spdlog::info("Found {} matches for '{}'", search_results_.size(), text.toStdString());
        }

        void PacketDetailWidget::findNext()
        {
            if (search_results_.isEmpty()) {
                return;
            }

            search_current_index_ = (search_current_index_ + 1) % search_results_.size();
            tree_widget_->setCurrentItem(search_results_[search_current_index_]);
            tree_widget_->scrollToItem(search_results_[search_current_index_]);
        }

        void PacketDetailWidget::findPrevious()
        {
            if (search_results_.isEmpty()) {
                return;
            }

            search_current_index_--;
            if (search_current_index_ < 0) {
                search_current_index_ = search_results_.size() - 1;
            }
            
            tree_widget_->setCurrentItem(search_results_[search_current_index_]);
            tree_widget_->scrollToItem(search_results_[search_current_index_]);
        }

        // ==================== Settings ====================

        void PacketDetailWidget::setShowHexData(bool show)
        {
            show_hex_data_ = show;
            refresh();
        }

        bool PacketDetailWidget::isShowHexData() const
        {
            return show_hex_data_;
        }

        void PacketDetailWidget::setAutoExpand(bool expand)
        {
            auto_expand_ = expand;
        }

        bool PacketDetailWidget::isAutoExpand() const
        {
            return auto_expand_;
        }

        // ==================== Context Menu Actions ====================

        void PacketDetailWidget::onExpandAll()
        {
            expandAll();
        }

        void PacketDetailWidget::onCollapseAll()
        {
            collapseAll();
        }

        void PacketDetailWidget::onExpandSubtree()
        {
            if (selected_item_) {
                selected_item_->setExpanded(true);
                
                // Expand all children recursively
                QTreeWidgetItemIterator it(selected_item_);
                while (*it) {
                    (*it)->setExpanded(true);
                    ++it;
                }
            }
        }

        void PacketDetailWidget::onCollapseSubtree()
        {
            if (selected_item_) {
                // Collapse all children recursively
                QTreeWidgetItemIterator it(selected_item_);
                while (*it) {
                    (*it)->setExpanded(false);
                    ++it;
                }
                
                selected_item_->setExpanded(false);
            }
        }

        void PacketDetailWidget::onApplyAsFilter()
        {
            if (!selected_item_) {
                return;
            }

            QString field = getSelectedField();
            QString value = getSelectedValue();
            
            // Create filter expression
            QString filter = QString("%1 == %2").arg(field).arg(value);
            
            emit filterRequested(filter);
            
            spdlog::info("Apply filter: {}", filter.toStdString());
        }

        void PacketDetailWidget::onPrepareFilter()
        {
            if (!selected_item_) {
                return;
            }

            QString field = getSelectedField();
            QString value = getSelectedValue();
            
            // Create NOT filter expression
            QString filter = QString("%1 != %2").arg(field).arg(value);
            
            emit filterRequested(filter);
            
            spdlog::info("Prepare filter: {}", filter.toStdString());
        }

        void PacketDetailWidget::onApplyAsColumn()
        {
            // TODO: Implement apply as column
            spdlog::info("Apply as column not yet implemented");
        }

        void PacketDetailWidget::onCopyField()
        {
            QString field = getSelectedField();
            if (!field.isEmpty()) {
                QApplication::clipboard()->setText(field);
                spdlog::debug("Copied field: {}", field.toStdString());
            }
        }

        void PacketDetailWidget::onCopyValue()
        {
            QString value = getSelectedValue();
            if (!value.isEmpty()) {
                QApplication::clipboard()->setText(value);
                spdlog::debug("Copied value: {}", value.toStdString());
            }
        }

        void PacketDetailWidget::onCopyBoth()
        {
            QString field = getSelectedField();
            QString value = getSelectedValue();
            
            if (!field.isEmpty() || !value.isEmpty()) {
                QString text = QString("%1: %2").arg(field).arg(value);
                QApplication::clipboard()->setText(text);
                spdlog::debug("Copied: {}", text.toStdString());
            }
        }

        void PacketDetailWidget::onCopyBytes()
        {
            onCopyBytesHex();
        }

        void PacketDetailWidget::onCopyBytesHex()
        {
            QByteArray bytes = getSelectedBytes();
            if (!bytes.isEmpty()) {
                QString hex = formatBytes(reinterpret_cast<const uint8_t*>(bytes.data()), 
                                        bytes.size(), false);
                QApplication::clipboard()->setText(hex);
                spdlog::debug("Copied {} bytes as hex", bytes.size());
            }
        }

        void PacketDetailWidget::onCopyBytesText()
        {
            QByteArray bytes = getSelectedBytes();
            if (!bytes.isEmpty()) {
                QString text;
                for (int i = 0; i < bytes.size(); i++) {
                    char c = bytes[i];
                    text += (c >= 32 && c <= 126) ? QChar(c) : QChar('.');
                }
                QApplication::clipboard()->setText(text);
                spdlog::debug("Copied {} bytes as text", bytes.size());
            }
        }

        void PacketDetailWidget::onExportBytes()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            QString filename = QFileDialog::getSaveFileName(this,
                tr("Export Bytes"),
                QString(),
                tr("Binary Files (*.bin);;All Files (*)"));
            
            if (filename.isEmpty()) {
                return;
            }

            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly)) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to open file for writing:\n%1").arg(filename));
                return;
            }

            file.write(bytes);
            file.close();

            spdlog::info("Exported {} bytes to {}", bytes.size(), filename.toStdString());
        }

        void PacketDetailWidget::onExportPacket()
        {
            QString filename = QFileDialog::getSaveFileName(this,
                tr("Export Packet Details"),
                QString(),
                tr("Text Files (*.txt);;All Files (*)"));
            
            if (filename.isEmpty()) {
                return;
            }

            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QMessageBox::warning(this, tr("Error"),
                    tr("Failed to open file for writing:\n%1").arg(filename));
                return;
            }

            QTextStream out(&file);
            
            // Export tree structure
            for (int i = 0; i < tree_widget_->topLevelItemCount(); i++) {
                QTreeWidgetItem* item = tree_widget_->topLevelItem(i);
                exportItemToText(out, item, 0);
            }
            
            file.close();

            spdlog::info("Exported packet details to {}", filename.toStdString());
        }

        void PacketDetailWidget::exportItemToText(QTextStream& out, QTreeWidgetItem* item, int indent) const
        {
            if (!item) {
                return;
            }

            QString indent_str = QString("  ").repeated(indent);
            out << indent_str << item->text(0);
            
            if (!item->text(1).isEmpty()) {
                out << ": " << item->text(1);
            }
            
            out << "\n";

            // Export children
            for (int i = 0; i < item->childCount(); i++) {
                exportItemToText(out, item->child(i), indent + 1);
            }
        }

        void PacketDetailWidget::onFollowStream()
        {
            // TODO: Implement follow stream
            spdlog::info("Follow stream not yet implemented");
        }

        void PacketDetailWidget::onShowInHexDump()
        {
            int offset = getSelectedOffset();
            int length = getSelectedLength();
            
            if (offset >= 0 && length > 0) {
                emit bytesSelected(offset, length);
                spdlog::debug("Show in hex dump: offset={}, length={}", offset, length);
            }
        }

        void PacketDetailWidget::contextMenuEvent(QContextMenuEvent* event)
        {
            Q_UNUSED(event);
            // Context menu is handled by customContextMenuRequested signal
        }

    } // namespace GUI
} // namespace NetworkSecurity

