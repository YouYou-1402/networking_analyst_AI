// src/gui/widgets/packet_detail_widget.cpp

#include "packet_detail_widget.hpp"
#include <string.h>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QApplication>
#include <QClipboard>
#include <QContextMenuEvent>
#include <arpa/inet.h>
#include <QHostAddress>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        PacketDetailWidget::PacketDetailWidget(QWidget* parent)
            : QWidget(parent),
              current_packet_(nullptr),
              current_raw_data_(nullptr),
              selected_item_(nullptr)
        {
            setupUI();
            setupContextMenu();
        }

        PacketDetailWidget::~PacketDetailWidget()
        {
        }

        void PacketDetailWidget::setupUI()
        {
            QVBoxLayout* layout = new QVBoxLayout(this);
            layout->setContentsMargins(0, 0, 0, 0);

            // Create tree widget
            tree_widget_ = new QTreeWidget(this);
            tree_widget_->setHeaderLabels(QStringList() << tr("Field") << tr("Value"));
            tree_widget_->setAlternatingRowColors(true);
            tree_widget_->setContextMenuPolicy(Qt::CustomContextMenu);
            tree_widget_->header()->setStretchLastSection(true);
            tree_widget_->setColumnWidth(0, 300);

            layout->addWidget(tree_widget_);

            // Connect signals
            connect(tree_widget_, &QTreeWidget::itemClicked,
                    this, &PacketDetailWidget::onItemClicked);
            connect(tree_widget_, &QTreeWidget::itemExpanded,
                    this, &PacketDetailWidget::onItemExpanded);
            connect(tree_widget_, &QTreeWidget::itemCollapsed,
                    this, &PacketDetailWidget::onItemCollapsed);
            connect(tree_widget_, &QTreeWidget::customContextMenuRequested,
                    this, &PacketDetailWidget::onItemContextMenu);
        }

        void PacketDetailWidget::setupContextMenu()
        {
            context_menu_ = new QMenu(this);

            action_expand_all_ = context_menu_->addAction(tr("Expand All"));
            connect(action_expand_all_, &QAction::triggered, this, &PacketDetailWidget::expandAll);

            action_collapse_all_ = context_menu_->addAction(tr("Collapse All"));
            connect(action_collapse_all_, &QAction::triggered, this, &PacketDetailWidget::collapseAll);

            context_menu_->addSeparator();

            action_apply_filter_ = context_menu_->addAction(tr("Apply as Filter"));
            connect(action_apply_filter_, &QAction::triggered, this, &PacketDetailWidget::onApplyAsFilter);

            action_prepare_filter_ = context_menu_->addAction(tr("Prepare Filter"));
            connect(action_prepare_filter_, &QAction::triggered, this, &PacketDetailWidget::onPrepareFilter);

            context_menu_->addSeparator();

            action_copy_field_ = context_menu_->addAction(tr("Copy Field Name"));
            connect(action_copy_field_, &QAction::triggered, this, &PacketDetailWidget::onCopyField);

            action_copy_value_ = context_menu_->addAction(tr("Copy Value"));
            connect(action_copy_value_, &QAction::triggered, this, &PacketDetailWidget::onCopyValue);

            action_copy_bytes_ = context_menu_->addAction(tr("Copy Bytes"));
            connect(action_copy_bytes_, &QAction::triggered, this, &PacketDetailWidget::onCopyBytes);

            context_menu_->addSeparator();

            action_export_bytes_ = context_menu_->addAction(tr("Export Bytes..."));
            connect(action_export_bytes_, &QAction::triggered, this, &PacketDetailWidget::onExportBytes);
        }

        // ==================== Display ====================

        void PacketDetailWidget::displayPacket(const Common::ParsedPacket& packet,
                                              const std::vector<uint8_t>& raw_data)
        {
            tree_widget_->clear();
            current_packet_ = &packet;
            current_raw_data_ = &raw_data;

            buildPacketTree(packet, raw_data);
        }

        void PacketDetailWidget::clearDisplay()
        {
            tree_widget_->clear();
            current_packet_ = nullptr;
            current_raw_data_ = nullptr;
            selected_item_ = nullptr;
        }

        void PacketDetailWidget::buildPacketTree(const Common::ParsedPacket& packet,
                                                const std::vector<uint8_t>& raw_data)
        {
            // Frame information
            addFrameInfo(packet);

            // Ethernet
            if (packet.has_ethernet) {
                addEthernetInfo(packet);
            }

            // VLAN
            if (packet.ethernet.has_vlan) {
                addVLANInfo(packet);
            }

            // ARP
            if (packet.has_arp) {
                addARPInfo(packet);
            }

            // IPv4
            if (packet.has_ipv4) {
                addIPv4Info(packet);
            }

            // IPv6
            if (packet.has_ipv6) {
                addIPv6Info(packet);
            }

            // TCP
            if (packet.has_tcp) {
                addTCPInfo(packet);
            }

            // UDP
            if (packet.has_udp) {
                addUDPInfo(packet);
            }

            // ICMP
            if (packet.has_icmp) {
                addICMPInfo(packet);
            }

            // ICMPv6
            if (packet.has_icmpv6) {
                addICMPv6Info(packet);
            }

            // Application layer
            if (packet.app_protocol != Common::AppProtocol::UNKNOWN) {
                addApplicationInfo(packet);
            }
        }

        QTreeWidgetItem* PacketDetailWidget::addFrameInfo(const Common::ParsedPacket& packet)
        {
            auto* frame = createItem(QString("Frame %1: %2 bytes")
                .arg(packet.frame_metadata.frame_number)
                .arg(packet.frame_metadata.frame_len));

            addChildItem(frame, "Frame Number", QString::number(packet.frame_metadata.frame_number));
            addChildItem(frame, "Frame Length", QString("%1 bytes").arg(packet.frame_metadata.frame_len));
            addChildItem(frame, "Capture Length", QString("%1 bytes").arg(packet.frame_metadata.frame_cap_len));
            addChildItem(frame, "Time Relative", QString("%1 seconds").arg(packet.frame_metadata.frame_time_relative, 0, 'f', 6));
            addChildItem(frame, "Time Delta", QString("%1 seconds").arg(packet.frame_metadata.frame_time_delta, 0, 'f', 6));
            addChildItem(frame, "Protocols", QString::fromStdString(packet.frame_metadata.frame_protocols));

            tree_widget_->addTopLevelItem(frame);
            frame->setExpanded(true);
            return frame;
        }

        QTreeWidgetItem* PacketDetailWidget::addEthernetInfo(const Common::ParsedPacket& packet)
        {
            auto* eth = createItem("Ethernet II");

            addChildItem(eth, "Destination", formatMAC(packet.ethernet.dst_mac), 0, 6);
            addChildItem(eth, "Source", formatMAC(packet.ethernet.src_mac), 6, 6);
            addChildItem(eth, "Type", QString("0x%1").arg(ntohs(packet.ethernet.ether_type), 4, 16, QChar('0')), 12, 2);

            tree_widget_->addTopLevelItem(eth);
            eth->setExpanded(true);
            return eth;
        }

        QTreeWidgetItem* PacketDetailWidget::addVLANInfo(const Common::ParsedPacket& packet)
        {
            auto* vlan = createItem("802.1Q Virtual LAN");

            addChildItem(vlan, "Priority", QString::number(packet.ethernet.vlan_priority));
            addChildItem(vlan, "CFI", QString::number(packet.ethernet.vlan_cfi));
            addChildItem(vlan, "ID", QString::number(packet.ethernet.vlan_id));

            tree_widget_->addTopLevelItem(vlan);
            vlan->setExpanded(true);
            return vlan;
        }

        QTreeWidgetItem* PacketDetailWidget::addARPInfo(const Common::ParsedPacket& packet)
        {
            auto* arp = createItem("Address Resolution Protocol");

            QString opcode_str = (packet.arp.opcode == 1) ? "request" : "reply";
            addChildItem(arp, "Opcode", QString("%1 (%2)").arg(opcode_str).arg(packet.arp.opcode));
            addChildItem(arp, "Sender MAC", formatMAC(packet.arp.sender_mac));
            addChildItem(arp, "Sender IP", formatIP(packet.arp.sender_ip));
            addChildItem(arp, "Target MAC", formatMAC(packet.arp.target_mac));
            addChildItem(arp, "Target IP", formatIP(packet.arp.target_ip));

            if (packet.arp.is_gratuitous) {
                addChildItem(arp, "Gratuitous ARP", "True");
            }
            if (packet.arp.is_probe) {
                addChildItem(arp, "ARP Probe", "True");
            }

            tree_widget_->addTopLevelItem(arp);
            arp->setExpanded(true);
            return arp;
        }

        QTreeWidgetItem* PacketDetailWidget::addIPv4Info(const Common::ParsedPacket& packet)
        {
            auto* ip = createItem(QString("Internet Protocol Version 4, Src: %1, Dst: %2")
                .arg(QString::fromStdString(std::to_string(packet.ipv4.src_ip)))
                .arg(QString::fromStdString(std::to_string(packet.ipv4.dst_ip))));

            addChildItem(ip, "Version", QString::number(packet.ipv4.version));
            addChildItem(ip, "Header Length", QString("%1 bytes").arg(packet.ipv4.ihl * 4));
            addChildItem(ip, "DSCP", QString("0x%1").arg(packet.ipv4.dscp, 2, 16, QChar('0')));
            addChildItem(ip, "ECN", QString::number(packet.ipv4.ecn));
            addChildItem(ip, "Total Length", QString("%1 bytes").arg(packet.ipv4.total_length));
            addChildItem(ip, "Identification", QString("0x%1").arg(packet.ipv4.identification, 4, 16, QChar('0')));
            
            // Flags
            auto* flags = createItem("Flags", QString("0x%1").arg(packet.ipv4.flags, 2, 16, QChar('0')));
            addChildItem(flags, "Reserved", packet.ipv4.flag_reserved ? "Set" : "Not set");
            addChildItem(flags, "Don't Fragment", packet.ipv4.flag_df ? "Set" : "Not set");
            addChildItem(flags, "More Fragments", packet.ipv4.flag_mf ? "Set" : "Not set");
            ip->addChild(flags);

            addChildItem(ip, "Fragment Offset", QString::number(packet.ipv4.fragment_offset));
            addChildItem(ip, "Time to Live", QString::number(packet.ipv4.ttl));
            addChildItem(ip, "Protocol", 
                QString("%1 (%2)").arg(packet.ipv4.protocol)               // tự động chuyển uint8_t → int
                                .arg(QString::number(packet.ipv4.protocol)));
            addChildItem(ip, "Header Checksum", QString("0x%1").arg(packet.ipv4.checksum, 4, 16, QChar('0')));
            addChildItem(ip, "Source", formatIP(packet.ipv4.src_ip));
            addChildItem(ip, "Destination", formatIP(packet.ipv4.dst_ip));

            tree_widget_->addTopLevelItem(ip);
            ip->setExpanded(true);
            return ip;
        }

        QTreeWidgetItem* PacketDetailWidget::addIPv6Info(const Common::ParsedPacket& packet)
        {
            QHostAddress src(packet.ipv6.src_ip);
            QHostAddress dst(packet.ipv6.dst_ip);

            auto* ip = createItem(QStringLiteral("Internet Protocol Version 6, Src: %1, Dst: %2")
                .arg(src.toString())
                .arg(dst.toString()));

            addChildItem(ip, "Version", QString::number(packet.ipv6.version));
            addChildItem(ip, "Traffic Class", QString("0x%1").arg(packet.ipv6.traffic_class, 2, 16, QChar('0')));
            addChildItem(ip, "Flow Label", QString("0x%1").arg(packet.ipv6.flow_label, 5, 16, QChar('0')));
            addChildItem(ip, "Payload Length", QString("%1 bytes").arg(packet.ipv6.payload_length));
            addChildItem(ip, "Next Header", QString::number(packet.ipv6.next_header));
            addChildItem(ip, "Hop Limit", QString::number(packet.ipv6.hop_limit));
            addChildItem(ip, "Source", formatIPv6(packet.ipv6.src_ip));
            addChildItem(ip, "Destination", formatIPv6(packet.ipv6.dst_ip));

            tree_widget_->addTopLevelItem(ip);
            ip->setExpanded(true);
            return ip;
        }

        QTreeWidgetItem* PacketDetailWidget::addTCPInfo(const Common::ParsedPacket& packet)
        {
            auto* tcp = createItem(QString("Transmission Control Protocol, Src Port: %1, Dst Port: %2")
                .arg(packet.tcp.src_port)
                .arg(packet.tcp.dst_port));

            addChildItem(tcp, "Source Port", QString::number(packet.tcp.src_port));
            addChildItem(tcp, "Destination Port", QString::number(packet.tcp.dst_port));
            addChildItem(tcp, "Stream Index", QString::number(packet.tcp.analysis.stream_index));
            addChildItem(tcp, "Sequence Number", QString::number(packet.tcp.seq_number));
            addChildItem(tcp, "Acknowledgment Number", QString::number(packet.tcp.ack_number));
            addChildItem(tcp, "Header Length", QString("%1 bytes").arg(packet.tcp.data_offset * 4));

            // Flags
            auto* flags = createItem("Flags", QString("0x%1").arg(packet.tcp.flags, 3, 16, QChar('0')));
            addChildItem(flags, "FIN", packet.tcp.flag_fin ? "Set" : "Not set");
            addChildItem(flags, "SYN", packet.tcp.flag_syn ? "Set" : "Not set");
            addChildItem(flags, "RST", packet.tcp.flag_rst ? "Set" : "Not set");
            addChildItem(flags, "PSH", packet.tcp.flag_psh ? "Set" : "Not set");
            addChildItem(flags, "ACK", packet.tcp.flag_ack ? "Set" : "Not set");
            addChildItem(flags, "URG", packet.tcp.flag_urg ? "Set" : "Not set");
            addChildItem(flags, "ECE", packet.tcp.flag_ece ? "Set" : "Not set");
            addChildItem(flags, "CWR", packet.tcp.flag_cwr ? "Set" : "Not set");
            tcp->addChild(flags);

            addChildItem(tcp, "Window Size", QString::number(packet.tcp.window_size));
            addChildItem(tcp, "Checksum", QString("0x%1").arg(packet.tcp.checksum, 4, 16, QChar('0')));
            addChildItem(tcp, "Urgent Pointer", QString::number(packet.tcp.urgent_pointer));

            // Options
            if (packet.tcp.has_options) {
                auto* options = createItem("Options");
                
                if (packet.tcp.opt_mss.has_value()) {
                    addChildItem(options, "MSS", QString::number(packet.tcp.opt_mss->value));
                }
                if (packet.tcp.opt_window_scale.has_value()) {
                    addChildItem(options, "Window Scale", QString::number(packet.tcp.opt_window_scale->shift_count));
                }
                if (packet.tcp.opt_sack.has_value()) {
                    addChildItem(options, "SACK Permitted", "Yes");
                }
                if (packet.tcp.opt_timestamp.has_value()) {
                    addChildItem(options, "Timestamp", QString::number(packet.tcp.opt_timestamp->tsval));
                    addChildItem(options, "Timestamp Echo", QString::number(packet.tcp.opt_timestamp->tsecr));
                }
                
                tcp->addChild(options);
            }

            // TCP Analysis
            if (packet.tcp.analysis.is_retransmission ||
                packet.tcp.analysis.is_dup_ack ||
                packet.tcp.analysis.is_zero_window ||
                packet.tcp.analysis.is_out_of_order) {
                
                auto* analysis = createItem("TCP Analysis Flags");
                
                if (packet.tcp.analysis.is_retransmission) {
                    addChildItem(analysis, "Retransmission", "True");
                }
                if (packet.tcp.analysis.is_fast_retransmission) {
                    addChildItem(analysis, "Fast Retransmission", "True");
                }
                if (packet.tcp.analysis.is_dup_ack) {
                    addChildItem(analysis, "Duplicate ACK", "True");
                }
                if (packet.tcp.analysis.is_zero_window) {
                    addChildItem(analysis, "Zero Window", "True");
                }
                if (packet.tcp.analysis.is_out_of_order) {
                    addChildItem(analysis, "Out of Order", "True");
                }
                if (packet.tcp.analysis.is_keep_alive) {
                    addChildItem(analysis, "Keep Alive", "True");
                }
                
                tcp->addChild(analysis);
            }

            tree_widget_->addTopLevelItem(tcp);
            tcp->setExpanded(true);
            return tcp;
        }

        QTreeWidgetItem* PacketDetailWidget::addUDPInfo(const Common::ParsedPacket& packet)
        {
            auto* udp = createItem(QString("User Datagram Protocol, Src Port: %1, Dst Port: %2")
                .arg(packet.udp.src_port)
                .arg(packet.udp.dst_port));

            addChildItem(udp, "Source Port", QString::number(packet.udp.src_port));
            addChildItem(udp, "Destination Port", QString::number(packet.udp.dst_port));
            addChildItem(udp, "Length", QString("%1 bytes").arg(packet.udp.length));
            addChildItem(udp, "Checksum", QString("0x%1").arg(packet.udp.checksum, 4, 16, QChar('0')));
            addChildItem(udp, "Stream Index", QString::number(packet.udp.stream_index));

            tree_widget_->addTopLevelItem(udp);
            udp->setExpanded(true);
            return udp;
        }

        QTreeWidgetItem* PacketDetailWidget::addICMPInfo(const Common::ParsedPacket& packet)
        {
            auto* icmp = createItem("Internet Control Message Protocol");

            addChildItem(icmp, "Type",
                QStringLiteral("%1 (%2)")
                    .arg(packet.icmp.type)                    
                    .arg(QString::number(packet.icmp.type))
            );
            addChildItem(icmp, "Code", QString::number(packet.icmp.code));
            addChildItem(icmp, "Checksum", QString("0x%1").arg(packet.icmp.checksum, 4, 16, QChar('0')));

            if (packet.icmp.type == 8 || packet.icmp.type == 0) { // Echo request/reply
                addChildItem(icmp, "Identifier", QString::number(packet.icmp.identifier));
                addChildItem(icmp, "Sequence", QString::number(packet.icmp.sequence));
            }

            if (packet.icmp.is_response_to) {
                addChildItem(icmp, "Response Time", QString("%1 ms").arg(packet.icmp.response_time * 1000, 0, 'f', 3));
            }

            tree_widget_->addTopLevelItem(icmp);
            icmp->setExpanded(true);
            return icmp;
        }

        QTreeWidgetItem* PacketDetailWidget::addICMPv6Info(const Common::ParsedPacket& packet)
        {
            auto* icmpv6 = createItem("Internet Control Message Protocol v6");

            addChildItem(icmpv6, "Type", QString::number(packet.icmpv6.type));
            addChildItem(icmpv6, "Code", QString::number(packet.icmpv6.code));
            addChildItem(icmpv6, "Checksum", QString("0x%1").arg(packet.icmpv6.checksum, 4, 16, QChar('0')));

            tree_widget_->addTopLevelItem(icmpv6);
            icmpv6->setExpanded(true);
            return icmpv6;
        }

        QTreeWidgetItem* PacketDetailWidget::addApplicationInfo(const Common::ParsedPacket& packet)
        {
            QString protocol_name;
            switch (packet.app_protocol) {
                case Common::AppProtocol::HTTP:
                    protocol_name = "Hypertext Transfer Protocol";
                    break;
                case Common::AppProtocol::HTTPS:
                    protocol_name = "HTTP over TLS";
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
                default:
                    protocol_name = "Application Data";
                    break;
            }

            auto* app = createItem(protocol_name);
            
            if (packet.payload_length > 0) {
                addChildItem(app, "Payload Length", QString("%1 bytes").arg(packet.payload_length));
                
                // Show first 64 bytes of payload as hex
                size_t show_bytes = std::min(packet.payload_length, size_t(64));
                QString hex_data = formatBytes(packet.payload, show_bytes);
                addChildItem(app, "Data", hex_data);
            }

            tree_widget_->addTopLevelItem(app);
            app->setExpanded(true);
            return app;
        }
        // ==================== Helper Methods ====================

        QTreeWidgetItem* PacketDetailWidget::createItem(const QString& name,
                                                       const QString& value,
                                                       int offset,
                                                       int length)
        {
            QTreeWidgetItem* item = new QTreeWidgetItem();
            item->setText(0, name);
            item->setText(1, value);
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
            QTreeWidgetItem* child = createItem(name, value, offset, length);
            parent->addChild(child);
        }

        QString PacketDetailWidget::formatBytes(const uint8_t* data, size_t length) const
        {
            QString result;
            for (size_t i = 0; i < length; i++) {
                result += QString("%1").arg(data[i], 2, 16, QChar('0'));
                if (i < length - 1) {
                    result += " ";
                }
                if ((i + 1) % 16 == 0 && i < length - 1) {
                    result += "\n";
                }
            }
            return result;
        }

        QString PacketDetailWidget::formatMAC(const uint8_t* mac) const
        {
            return QString("%1:%2:%3:%4:%5:%6")
                .arg(mac[0], 2, 16, QChar('0'))
                .arg(mac[1], 2, 16, QChar('0'))
                .arg(mac[2], 2, 16, QChar('0'))
                .arg(mac[3], 2, 16, QChar('0'))
                .arg(mac[4], 2, 16, QChar('0'))
                .arg(mac[5], 2, 16, QChar('0'));
        }

        QString PacketDetailWidget::formatIP(uint32_t ip) const
        {
            struct in_addr addr;
            addr.s_addr = ip;
            return QString(inet_ntoa(addr));
        }

        QString PacketDetailWidget::formatIPv6(const uint8_t* ipv6) const
        {
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ipv6, str, INET6_ADDRSTRLEN);
            return QString(str);
        }

        QString PacketDetailWidget::formatFlags(uint8_t flags, const char** flag_names) const
        {
            QString result;
            for (int i = 0; i < 8; i++) {
                if (flags & (1 << i)) {
                    if (!result.isEmpty()) {
                        result += ", ";
                    }
                    result += flag_names[i];
                }
            }
            return result.isEmpty() ? "None" : result;
        }

        // ==================== Navigation ====================

        void PacketDetailWidget::expandAll()
        {
            tree_widget_->expandAll();
        }

        void PacketDetailWidget::collapseAll()
        {
            tree_widget_->collapseAll();
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

        // ==================== Selection ====================

        QByteArray PacketDetailWidget::getSelectedBytes() const
        {
            if (!selected_item_ || !current_raw_data_) {
                return QByteArray();
            }

            int offset = selected_item_->data(0, Qt::UserRole).toInt();
            int length = selected_item_->data(0, Qt::UserRole + 1).toInt();

            if (offset >= 0 && length > 0 && 
                offset + length <= static_cast<int>(current_raw_data_->size())) {
                return QByteArray(reinterpret_cast<const char*>(current_raw_data_->data() + offset), length);
            }

            return QByteArray();
        }

        QString PacketDetailWidget::getSelectedField() const
        {
            if (!selected_item_) {
                return QString();
            }
            return selected_item_->text(0);
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

        // ==================== Event Handlers ====================

        void PacketDetailWidget::contextMenuEvent(QContextMenuEvent* event)
        {
            if (tree_widget_->currentItem()) {
                context_menu_->exec(event->globalPos());
            }
        }

        // ==================== Slots ====================

        void PacketDetailWidget::onItemClicked(QTreeWidgetItem* item, int column)
        {
            Q_UNUSED(column);
            
            selected_item_ = item;

            // Emit bytes selected signal
            int offset = item->data(0, Qt::UserRole).toInt();
            int length = item->data(0, Qt::UserRole + 1).toInt();

            if (offset >= 0 && length > 0) {
                emit bytesSelected(offset, length);
            }

            // Emit field selected signal
            emit fieldSelected(item->text(0));
        }

        void PacketDetailWidget::onItemExpanded(QTreeWidgetItem* item)
        {
            Q_UNUSED(item);
            // Could implement lazy loading here
        }

        void PacketDetailWidget::onItemCollapsed(QTreeWidgetItem* item)
        {
            Q_UNUSED(item);
        }

        void PacketDetailWidget::onItemContextMenu(const QPoint& pos)
        {
            QTreeWidgetItem* item = tree_widget_->itemAt(pos);
            if (item) {
                selected_item_ = item;
                context_menu_->exec(tree_widget_->viewport()->mapToGlobal(pos));
            }
        }

        void PacketDetailWidget::onApplyAsFilter()
        {
            if (!selected_item_) {
                return;
            }

            QString field = selected_item_->text(0);
            QString value = selected_item_->text(1);

            // Build filter string based on field
            QString filter;
            // TODO: Map field names to filter syntax
            // For now, just emit the field name
            emit filterRequested(field + " == " + value);
        }

        void PacketDetailWidget::onPrepareFilter()
        {
            if (!selected_item_) {
                return;
            }

            QString field = selected_item_->text(0);
            QString value = selected_item_->text(1);

            // Build negated filter
            emit filterRequested("!(" + field + " == " + value + ")");
        }

        void PacketDetailWidget::onCopyField()
        {
            if (!selected_item_) {
                return;
            }

            QString field = selected_item_->text(0);
            QApplication::clipboard()->setText(field);
            spdlog::debug("Copied field name: {}", field.toStdString());
        }

        void PacketDetailWidget::onCopyValue()
        {
            if (!selected_item_) {
                return;
            }

            QString value = selected_item_->text(1);
            QApplication::clipboard()->setText(value);
            spdlog::debug("Copied value: {}", value.toStdString());
        }

        void PacketDetailWidget::onCopyBytes()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            QString hex = bytes.toHex(' ');
            QApplication::clipboard()->setText(hex);
            spdlog::debug("Copied {} bytes", bytes.size());
        }

        void PacketDetailWidget::onExportBytes()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            // TODO: Implement export dialog
            spdlog::info("Export bytes requested ({} bytes)", bytes.size());
        }

    } // namespace GUI
} // namespace NetworkSecurity

