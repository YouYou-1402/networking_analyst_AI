// src/gui/models/packet_table_model.cpp

#include "packet_table_model.hpp"
#include <QDateTime>
#include <QFont>
#include <QBrush>
#include <arpa/inet.h>
#include <algorithm>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        // ==================== Constructor & Destructor ====================

        PacketTableModel::PacketTableModel(QObject* parent)
            : QAbstractTableModel(parent)
            , color_rules_(nullptr)
            , coloring_enabled_(true)
            , time_format_(TIME_RELATIVE)
            , first_packet_time_(0)
            , last_packet_time_(0)
            , filtering_enabled_(false)
        {
            column_visible_.resize(COL_COUNT, true);
            
            spdlog::info("PacketTableModel initialized");
        }

        PacketTableModel::~PacketTableModel()
        {
            // Don't delete color_rules_ (external ownership)
            spdlog::info("PacketTableModel destroyed with {} packets", packets_.size());
        }

        // ==================== QAbstractTableModel Interface ====================

        int PacketTableModel::rowCount(const QModelIndex& parent) const
        {
            if (parent.isValid()) {
                return 0;
            }
            
            return filtering_enabled_ ? filtered_indices_.size() : packets_.size();
        }

        int PacketTableModel::columnCount(const QModelIndex& parent) const
        {
            if (parent.isValid()) {
                return 0;
            }
            return COL_COUNT;
        }

        QVariant PacketTableModel::data(const QModelIndex& index, int role) const
        {
            if (!index.isValid() || index.row() >= rowCount()) {
                return QVariant();
            }

            size_t packet_index = mapRowToIndex(index.row());
            if (packet_index >= packets_.size()) {
                return QVariant();
            }

            const PacketEntry& entry = packets_[packet_index];

            switch (role) {
                case Qt::DisplayRole:
                    return getDisplayData(entry, index.column());

                case Qt::BackgroundRole:
                    return getBackgroundColor(entry);

                case Qt::ForegroundRole:
                    return getForegroundColor(entry);

                case Qt::FontRole:
                    return getPacketFont(entry);

                case Qt::TextAlignmentRole:
                    switch (index.column()) {
                        case COL_NUMBER:
                        case COL_LENGTH:
                            return QVariant(Qt::AlignRight | Qt::AlignVCenter);
                        default:
                            return QVariant(Qt::AlignLeft | Qt::AlignVCenter);
                    }

                case Qt::ToolTipRole:
                    return getToolTip(entry, index.column());

                default:
                    break;
            }

            return QVariant();
        }

        QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
        {
            if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
                return QVariant();
            }

            switch (section) {
                case COL_NUMBER:      return tr("No.");
                case COL_TIME:        return tr("Time");
                case COL_SOURCE:      return tr("Source");
                case COL_DESTINATION: return tr("Destination");
                case COL_PROTOCOL:    return tr("Protocol");
                case COL_LENGTH:      return tr("Length");
                case COL_INFO:        return tr("Info");
                default:              return QVariant();
            }
        }

        Qt::ItemFlags PacketTableModel::flags(const QModelIndex& index) const
        {
            if (!index.isValid()) {
                return Qt::NoItemFlags;
            }
            return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
        }

        // ==================== Packet Management ====================

        void PacketTableModel::addPacket(const Common::ParsedPacket& packet, 
                                        const std::vector<uint8_t>& raw_data)
        {
            PacketEntry entry;
            entry.index = packets_.size();
            entry.timestamp = packet.timestamp;
            entry.parsed = packet;
            entry.raw_data = raw_data;
            entry.marked = false;
            entry.filtered = true;

            // Track time
            if (packets_.empty()) {
                first_packet_time_ = packet.timestamp;
            }
            last_packet_time_ = packet.timestamp;

            // Apply color rules
            if (coloring_enabled_ && color_rules_) {
                applyColorRule(entry);
            } else {
                resetColor(entry);
            }

            // Check filter
            if (filtering_enabled_) {
                entry.filtered = matchesFilter(entry);
            }

            // Add to model
            int new_row = rowCount();
            
            beginInsertRows(QModelIndex(), new_row, new_row);
            packets_.push_back(entry);
            
            if (filtering_enabled_ && entry.filtered) {
                filtered_indices_.push_back(entry.index);
            }
            endInsertRows();

            emit packetAdded(new_row);
            emit packetsChanged();
        }

        void PacketTableModel::clearPackets()
        {
            beginResetModel();
            
            packets_.clear();
            filtered_indices_.clear();
            first_packet_time_ = 0;
            last_packet_time_ = 0;
            
            endResetModel();
            
            emit packetsChanged();
            
            spdlog::info("All packets cleared");
        }

        void PacketTableModel::removePacket(int row)
        {
            if (row < 0 || row >= rowCount()) {
                return;
            }

            size_t packet_index = mapRowToIndex(row);
            
            beginRemoveRows(QModelIndex(), row, row);
            
            packets_.erase(packets_.begin() + packet_index);
            
            if (filtering_enabled_) {
                rebuildFilteredIndices();
            }
            
            endRemoveRows();
            
            emit packetsChanged();
        }

        void PacketTableModel::updatePacket(int row)
        {
            if (row < 0 || row >= rowCount()) {
                return;
            }

            size_t packet_index = mapRowToIndex(row);
            PacketEntry& entry = packets_[packet_index];

            // Reapply color
            if (coloring_enabled_ && color_rules_) {
                applyColorRule(entry);
            }

            QModelIndex topLeft = index(row, 0);
            QModelIndex bottomRight = index(row, COL_COUNT - 1);
            emit dataChanged(topLeft, bottomRight);
        }

        const PacketEntry& PacketTableModel::getPacket(int row) const
        {
            static PacketEntry empty;
            
            if (row < 0 || row >= rowCount()) {
                return empty;
            }

            size_t packet_index = mapRowToIndex(row);
            if (packet_index >= packets_.size()) {
                return empty;
            }

            return packets_[packet_index];
        }

        const PacketEntry& PacketTableModel::getPacketByIndex(size_t index) const
        {
            static PacketEntry empty;
            
            if (index >= packets_.size()) {
                return empty;
            }
            
            return packets_[index];
        }

        int PacketTableModel::getPacketCount() const
        {
            return rowCount();
        }

        int PacketTableModel::getTotalPacketCount() const
        {
            return packets_.size();
        }

        std::vector<PacketEntry> PacketTableModel::getAllPackets() const
        {
            return packets_;
        }

        // ==================== Filtering ====================

        void PacketTableModel::setFilter(const QString& filter)
        {
            current_filter_ = filter.trimmed();
            filtering_enabled_ = !current_filter_.isEmpty();
            
            spdlog::info("Filter set: '{}'", current_filter_.toStdString());
        }

        QString PacketTableModel::getFilter() const
        {
            return current_filter_;
        }

        void PacketTableModel::applyFilter()
        {
            if (!filtering_enabled_) {
                clearFilter();
                return;
            }

            beginResetModel();
            
            filtered_indices_.clear();
            
            for (size_t i = 0; i < packets_.size(); i++) {
                packets_[i].filtered = matchesFilter(packets_[i]);
                
                if (packets_[i].filtered) {
                    filtered_indices_.push_back(i);
                }
            }
            
            endResetModel();
            
            emit filterChanged();
            
            spdlog::info("Filter applied: {}/{} packets match", 
                        filtered_indices_.size(), packets_.size());
        }

        void PacketTableModel::clearFilter()
        {
            beginResetModel();
            
            current_filter_.clear();
            filtering_enabled_ = false;
            filtered_indices_.clear();
            
            for (auto& entry : packets_) {
                entry.filtered = true;
            }
            
            endResetModel();
            
            emit filterChanged();
            
            spdlog::info("Filter cleared");
        }

        bool PacketTableModel::isFiltering() const
        {
            return filtering_enabled_;
        }

        // ==================== Color Rules ====================

        void PacketTableModel::setColorRules(ColorRules* rules)
        {
            color_rules_ = rules;
            
            if (coloring_enabled_ && !packets_.empty()) {
                refreshColors();
            }
            
            spdlog::info("Color rules set: {} rules", 
                        rules ? rules->getRuleCount() : 0);
        }

        ColorRules* PacketTableModel::getColorRules() const
        {
            return color_rules_;
        }

        void PacketTableModel::setColoringEnabled(bool enabled)
        {
            if (coloring_enabled_ == enabled) {
                return;
            }

            coloring_enabled_ = enabled;
            
            if (enabled) {
                refreshColors();
            } else {
                // Reset all colors to default
                for (auto& entry : packets_) {
                    resetColor(entry);
                }
                
                if (!packets_.empty()) {
                    emit dataChanged(index(0, 0), 
                                   index(rowCount() - 1, COL_COUNT - 1),
                                   {Qt::BackgroundRole, Qt::ForegroundRole});
                }
            }
            
            emit coloringChanged();
            
            spdlog::info("Packet coloring {}", enabled ? "enabled" : "disabled");
        }

        bool PacketTableModel::isColoringEnabled() const
        {
            return coloring_enabled_;
        }

        void PacketTableModel::refreshColors()
        {
            if (!coloring_enabled_ || !color_rules_) {
                return;
            }

            for (auto& entry : packets_) {
                applyColorRule(entry);
            }

            if (!packets_.empty()) {
                emit dataChanged(index(0, 0), 
                               index(rowCount() - 1, COL_COUNT - 1),
                               {Qt::BackgroundRole, Qt::ForegroundRole});
            }

            spdlog::debug("Refreshed colors for {} packets", packets_.size());
        }

        void PacketTableModel::applyColorRules()
        {
            refreshColors();
        }

        // ==================== Marking ====================

        void PacketTableModel::markPacket(int row, bool marked)
        {
            if (row < 0 || row >= rowCount()) {
                return;
            }

            size_t packet_index = mapRowToIndex(row);
            packets_[packet_index].marked = marked;

            QModelIndex topLeft = index(row, 0);
            QModelIndex bottomRight = index(row, COL_COUNT - 1);
            emit dataChanged(topLeft, bottomRight, {Qt::FontRole, Qt::BackgroundRole});

            spdlog::debug("Packet {} {}", row, marked ? "marked" : "unmarked");
        }

        void PacketTableModel::unmarkPacket(int row)
        {
            markPacket(row, false);
        }

        bool PacketTableModel::isMarked(int row) const
        {
            if (row < 0 || row >= rowCount()) {
                return false;
            }

            size_t packet_index = mapRowToIndex(row);
            return packets_[packet_index].marked;
        }

        void PacketTableModel::markAll()
        {
            for (auto& entry : packets_) {
                entry.marked = true;
            }

            if (!packets_.empty()) {
                emit dataChanged(index(0, 0), 
                               index(rowCount() - 1, COL_COUNT - 1),
                               {Qt::FontRole, Qt::BackgroundRole});
            }

            spdlog::info("All packets marked");
        }

        void PacketTableModel::unmarkAll()
        {
            for (auto& entry : packets_) {
                entry.marked = false;
            }

            if (!packets_.empty()) {
                emit dataChanged(index(0, 0), 
                               index(rowCount() - 1, COL_COUNT - 1),
                               {Qt::FontRole, Qt::BackgroundRole});
            }

            spdlog::info("All packets unmarked");
        }

        void PacketTableModel::toggleMark(int row)
        {
            if (row >= 0 && row < rowCount()) {
                markPacket(row, !isMarked(row));
            }
        }

        int PacketTableModel::getMarkedCount() const
        {
            return std::count_if(packets_.begin(), packets_.end(),
                               [](const PacketEntry& e) { return e.marked; });
        }

        // ==================== Display Settings ====================

        void PacketTableModel::setTimeFormat(TimeFormat format)
        {
            if (time_format_ == format) {
                return;
            }

            time_format_ = format;

            if (!packets_.empty()) {
                emit dataChanged(index(0, COL_TIME), 
                               index(rowCount() - 1, COL_TIME));
            }

            spdlog::info("Time format changed to {}", static_cast<int>(format));
        }

        PacketTableModel::TimeFormat PacketTableModel::getTimeFormat() const
        {
            return time_format_;
        }

        void PacketTableModel::setColumnVisible(int column, bool visible)
        {
            if (column >= 0 && column < COL_COUNT) {
                column_visible_[column] = visible;
            }
        }

        bool PacketTableModel::isColumnVisible(int column) const
        {
            if (column >= 0 && column < COL_COUNT) {
                return column_visible_[column];
            }
            return false;
        }

        void PacketTableModel::resetColumns()
        {
            std::fill(column_visible_.begin(), column_visible_.end(), true);
        }

        // ==================== Statistics ====================

        PacketTableModel::Statistics PacketTableModel::getStatistics() const
        {
            Statistics stats;
            stats.total_packets = packets_.size();
            stats.filtered_packets = filtering_enabled_ ? filtered_indices_.size() : packets_.size();
            stats.marked_packets = getMarkedCount();
            stats.first_timestamp = first_packet_time_;
            stats.last_timestamp = last_packet_time_;
            
            stats.total_bytes = 0;
            for (const auto& entry : packets_) {
                stats.total_bytes += entry.parsed.packet_size;
            }
            
            return stats;
        }

        // ==================== Helper Methods ====================

        QVariant PacketTableModel::getDisplayData(const PacketEntry& entry, int column) const
        {
            switch (column) {
                case COL_NUMBER:
                    return QString::number(entry.index + 1);
                case COL_TIME:
                    return formatTime(entry.timestamp);
                case COL_SOURCE:
                    return formatSource(entry);
                case COL_DESTINATION:
                    return formatDestination(entry);
                case COL_PROTOCOL:
                    return formatProtocol(entry);
                case COL_LENGTH:
                    return QString::number(entry.parsed.packet_size);
                case COL_INFO:
                    return formatInfo(entry);
                default:
                    return QVariant();
            }
        }

        QVariant PacketTableModel::getBackgroundColor(const PacketEntry& entry) const
        {
            if (entry.marked) {
                return QColor(255, 255, 180);  // Light yellow for marked
            }
            
            if (coloring_enabled_) {
                return entry.background;
            }
            
            return QVariant();  // Use default alternating colors
        }

        QVariant PacketTableModel::getForegroundColor(const PacketEntry& entry) const
        {
            if (coloring_enabled_) {
                return entry.foreground;
            }
            
            return QColor(Qt::black);
        }

        QVariant PacketTableModel::getToolTip(const PacketEntry& entry, int column) const
        {
            Q_UNUSED(column);
            
            QString tooltip;
            tooltip += QString("Packet #%1\n").arg(entry.index + 1);
            tooltip += QString("Time: %1\n").arg(formatTime(entry.timestamp));
            tooltip += QString("Length: %1 bytes\n").arg(entry.parsed.packet_size);
            tooltip += QString("Protocol: %1\n").arg(formatProtocol(entry));
            tooltip += QString("\n%1").arg(formatInfo(entry));
            
            return tooltip;
        }

        QFont PacketTableModel::getPacketFont(const PacketEntry& entry) const
        {
            QFont font;
            
            if (entry.marked) {
                font.setBold(true);
            }
            
            return font;
        }

        // ==================== Formatting ====================

        QString PacketTableModel::formatTime(uint64_t timestamp) const
        {
            switch (time_format_) {
                case TIME_ABSOLUTE: {
                    QDateTime dt = QDateTime::fromMSecsSinceEpoch(timestamp / 1000);
                    return dt.toString("yyyy-MM-dd hh:mm:ss.zzz");
                }

                case TIME_RELATIVE: {
                    if (first_packet_time_ == 0) {
                        return "0.000000";
                    }
                    double seconds = static_cast<double>(timestamp - first_packet_time_) / 1000000.0;
                    return QString::number(seconds, 'f', 6);
                }

                case TIME_DELTA: {
                    if (last_packet_time_ == 0 || timestamp == first_packet_time_) {
                        return "0.000000";
                    }
                    double seconds = static_cast<double>(timestamp - last_packet_time_) / 1000000.0;
                    return QString::number(seconds, 'f', 6);
                }

                case TIME_EPOCH: {
                    double seconds = static_cast<double>(timestamp) / 1000000.0;
                    return QString::number(seconds, 'f', 6);
                }

                default:
                    return QString::number(timestamp);
            }
        }

        QString PacketTableModel::formatIPv4(uint32_t ip) const
        {
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
            return QString(str);
        }

        QString PacketTableModel::formatIPv6(const uint8_t* ip) const
        {
            char str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip, str, INET6_ADDRSTRLEN);
            return QString(str);
        }

        QString PacketTableModel::formatMAC(const uint8_t* mac) const
        {
            return QString("%1:%2:%3:%4:%5:%6")
                .arg(mac[0], 2, 16, QChar('0'))
                .arg(mac[1], 2, 16, QChar('0'))
                .arg(mac[2], 2, 16, QChar('0'))
                .arg(mac[3], 2, 16, QChar('0'))
                .arg(mac[4], 2, 16, QChar('0'))
                .arg(mac[5], 2, 16, QChar('0'));
        }

        QString PacketTableModel::formatSource(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            if (packet.has_ipv4) {
                QString ip = formatIPv4(packet.ipv4.src_ip);
                if (packet.has_tcp) {
                    return QString("%1:%2").arg(ip).arg(packet.tcp.src_port);
                } else if (packet.has_udp) {
                    return QString("%1:%2").arg(ip).arg(packet.udp.src_port);
                }
                return ip;
            }

            if (packet.has_ipv6) {
                QString ip = formatIPv6(packet.ipv6.src_ip);
                if (packet.has_tcp) {
                    return QString("[%1]:%2").arg(ip).arg(packet.tcp.src_port);
                } else if (packet.has_udp) {
                    return QString("[%1]:%2").arg(ip).arg(packet.udp.src_port);
                }
                return ip;
            }

            if (packet.has_ethernet) {
                return formatMAC(packet.ethernet.src_mac);
            }

            return tr("Unknown");
        }

        QString PacketTableModel::formatDestination(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            if (packet.has_ipv4) {
                QString ip = formatIPv4(packet.ipv4.dst_ip);
                if (packet.has_tcp) {
                    return QString("%1:%2").arg(ip).arg(packet.tcp.dst_port);
                } else if (packet.has_udp) {
                    return QString("%1:%2").arg(ip).arg(packet.udp.dst_port);
                }
                return ip;
            }

            if (packet.has_ipv6) {
                QString ip = formatIPv6(packet.ipv6.dst_ip);
                if (packet.has_tcp) {
                    return QString("[%1]:%2").arg(ip).arg(packet.tcp.dst_port);
                } else if (packet.has_udp) {
                    return QString("[%1]:%2").arg(ip).arg(packet.udp.dst_port);
                }
                return ip;
            }

            if (packet.has_ethernet) {
                return formatMAC(packet.ethernet.dst_mac);
            }

            return tr("Unknown");
        }

        QString PacketTableModel::formatProtocol(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            // Application layer protocols
            switch (packet.app_protocol) {
                case Common::AppProtocol::HTTP:    return "HTTP";
                case Common::AppProtocol::HTTPS:   return "HTTPS";
                case Common::AppProtocol::DNS:     return "DNS";
                case Common::AppProtocol::SSH:     return "SSH";
                case Common::AppProtocol::FTP:     return "FTP";
                case Common::AppProtocol::SMTP:    return "SMTP";
                case Common::AppProtocol::TELNET:  return "TELNET";
                case Common::AppProtocol::DHCP:    return "DHCP";
                default: break;
            }

            // Transport layer
            if (packet.has_tcp) return "TCP";
            if (packet.has_udp) return "UDP";
            if (packet.has_icmp) return "ICMP";

            // Network layer
            if (packet.has_ipv4) return "IPv4";
            if (packet.has_ipv6) return "IPv6";
            if (packet.has_arp) return "ARP";

            // Link layer
            if (packet.has_ethernet) return "Ethernet";

            return tr("Unknown");
        }

        QString PacketTableModel::formatLength(const PacketEntry& entry) const
        {
            return QString::number(entry.parsed.packet_size);
        }

        QString PacketTableModel::formatInfo(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            // Application protocols
            if (packet.app_protocol == Common::AppProtocol::HTTP) {
                return getHTTPInfo(packet);
            }
            if (packet.app_protocol == Common::AppProtocol::DNS) {
                return getDNSInfo(packet);
            }
            if (packet.app_protocol == Common::AppProtocol::SSH) {
                return getSSHInfo(packet);
            }
            if (packet.app_protocol == Common::AppProtocol::FTP) {
                return getFTPInfo(packet);
            }

            // Transport protocols
            if (packet.has_tcp) {
                return getTCPInfo(packet);
            }
            if (packet.has_udp) {
                return getUDPInfo(packet);
            }
            if (packet.has_icmp) {
                return getICMPInfo(packet);
            }

            // Network protocols
            if (packet.has_arp) {
                return getARPInfo(packet);
            }

            return tr("No additional info");
        }

        // ==================== Protocol Info ====================

        QString PacketTableModel::getTCPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_tcp) {
                return QString();
            }

            QStringList flags;
            if (packet.tcp.flags & 0x01) flags << "FIN";
            if (packet.tcp.flags & 0x02) flags << "SYN";
            if (packet.tcp.flags & 0x04) flags << "RST";
            if (packet.tcp.flags & 0x08) flags << "PSH";
            if (packet.tcp.flags & 0x10) flags << "ACK";
            if (packet.tcp.flags & 0x20) flags << "URG";

            QString info = QString("%1 → %2 [%3]")
                .arg(packet.tcp.src_port)
                .arg(packet.tcp.dst_port)
                .arg(flags.join(", "));

            info += QString(" Seq=%1 Ack=%2 Win=%3 Len=%4")
                .arg(packet.tcp.seq_number)
                .arg(packet.tcp.ack_number)
                .arg(packet.tcp.window_size)
                .arg(packet.tcp.payload_length);

            return info;
        }

        QString PacketTableModel::getUDPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_udp) {
                return QString();
            }

            return QString("UDP %1 → %2 Len=%3")
                .arg(packet.udp.src_port)
                .arg(packet.udp.dst_port)
                .arg(packet.udp.length);
        }

        QString PacketTableModel::getICMPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_icmp) {
                return QString();
            }

            QString type_str;
            switch (packet.icmp.type) {
                case 0:  type_str = "Echo Reply"; break;
                case 3:  type_str = "Destination Unreachable"; break;
                case 8:  type_str = "Echo Request"; break;
                case 11: type_str = "Time Exceeded"; break;
                default: type_str = QString("Type %1").arg(packet.icmp.type);
            }

            return QString("ICMP %1 (Code %2)")
                .arg(type_str)
                .arg(packet.icmp.code);
        }

        QString PacketTableModel::getARPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_arp) {
                return QString();
            }

            QString op_str = (packet.arp.opcode == 1) ? "Request" : "Reply";
            
            return QString("ARP %1: Who has %2? Tell %3")
                .arg(op_str)
                .arg(formatIPv4(packet.arp.target_ip))
                .arg(formatIPv4(packet.arp.sender_ip));
        }

        QString PacketTableModel::getDNSInfo(const Common::ParsedPacket& packet) const
        {
            // Simplified DNS info
            return QString("DNS Query/Response");
        }

        QString PacketTableModel::getHTTPInfo(const Common::ParsedPacket& p) const { return formatTcpConnection(p, "HTTP"); }
        QString PacketTableModel::getSSHInfo (const Common::ParsedPacket& p) const { return formatTcpConnection(p, "SSH");  }
        QString PacketTableModel::getFTPInfo (const Common::ParsedPacket& p) const { return formatTcpConnection(p, "FTP");  }

        // ==================== Color Helpers ====================

        void PacketTableModel::applyColorRule(PacketEntry& entry)
        {
            if (!color_rules_) {
                resetColor(entry);
                return;
            }

            QColor fg, bg;
            if (color_rules_->matchPacket(entry.parsed, fg, bg)) {
                entry.foreground = fg;
                entry.background = bg;
            } else {
                resetColor(entry);
            }
        }

        void PacketTableModel::resetColor(PacketEntry& entry)
        {
            entry.background = Qt::white;
            entry.foreground = Qt::black;
        }

        // ==================== Filter Helpers ====================

        bool PacketTableModel::matchesFilter(const PacketEntry& entry) const
        {
            if (current_filter_.isEmpty()) {
                return true;
            }

            QString filter = current_filter_.toLower();

            // Protocol matching
            if (formatProtocol(entry).toLower().contains(filter)) {
                return true;
            }

            // Address matching
            if (formatSource(entry).toLower().contains(filter) ||
                formatDestination(entry).toLower().contains(filter)) {
                return true;
            }

            // Info matching
            if (formatInfo(entry).toLower().contains(filter)) {
                return true;
            }

            // Port matching
            const auto& packet = entry.parsed;
            if (packet.has_tcp) {
                if (QString::number(packet.tcp.src_port).contains(filter) ||
                    QString::number(packet.tcp.dst_port).contains(filter)) {
                    return true;
                }
            }
            if (packet.has_udp) {
                if (QString::number(packet.udp.src_port).contains(filter) ||
                    QString::number(packet.udp.dst_port).contains(filter)) {
                    return true;
                }
            }

            return false;
        }

        void PacketTableModel::rebuildFilteredIndices()
        {
            filtered_indices_.clear();
            
            for (size_t i = 0; i < packets_.size(); i++) {
                if (packets_[i].filtered) {
                    filtered_indices_.push_back(i);
                }
            }
        }

        // ==================== Index Mapping ====================

        size_t PacketTableModel::mapRowToIndex(int row) const
        {
            if (filtering_enabled_ && !filtered_indices_.empty()) {
                if (row >= 0 && row < static_cast<int>(filtered_indices_.size())) {
                    return filtered_indices_[row];
                }
            } else {
                if (row >= 0 && row < static_cast<int>(packets_.size())) {
                    return row;
                }
            }
            
            return 0;
        }

        int PacketTableModel::mapIndexToRow(size_t index) const
        {
            if (filtering_enabled_ && !filtered_indices_.empty()) {
                auto it = std::find(filtered_indices_.begin(), filtered_indices_.end(), index);
                if (it != filtered_indices_.end()) {
                    return std::distance(filtered_indices_.begin(), it);
                }
                return -1;
            }
            
            return index < packets_.size() ? static_cast<int>(index) : -1;
        }

        // ==================== Sorting ====================

        void PacketTableModel::sortByColumn(int column, Qt::SortOrder order)
        {
            // TODO: Implement sorting
            Q_UNUSED(column);
            Q_UNUSED(order);
            
            spdlog::warn("Sorting not yet implemented");
        }

    } // namespace GUI
} // namespace NetworkSecurity
