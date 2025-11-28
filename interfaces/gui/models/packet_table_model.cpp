// src/gui/models/packet_table_model.cpp

#include "packet_table_model.hpp"
#include <QDateTime>
#include <QFont>
#include <QVariant>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        PacketTableModel::PacketTableModel(QObject* parent)
            : QAbstractTableModel(parent),
              time_format_(TIME_RELATIVE),
              coloring_enabled_(true),
              first_packet_time_(0),
              last_packet_time_(0)
        {
            column_visible_.resize(COL_COUNT, true);
            color_rules_ = std::make_unique<ColorRules>();
            color_rules_->loadDefaults();
        }

        PacketTableModel::~PacketTableModel()
        {
        }

        // ==================== QAbstractTableModel Interface ====================

        int PacketTableModel::rowCount(const QModelIndex& parent) const
        {
            if (parent.isValid()) {
                return 0;
            }
            return packets_.size();
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
            if (!index.isValid() || index.row() >= static_cast<int>(packets_.size())) {
                return QVariant();
            }

            const PacketEntry& entry = packets_[index.row()];

            switch (role) {
                case Qt::DisplayRole:
                    return getDisplayData(entry, index.column());

                case Qt::BackgroundRole:
                    if (coloring_enabled_) {
                        return entry.color;
                    }
                    break;

                case Qt::ForegroundRole:
                    if (entry.marked) {
                        return QColor(Qt::black);
                    }
                    break;

                case Qt::FontRole:
                    return getPacketFont(entry);

                case Qt::TextAlignmentRole:
                    // ✅ FIX: Convert QFlags to QVariant
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
                case COL_NUMBER:
                    return tr("No.");
                case COL_TIME:
                    return tr("Time");
                case COL_SOURCE:
                    return tr("Source");
                case COL_DESTINATION:
                    return tr("Destination");
                case COL_PROTOCOL:
                    return tr("Protocol");
                case COL_LENGTH:
                    return tr("Length");
                case COL_INFO:
                    return tr("Info");
                default:
                    return QVariant();
            }
        }

        Qt::ItemFlags PacketTableModel::flags(const QModelIndex& index) const
        {
            if (!index.isValid()) {
                return Qt::NoItemFlags;
            }
            return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
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
                    return formatLength(entry);
                case COL_INFO:
                    return formatInfo(entry);
                default:
                    return QVariant();
            }
        }

        QVariant PacketTableModel::getToolTip(const PacketEntry& entry, int column) const
        {
            Q_UNUSED(column);
            return formatInfo(entry);
        }

        QFont PacketTableModel::getPacketFont(const PacketEntry& entry) const
        {
            QFont font;
            if (entry.marked) {
                font.setBold(true);
            }
            return font;
        }

        // ==================== Formatting Helpers ====================

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
                    double seconds = (timestamp - first_packet_time_) / 1000000.0;
                    return QString::number(seconds, 'f', 6);
                }

                case TIME_DELTA: {
                    if (last_packet_time_ == 0) {
                        return "0.000000";
                    }
                    double seconds = (timestamp - last_packet_time_) / 1000000.0;
                    return QString::number(seconds, 'f', 6);
                }

                case TIME_EPOCH:
                    return QString::number(timestamp / 1000000.0, 'f', 6);

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

            // Try IP first
            if (packet.has_ipv4) {
                return formatIPv4(packet.ipv4.src_ip);
            }
            if (packet.has_ipv6) {
                return formatIPv6(packet.ipv6.src_ip);
            }

            // Fallback to MAC
            if (packet.has_ethernet) {
                return formatMAC(packet.ethernet.src_mac);
            }

            return tr("Unknown");
        }

        QString PacketTableModel::formatDestination(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            // Try IP first
            if (packet.has_ipv4) {
                return formatIPv4(packet.ipv4.dst_ip);
            }
            if (packet.has_ipv6) {
                return formatIPv6(packet.ipv6.dst_ip);
            }

            // Fallback to MAC
            if (packet.has_ethernet) {
                return formatMAC(packet.ethernet.dst_mac);
            }

            return tr("Unknown");
        }

        QString PacketTableModel::formatProtocol(const PacketEntry& entry) const
        {
            const auto& packet = entry.parsed;

            // Application layer
            switch (packet.app_protocol) {
                case Common::AppProtocol::HTTP:
                    return "HTTP";
                case Common::AppProtocol::HTTPS:
                    return "HTTPS";
                case Common::AppProtocol::DNS:
                    return "DNS";
                case Common::AppProtocol::SSH:
                    return "SSH";
                case Common::AppProtocol::FTP:
                    return "FTP";
                case Common::AppProtocol::SMTP:
                    return "SMTP";
                case Common::AppProtocol::TELNET:
                    return "TELNET";
                default:
                    break;
            }

            // Transport layer
            if (packet.has_tcp) {
                return "TCP";
            }
            if (packet.has_udp) {
                return "UDP";
            }
            if (packet.has_icmp) {
                return "ICMP";
            }

            // Network layer
            if (packet.has_ipv4) {
                return "IPv4";
            }
            if (packet.has_ipv6) {
                return "IPv6";
            }
            if (packet.has_arp) {
                return "ARP";
            }

            // Link layer
            if (packet.has_ethernet) {
                return "Ethernet";
            }

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

            // Default
            if (packet.has_ipv4) {
                return QString("IPv4: %1 → %2")
                    .arg(formatIPv4(packet.ipv4.src_ip))
                    .arg(formatIPv4(packet.ipv4.dst_ip));
            }

            return tr("Unknown protocol");
        }

        // ==================== Protocol Info Helpers ====================

        QString PacketTableModel::getTCPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_tcp) {
                return QString();
            }

            QStringList flags;
            if (packet.tcp.flag_syn) flags << "SYN";
            if (packet.tcp.flag_ack) flags << "ACK";
            if (packet.tcp.flag_fin) flags << "FIN";
            if (packet.tcp.flag_rst) flags << "RST";
            if (packet.tcp.flag_psh) flags << "PSH";
            if (packet.tcp.flag_urg) flags << "URG";

            QString info = QString("%1 → %2 [%3]")
                .arg(packet.tcp.src_port)
                .arg(packet.tcp.dst_port)
                .arg(flags.join(","));

            if (packet.tcp.analysis.is_retransmission) {
                info += " [TCP Retransmission]";
            }

            return info;
        }

        QString PacketTableModel::getUDPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_udp) {
                return QString();
            }

            return QString("UDP: %1 → %2 Len=%3")
                .arg(packet.udp.src_port)
                .arg(packet.udp.dst_port)
                .arg(packet.udp.length);
        }

        QString PacketTableModel::getICMPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_icmp) {
                return QString();
            }

            QString type_name;
            switch (packet.icmp.type) {
                case 0: type_name = "Echo Reply"; break;
                case 3: type_name = "Destination Unreachable"; break;
                case 8: type_name = "Echo Request"; break;
                case 11: type_name = "Time Exceeded"; break;
                default: type_name = QString("Type %1").arg(packet.icmp.type); break;
            }

            return QString("ICMP: %1 (Code %2)")
                .arg(type_name)
                .arg(packet.icmp.code);
        }

        QString PacketTableModel::getARPInfo(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_arp) {
                return QString();
            }

            QString op = (packet.arp.opcode == 1) ? "Request" : "Reply";
            
            return QString("ARP %1: Who has %2? Tell %3")
                .arg(op)
                .arg(formatIPv4(packet.arp.target_ip))
                .arg(formatIPv4(packet.arp.sender_ip));
        }

        QString PacketTableModel::getDNSInfo(const Common::ParsedPacket& packet) const
        {
            // TODO: Implement DNS parsing
            return "DNS Query/Response";
        }

        QString PacketTableModel::getHTTPInfo(const Common::ParsedPacket& packet) const
        {
            // TODO: Implement HTTP parsing
            return "HTTP Request/Response";
        }

        // ==================== Packet Management ====================

        void PacketTableModel::addPacket(const Common::ParsedPacket& packet,
                                        const std::vector<uint8_t>& raw_data)
        {
            PacketEntry entry;
            entry.parsed = packet;
            entry.raw_data = raw_data;
            entry.timestamp = packet.timestamp;
            entry.index = packets_.size();
            entry.marked = false;
            entry.filtered = false;

            if (packets_.empty()) {
                first_packet_time_ = packet.timestamp;
            }
            last_packet_time_ = packet.timestamp;

            if (coloring_enabled_) {
                QColor fg, bg;
                if (color_rules_->matchPacket(packet, fg, bg)) {
                    entry.color = bg;
                }
            }

            beginInsertRows(QModelIndex(), packets_.size(), packets_.size());
            packets_.push_back(entry);
            endInsertRows();
        }

        void PacketTableModel::clearPackets()
        {
            beginResetModel();
            packets_.clear();
            filtered_indices_.clear();
            first_packet_time_ = 0;
            last_packet_time_ = 0;
            endResetModel();
        }

        // ... (rest of methods remain the same)

        // ==================== Sorting (FIX protocol_summary) ====================

        void PacketTableModel::sortByColumn(int column, Qt::SortOrder order)
        {
            beginResetModel();

            std::sort(packets_.begin(), packets_.end(),
                [column, order](const PacketEntry& a, const PacketEntry& b) {
                    bool less = false;

                    switch (column) {
                        case COL_NUMBER:
                            less = a.index < b.index;
                            break;
                        case COL_TIME:
                            less = a.timestamp < b.timestamp;
                            break;
                        case COL_LENGTH:
                            less = a.parsed.packet_size < b.parsed.packet_size;
                            break;
                        case COL_PROTOCOL:
                            // ✅ FIX: Use app_protocol enum instead
                            less = static_cast<int>(a.parsed.app_protocol) < 
                                   static_cast<int>(b.parsed.app_protocol);
                            break;
                        default:
                            less = a.index < b.index;
                            break;
                    }

                    return (order == Qt::AscendingOrder) ? less : !less;
                });

            endResetModel();
        }

    } // namespace GUI
} // namespace NetworkSecurity
