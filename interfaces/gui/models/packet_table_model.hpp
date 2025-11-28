// src/gui/models/packet_table_model.hpp

#ifndef PACKET_TABLE_MODEL_HPP
#define PACKET_TABLE_MODEL_HPP

#include <QAbstractTableModel>
#include <QColor>
#include <QFont>
#include <QDateTime>
#include <vector>
#include <memory>
#include "common/packet_parser.hpp"
#include "utils/color_rules.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Packet entry with display metadata
         */
        struct PacketEntry
        {
            size_t index;                      // Packet number (0-based)
            uint64_t timestamp;                // Timestamp (microseconds since epoch)
            Common::ParsedPacket parsed;       // Parsed packet data
            std::vector<uint8_t> raw_data;     // Raw packet bytes
            
            // Display properties
            QColor background;                 // Background color
            QColor foreground;                 // Text color
            bool marked;                       // User marked flag
            bool filtered;                     // Matches current filter
            
            PacketEntry()
                : index(0)
                , timestamp(0)
                , background(Qt::white)
                , foreground(Qt::black)
                , marked(false)
                , filtered(true)
            {}
        };

        /**
         * @brief Table model for packet list (Wireshark-like)
         */
        class PacketTableModel : public QAbstractTableModel
        {
            Q_OBJECT

        public:
            // ==================== Column Definitions ====================
            enum Column {
                COL_NUMBER = 0,
                COL_TIME,
                COL_SOURCE,
                COL_DESTINATION,
                COL_PROTOCOL,
                COL_LENGTH,
                COL_INFO,
                COL_COUNT
            };

            // ==================== Time Format ====================
            enum TimeFormat {
                TIME_ABSOLUTE,      // 2024-01-15 14:30:25.123456
                TIME_RELATIVE,      // 0.123456 (since first packet)
                TIME_DELTA,         // 0.000123 (since previous packet)
                TIME_EPOCH          // 1705329025.123456
            };

            explicit PacketTableModel(QObject* parent = nullptr);
            ~PacketTableModel() override;

            // ==================== QAbstractTableModel Interface ====================
            int rowCount(const QModelIndex& parent = QModelIndex()) const override;
            int columnCount(const QModelIndex& parent = QModelIndex()) const override;
            QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
            QVariant headerData(int section, Qt::Orientation orientation, 
                              int role = Qt::DisplayRole) const override;
            Qt::ItemFlags flags(const QModelIndex& index) const override;

            // ==================== Packet Management ====================
            void addPacket(const Common::ParsedPacket& packet, 
                          const std::vector<uint8_t>& raw_data);
            void clearPackets();
            void removePacket(int row);
            void updatePacket(int row);
            
            const PacketEntry& getPacket(int row) const;
            const PacketEntry& getPacketByIndex(size_t index) const;
            int getPacketCount() const;
            int getTotalPacketCount() const;
            std::vector<PacketEntry> getAllPackets() const;

            // ==================== Filtering ====================
            void setFilter(const QString& filter);
            QString getFilter() const;
            void applyFilter();
            void clearFilter();
            bool isFiltering() const;

            // ==================== Color Rules ====================
            void setColorRules(ColorRules* rules);
            ColorRules* getColorRules() const;
            void setColoringEnabled(bool enabled);
            bool isColoringEnabled() const;
            void refreshColors();
            void applyColorRules();

            // ==================== Marking ====================
            void markPacket(int row, bool marked = true);
            void unmarkPacket(int row);
            bool isMarked(int row) const;
            void markAll();
            void unmarkAll();
            void toggleMark(int row);
            int getMarkedCount() const;

            // ==================== Display Settings ====================
            void setTimeFormat(TimeFormat format);
            TimeFormat getTimeFormat() const;
            void setColumnVisible(int column, bool visible);
            bool isColumnVisible(int column) const;
            void resetColumns();

            // ==================== Sorting ====================
            void sortByColumn(int column, Qt::SortOrder order);

            // ==================== Statistics ====================
            struct Statistics {
                int total_packets;
                int filtered_packets;
                int marked_packets;
                uint64_t first_timestamp;
                uint64_t last_timestamp;
                size_t total_bytes;
            };
            Statistics getStatistics() const;

        signals:
            void packetsChanged();
            void packetAdded(int row);
            void filterChanged();
            void coloringChanged();

        private:
            // ==================== Data Storage ====================
            std::vector<PacketEntry> packets_;          // All packets
            std::vector<size_t> filtered_indices_;      // Indices of filtered packets
            
            // ==================== Color Rules ====================
            ColorRules* color_rules_;                   // External ownership
            bool coloring_enabled_;
            
            // ==================== Display Settings ====================
            TimeFormat time_format_;
            std::vector<bool> column_visible_;
            
            // ==================== Time Tracking ====================
            uint64_t first_packet_time_;
            uint64_t last_packet_time_;
            
            // ==================== Filtering ====================
            QString current_filter_;
            bool filtering_enabled_;

            // ==================== Helper Methods ====================
            QVariant getDisplayData(const PacketEntry& entry, int column) const;
            QVariant getBackgroundColor(const PacketEntry& entry) const;
            QVariant getForegroundColor(const PacketEntry& entry) const;
            QVariant getToolTip(const PacketEntry& entry, int column) const;
            QFont getPacketFont(const PacketEntry& entry) const;
            QString formatTcpConnection(const Common::ParsedPacket& packet, 
                                                        const QString& protocol) const
            {
                if (!packet.has_tcp) {
                    return protocol;
                }

                QString src_ip, dst_ip;

                // Format source IP
                if (packet.has_ipv4) {
                    src_ip = formatIPv4(packet.ipv4.src_ip);
                    dst_ip = formatIPv4(packet.ipv4.dst_ip);
                } else if (packet.has_ipv6) {
                    src_ip = formatIPv6(packet.ipv6.src_ip);
                    dst_ip = formatIPv6(packet.ipv6.dst_ip);
                } else {
                    src_ip = "Unknown";
                    dst_ip = "Unknown";
                }

                return QString("%1 %2:%3 → %4:%5")
                    .arg(protocol)
                    .arg(src_ip)
                    .arg(packet.tcp.src_port)
                    .arg(dst_ip)
                    .arg(packet.tcp.dst_port);
            }
       
            // ==================== Formatting ====================
            QString formatTime(uint64_t timestamp) const;
            QString formatIPv4(uint32_t ip) const;
            QString formatIPv6(const uint8_t* ip) const;
            QString formatMAC(const uint8_t* mac) const;
            QString formatSource(const PacketEntry& entry) const;
            QString formatDestination(const PacketEntry& entry) const;
            QString formatProtocol(const PacketEntry& entry) const;
            QString formatLength(const PacketEntry& entry) const;
            QString formatInfo(const PacketEntry& entry) const;
            
            // ==================== Protocol Info ====================
            QString getTCPInfo(const Common::ParsedPacket& packet) const;
            QString getUDPInfo(const Common::ParsedPacket& packet) const;
            QString getICMPInfo(const Common::ParsedPacket& packet) const;
            QString getARPInfo(const Common::ParsedPacket& packet) const;
            QString getDNSInfo(const Common::ParsedPacket& packet) const;
            QString getHTTPInfo(const Common::ParsedPacket& packet) const;
            QString getSSHInfo(const Common::ParsedPacket& packet) const;
            QString getFTPInfo(const Common::ParsedPacket& packet) const;
            
            // ==================== Color Helpers ====================
            void applyColorRule(PacketEntry& entry);
            void resetColor(PacketEntry& entry);
            
            // ==================== Filter Helpers ====================
            bool matchesFilter(const PacketEntry& entry) const;
            void rebuildFilteredIndices();
            
            // ==================== Index Mapping ====================
            size_t mapRowToIndex(int row) const;
            int mapIndexToRow(size_t index) const;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_TABLE_MODEL_HPP
