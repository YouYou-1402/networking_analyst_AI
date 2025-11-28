// src/gui/models/packet_table_model.hpp

#ifndef PACKET_TABLE_MODEL_HPP
#define PACKET_TABLE_MODEL_HPP

#include <QAbstractTableModel>
#include <QColor>
#include <QFont>
#include <vector>
#include <memory>

#include "common/packet_parser.hpp"
#include "utils/color_rules.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Table model for packet list
         */
        class PacketTableModel : public QAbstractTableModel
        {
            Q_OBJECT

        public:
            // Column definitions
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

            // Time format
            enum TimeFormat {
                TIME_ABSOLUTE,
                TIME_RELATIVE,
                TIME_DELTA,
                TIME_EPOCH
            };

            explicit PacketTableModel(QObject* parent = nullptr);
            ~PacketTableModel();

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
            void updatePacket(int index);

            const Common::ParsedPacket* getPacket(int index) const;
            const std::vector<uint8_t>* getRawData(int index) const;

            int getPacketCount() const;
            int getDisplayedCount() const;

            // ==================== Marking ====================
            void markPacket(int index, bool marked = true);
            void markAll();
            void unmarkAll();
            bool isMarked(int index) const;

            // ==================== Filtering ====================
            void setFilter(const QString& filter);
            void clearFilter();
            void applyFilter();

            // ==================== Display Settings ====================
            void setTimeFormat(TimeFormat format);
            TimeFormat getTimeFormat() const;

            void setColoringEnabled(bool enabled);
            bool isColoringEnabled() const;

            void setColumnVisible(int column, bool visible);
            bool isColumnVisible(int column) const;

            // ==================== Sorting ====================
            void sortByColumn(int column, Qt::SortOrder order);

            // ==================== Color Rules ====================
            ColorRules* getColorRules() const;
            void setColorRules(std::unique_ptr<ColorRules> rules);

        private:
            // ==================== MOVE PacketEntry to PUBLIC or add getters ====================
            struct PacketEntry {
                Common::ParsedPacket parsed;
                std::vector<uint8_t> raw_data;
                uint64_t timestamp;
                size_t index;
                bool marked;
                bool filtered;
                QColor color;
            };

            // ==================== Helper Methods (ADD DECLARATIONS) ====================
            QVariant getDisplayData(const PacketEntry& entry, int column) const;
            QVariant getToolTip(const PacketEntry& entry, int column) const;
            QFont getPacketFont(const PacketEntry& entry) const;

            // Formatting helpers
            QString formatTime(uint64_t timestamp) const;
            QString formatSource(const PacketEntry& entry) const;
            QString formatDestination(const PacketEntry& entry) const;
            QString formatProtocol(const PacketEntry& entry) const;
            QString formatLength(const PacketEntry& entry) const;
            QString formatInfo(const PacketEntry& entry) const;

            // IP formatting helpers
            QString formatIPv4(uint32_t ip) const;
            QString formatIPv6(const uint8_t* ip) const;
            QString formatMAC(const uint8_t* mac) const;

            // Protocol info helpers
            QString getTCPInfo(const Common::ParsedPacket& packet) const;
            QString getUDPInfo(const Common::ParsedPacket& packet) const;
            QString getICMPInfo(const Common::ParsedPacket& packet) const;
            QString getARPInfo(const Common::ParsedPacket& packet) const;
            QString getDNSInfo(const Common::ParsedPacket& packet) const;
            QString getHTTPInfo(const Common::ParsedPacket& packet) const;

            // Data
            std::vector<PacketEntry> packets_;
            std::vector<size_t> filtered_indices_;
            std::unique_ptr<ColorRules> color_rules_;

            // Settings
            TimeFormat time_format_;
            bool coloring_enabled_;
            std::vector<bool> column_visible_;
            QString current_filter_;

            // Time tracking
            uint64_t first_packet_time_;
            uint64_t last_packet_time_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_TABLE_MODEL_HPP
