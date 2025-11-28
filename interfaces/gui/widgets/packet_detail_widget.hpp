// src/gui/widgets/packet_detail_widget.hpp

#ifndef PACKET_DETAIL_WIDGET_HPP
#define PACKET_DETAIL_WIDGET_HPP

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QMenu>
#include <QAction>
#include <memory>

#include "common/packet_parser.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Packet details tree widget (like Wireshark packet details)
         */
        class PacketDetailWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit PacketDetailWidget(QWidget* parent = nullptr);
            ~PacketDetailWidget();

            // ==================== Display ====================
            void displayPacket(const Common::ParsedPacket& packet,
                             const std::vector<uint8_t>& raw_data);
            void clearDisplay();
            
            // ==================== Navigation ====================
            void expandAll();
            void collapseAll();
            void expandItem(QTreeWidgetItem* item);
            void collapseItem(QTreeWidgetItem* item);
            
            // ==================== Selection ====================
            QByteArray getSelectedBytes() const;
            QString getSelectedField() const;
            int getSelectedOffset() const;
            int getSelectedLength() const;

        signals:
            void bytesSelected(int offset, int length);
            void fieldSelected(const QString& field);
            void filterRequested(const QString& filter);

        protected:
            void contextMenuEvent(QContextMenuEvent* event) override;

        private slots:
            void onItemClicked(QTreeWidgetItem* item, int column);
            void onItemExpanded(QTreeWidgetItem* item);
            void onItemCollapsed(QTreeWidgetItem* item);
            void onItemContextMenu(const QPoint& pos);
            
            // Context menu actions
            void onApplyAsFilter();
            void onPrepareFilter();
            void onCopyField();
            void onCopyValue();
            void onCopyBytes();
            void onExportBytes();

        private:
            void setupUI();
            void setupContextMenu();
            
            // Build packet tree
            void buildPacketTree(const Common::ParsedPacket& packet,
                               const std::vector<uint8_t>& raw_data);
            
            QTreeWidgetItem* addFrameInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addEthernetInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addVLANInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addARPInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addIPv4Info(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addIPv6Info(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addTCPInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addUDPInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addICMPInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addICMPv6Info(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addApplicationInfo(const Common::ParsedPacket& packet);
            
            // Helper methods
            QTreeWidgetItem* createItem(const QString& name, 
                                       const QString& value = QString(),
                                       int offset = -1,
                                       int length = 0);
            
            void addChildItem(QTreeWidgetItem* parent,
                            const QString& name,
                            const QString& value,
                            int offset = -1,
                            int length = 0);
            
            QString formatBytes(const uint8_t* data, size_t length) const;
            QString formatMAC(const uint8_t* mac) const;
            QString formatIP(uint32_t ip) const;
            QString formatIPv6(const uint8_t* ipv6) const;
            QString formatFlags(uint8_t flags, const char** flag_names) const;

            // UI Components
            QTreeWidget* tree_widget_;
            QMenu* context_menu_;
            
            // Actions
            QAction* action_expand_all_;
            QAction* action_collapse_all_;
            QAction* action_apply_filter_;
            QAction* action_prepare_filter_;
            QAction* action_copy_field_;
            QAction* action_copy_value_;
            QAction* action_copy_bytes_;
            QAction* action_export_bytes_;
            
            // Data
            const Common::ParsedPacket* current_packet_;
            const std::vector<uint8_t>* current_raw_data_;
            
            // State
            QTreeWidgetItem* selected_item_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_DETAIL_WIDGET_HPP
