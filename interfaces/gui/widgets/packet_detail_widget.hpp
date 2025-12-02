// src/gui/widgets/packet_detail_widget.hpp

#ifndef PACKET_DETAIL_WIDGET_HPP
#define PACKET_DETAIL_WIDGET_HPP

#include <QWidget>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTextEdit>
#include <QSplitter>
#include <QMenu>
#include <QAction>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QTextCharFormat>
#include <QTextCursor>
#include <memory>

#include "common/packet_parser.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Custom QTextEdit for hex dump display with highlighting
         */
        class HexDumpWidget : public QTextEdit
        {
            Q_OBJECT

        public:
            explicit HexDumpWidget(QWidget* parent = nullptr);
            
            void setRawData(const std::vector<uint8_t>& data);
            void clearData();
            void highlightBytes(int offset, int length);
            void clearHighlight();
            
        protected:
            void mouseMoveEvent(QMouseEvent* event) override;
            void leaveEvent(QEvent* event) override;
            
        signals:
            void bytesHovered(int offset, int length);
            
        private:
            void buildHexDump();
            int getOffsetAtPosition(const QPoint& pos);
            void updateHoverHighlight(int offset);
            
            std::vector<uint8_t> raw_data_;
            int highlighted_offset_;
            int highlighted_length_;
            int hover_offset_;
            
            QTextCharFormat normal_format_;
            QTextCharFormat highlight_format_;
            QTextCharFormat hover_format_;
            
            static constexpr int BYTES_PER_LINE = 16;
        };

        /**
         * @brief Packet details widget with split view (Tree + Hex dump)
         */
        class PacketDetailWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit PacketDetailWidget(QWidget* parent = nullptr);
            ~PacketDetailWidget() override;

            // ==================== Display ====================
            void displayPacket(const Common::ParsedPacket& packet,
                             const std::vector<uint8_t>& raw_data);
            void clearDisplay();
            void refresh();
            
            // ==================== Navigation ====================
            void expandAll();
            void collapseAll();
            void expandItem(QTreeWidgetItem* item);
            void collapseItem(QTreeWidgetItem* item);
            void expandProtocol(const QString& protocol);
            void collapseProtocol(const QString& protocol);
                                             
            // ==================== Selection ====================
            QByteArray getSelectedBytes() const;
            QString getSelectedField() const;
            QString getSelectedValue() const;
            int getSelectedOffset() const;
            int getSelectedLength() const;
            QTreeWidgetItem* getSelectedItem() const;
            
            // ==================== Search ====================
            void findText(const QString& text, bool case_sensitive = false);
            void findNext();
            void findPrevious();
            
            // ==================== Settings ====================
            void setShowHexData(bool show);
            bool isShowHexData() const;
            void setAutoExpand(bool expand);
            bool isAutoExpand() const;
            void setSplitterRatio(double ratio); // 0.0 - 1.0
            
        signals:
            void bytesSelected(int offset, int length);
            void fieldSelected(const QString& field, const QString& value);
            void filterRequested(const QString& filter);
            void protocolExpanded(const QString& protocol);
            void protocolCollapsed(const QString& protocol);

        protected:
            void contextMenuEvent(QContextMenuEvent* event) override;

        private slots:
            void onItemClicked(QTreeWidgetItem* item, int column);
            void onItemDoubleClicked(QTreeWidgetItem* item, int column);
            void onItemExpanded(QTreeWidgetItem* item);
            void onItemCollapsed(QTreeWidgetItem* item);
            void onItemContextMenu(const QPoint& pos);
            void onItemSelectionChanged();
            void onTreeItemHovered(QTreeWidgetItem* item, int column);
            void onHexBytesHovered(int offset, int length);
            
            // Context menu actions
            void onExpandAll();
            void onCollapseAll();
            void onExpandSubtree();
            void onCollapseSubtree();
            
            void onApplyAsFilter();
            void onPrepareFilter();
            void onApplyAsColumn();
            
            void onCopyField();
            void onCopyValue();
            void onCopyBoth();
            void onCopyBytes();
            void onCopyBytesHex();
            void onCopyBytesText();
            
            void onExportBytes();
            void onExportPacket();
            
            void onFollowStream();
            void onShowInHexDump();

        private:
            // ==================== UI Setup ====================
            void setupUI();
            void setupTreeWidget();
            void setupHexWidget();
            void setupSplitter();
            void setupContextMenu();
            void applyWiresharkStyle();
            
            // ==================== Build Tree ====================
            void buildPacketTree(const Common::ParsedPacket& packet,
                               const std::vector<uint8_t>& raw_data);
            
            // Protocol layers
            QTreeWidgetItem* addFrameInfo(const Common::ParsedPacket& packet);
            QTreeWidgetItem* addEthernetInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addVLANInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addARPInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addIPv4Info(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addIPv6Info(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addTCPInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addUDPInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addICMPInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addICMPv6Info(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addApplicationInfo(const Common::ParsedPacket& packet, int offset);
            QTreeWidgetItem* addPayloadInfo(const Common::ParsedPacket& packet, int offset);
            
            // ==================== Helper Methods ====================
            QTreeWidgetItem* createItem(const QString& name, 
                                       const QString& value = QString(),
                                       int offset = -1,
                                       int length = 0);
            
            void addChildItem(QTreeWidgetItem* parent,
                            const QString& name,
                            const QString& value,
                            int offset = -1,
                            int length = 0);
            
            void addBitfieldItem(QTreeWidgetItem* parent,
                               const QString& name,
                               uint32_t value,
                               int bit_offset,
                               int bit_length,
                               int byte_offset);
            
            void addHexDumpItem(QTreeWidgetItem* parent,
                              const QString& name,
                              const uint8_t* data,
                              size_t length,
                              int offset);

            // ==================== Formatting ====================
            QString formatBytes(const uint8_t* data, size_t length, bool with_ascii = false) const;
            QString formatBytesOneLine(const uint8_t* data, size_t length) const;
            QString formatMAC(const uint8_t* mac) const;
            QString formatIPv4(uint32_t ip) const;
            QString formatIPv6(const uint8_t* ipv6) const;
            QString formatPort(uint16_t port) const;
            QString formatProtocol(uint8_t protocol) const;
            QString formatFlags(uint8_t flags, const QStringList& flag_names) const;
            QString formatTime(double seconds) const;
            QString formatSize(size_t bytes) const;
            
            // ==================== Protocol Helpers ====================
            QString getTCPFlagsString(const Common::ParsedPacket& packet) const;
            QString getICMPTypeString(uint8_t type) const;
            QString getICMPv6TypeString(uint8_t type) const;
            QString getARPOpcodeString(uint16_t opcode) const;
            QString getEtherTypeString(uint16_t ether_type) const;
            QString getIPProtocolString(uint8_t protocol) const;
            
            // ==================== Export ====================
            void exportItemToText(QTextStream& out, QTreeWidgetItem* item, int indent) const;
            
            // ==================== UI Components ====================
            QSplitter* splitter_;
            QTreeWidget* tree_widget_;
            HexDumpWidget* hex_widget_;
            
            // Context menus
            QMenu* context_menu_;
            QMenu* expand_menu_;
            QMenu* filter_menu_;
            QMenu* copy_menu_;
            QMenu* export_menu_;
            
            // Actions - Expand/Collapse
            QAction* action_expand_all_;
            QAction* action_collapse_all_;
            QAction* action_expand_subtree_;
            QAction* action_collapse_subtree_;
            
            // Actions - Filter
            QAction* action_apply_filter_;
            QAction* action_prepare_filter_;
            QAction* action_apply_column_;
            
            // Actions - Copy
            QAction* action_copy_field_;
            QAction* action_copy_value_;
            QAction* action_copy_both_;
            QAction* action_copy_bytes_;
            QAction* action_copy_bytes_hex_;
            QAction* action_copy_bytes_text_;
            
            // Actions - Export
            QAction* action_export_bytes_;
            QAction* action_export_packet_;
            
            // Actions - Follow
            QAction* action_follow_stream_;
            QAction* action_show_hex_;
            
            // ==================== Data ====================
            const Common::ParsedPacket* current_packet_;
            std::vector<uint8_t> current_raw_data_;
            QTreeWidgetItem* selected_item_;
            
            // Settings
            bool show_hex_data_;
            bool auto_expand_;
            
            // Search
            QString search_text_;
            bool search_case_sensitive_;
            QList<QTreeWidgetItem*> search_results_;
            int search_current_index_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_DETAIL_WIDGET_HPP
