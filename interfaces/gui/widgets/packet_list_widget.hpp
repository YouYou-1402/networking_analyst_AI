// src/gui/widgets/packet_list_widget.hpp

#ifndef PACKET_LIST_WIDGET_HPP
#define PACKET_LIST_WIDGET_HPP

#include <QWidget>
#include <QTableView>
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QContextMenuEvent>
#include <memory>

#include "models/packet_table_model.hpp"
#include "common/packet_parser.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Packet list table widget (like Wireshark packet list)
         */
        class PacketListWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit PacketListWidget(QWidget* parent = nullptr);
            ~PacketListWidget();

            // ==================== Packet Management ====================
            void addPacket(const Common::ParsedPacket& packet, 
                          const std::vector<uint8_t>& raw_data);
            void clearPackets();
            void updatePacket(int index);
            
            // ==================== Selection ====================
            int getSelectedRow() const;
            void selectRow(int row);
            void selectFirstPacket();
            void selectLastPacket();
            void selectNextPacket();
            void selectPreviousPacket();
            
            // ==================== Filtering ====================
            void applyFilter(const QString& filter);
            void clearFilter();
            
            // ==================== Marking ====================
            void markPacket(int index);
            void unmarkPacket(int index);
            void markAll();
            void unmarkAll();
            bool isMarked(int index) const;
            
            // ==================== Display ====================
            void setColumnVisible(int column, bool visible);
            void setTimeFormat(int format);
            void setColoringEnabled(bool enabled);
            void applyColoringRules();
            
            // ==================== Export ====================
            void copySelectedPacket();
            void copyAllPackets();
            QString getPacketSummary(int index) const;

        signals:
            void packetSelected(int row);
            void packetDoubleClicked(int row);
            void packetRightClicked(int row, const QPoint& pos);
            void filterRequested(const QString& filter);

        protected:
            void contextMenuEvent(QContextMenuEvent* event) override;
            void keyPressEvent(QKeyEvent* event) override;

        private slots:
            void onSelectionChanged(const QItemSelection& selected, 
                                   const QItemSelection& deselected);
            void onDoubleClicked(const QModelIndex& index);
            void onHeaderContextMenu(const QPoint& pos);
            void onCellContextMenu(const QPoint& pos);
            
            // Context menu actions
            void onMarkPacket();
            void onUnmarkPacket();
            void onApplyAsFilter();
            void onPrepareFilter();
            void onFollowStream();
            void onCopyPacket();
            void onExportPacket();

        private:
            void setupUI();
            void setupContextMenu();
            void setupHeaderMenu();
            void loadColumnSettings();
            void saveColumnSettings();
            
            QColor getPacketColor(const Common::ParsedPacket& packet) const;
            QString formatTime(uint64_t timestamp) const;

            // UI Components
            QTableView* table_view_;
            PacketTableModel* model_;
            
            // Context menus
            QMenu* context_menu_;
            QMenu* header_menu_;
            QMenu* filter_menu_;
            QMenu* follow_menu_;
            
            // Actions
            QAction* action_mark_;
            QAction* action_unmark_;
            QAction* action_copy_;
            QAction* action_export_;
            QAction* action_follow_tcp_;
            QAction* action_follow_udp_;
            QAction* action_apply_filter_;
            QAction* action_prepare_filter_;
            
            // Settings
            int time_format_;
            bool coloring_enabled_;
            bool auto_scroll_;
            
            // State
            int selected_row_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_LIST_WIDGET_HPP
