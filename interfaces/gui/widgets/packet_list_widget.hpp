// src/gui/widgets/packet_list_widget.hpp

#ifndef PACKET_LIST_WIDGET_HPP
#define PACKET_LIST_WIDGET_HPP

#include <QWidget>
#include <QTableView>
#include <QHeaderView>
#include <QMenu>
#include <QAction>
#include <QVBoxLayout>
#include <QLabel>
#include <QTimer>
#include <memory>

#include "models/packet_table_model.hpp"
#include "common/packet_parser.hpp"
#include "utils/color_rules.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Packet list widget (Wireshark-like packet list view)
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
            void removePacket(int row);
            void updatePacket(int row);
            
            // ==================== Selection ====================
            int getSelectedRow() const;
            Common::ParsedPacket getSelectedPacket() const;
            std::vector<uint8_t> getSelectedRawData() const;
            
            void selectRow(int row);
            void selectFirstPacket();
            void selectLastPacket();
            void selectNextPacket();
            void selectPreviousPacket();
            void clearSelection();
            
            // ==================== Filtering ====================
            void setFilter(const QString& filter);
            QString getFilter() const;
            void applyFilter();
            void clearFilter();
            bool isFiltering() const;
            
            // ==================== Marking ====================
            void markSelectedPacket();
            void unmarkSelectedPacket();
            void toggleMarkSelectedPacket();
            void markAllPackets();
            void unmarkAllPackets();
            bool isSelectedMarked() const;
            int getMarkedCount() const;
            void markPacket(int row);
            void unmarkPacket(int row);
            void markAll();
            void unmarkAll();
            void toggleMark(int row);
            // ==================== Display Settings ====================
            void setTimeFormat(PacketTableModel::TimeFormat format);
            PacketTableModel::TimeFormat getTimeFormat() const;
            
            void setColumnVisible(int column, bool visible);
            bool isColumnVisible(int column) const;
            void resetColumns();
            
            void setAutoScroll(bool enabled);
            bool isAutoScrollEnabled() const;
            
            // ==================== Color Rules ====================
            void setColorRules(ColorRules* rules);
            ColorRules* getColorRules() const;
            void setColoringEnabled(bool enabled);
            bool isColoringEnabled() const;
            void refreshColors();
            void loadDefaultColorRules();
            void loadColorRulesFromFile(const QString& filename);
            void saveColorRulesToFile(const QString& filename);
            
            // ==================== Export ====================
            void copySelectedPacket();
            void copyAllPackets();
            void exportSelectedPacket(const QString& filename);
            void exportAllPackets(const QString& filename);
            void exportMarkedPackets(const QString& filename);
            
            // ==================== Statistics ====================
            int getPacketCount() const;
            int getTotalPacketCount() const;
            PacketTableModel::Statistics getStatistics() const;
            
            // ==================== Model Access ====================
            PacketTableModel* getModel() const;
            QTableView* getTableView() const;

        signals:
            void packetSelected(int row);
            void packetDoubleClicked(int row);
            void packetsCleared();
            void filterChanged(const QString& filter);
            void statisticsChanged();

        public slots:
            // Display slots
            void scrollToTop();
            void scrollToBottom();
            void scrollToPacket(int row);
            
            // Column management
            void showColumn(int column);
            void hideColumn(int column);
            void resizeColumnsToContents();
            void autoSizeColumns();

        private slots:
            // Selection handlers
            void onSelectionChanged(const QItemSelection& selected, 
                                  const QItemSelection& deselected);
            void onDoubleClicked(const QModelIndex& index);
            
            // Context menu handlers
            void onCellContextMenu(const QPoint& pos);
            void onHeaderContextMenu(const QPoint& pos);
            
            // Action handlers
            void onMarkPacket();
            void onUnmarkPacket();
            void onToggleMarkPacket();
            void onMarkAllPackets();
            void onUnmarkAllPackets();
            
            void onApplyAsFilter();
            void onPrepareFilter();
            void onApplyAsColumn();
            
            void onFollowTCPStream();
            void onFollowUDPStream();
            
            void onCopyPacket();
            void onCopyAllPackets();
            void onExportPacket();
            void onExportAllPackets();
            
            void onShowPacketDetails();
            void onShowPacketBytes();
            
            // Model change handlers
            void onPacketAdded(int row);
            void onPacketsChanged();
            void onFilterChanged();
            
            // Update handlers
            void updateStatusBar();
            void updateColumnVisibility();

        private:
            // ==================== UI Setup ====================
            void setupUI();
            void setupTableView();
            void setupContextMenu();
            void setupHeaderMenu();
            void setupStatusBar();
            void setupColorRules();
            void setupConnections();
            
            // ==================== Settings ====================
            void loadSettings();
            void saveSettings();
            void loadColumnSettings();
            void saveColumnSettings();
            
            // ==================== Helper Methods ====================
            void updateSelection();
            void updateAutoScroll();
            QString formatPacketForClipboard(const PacketEntry& entry) const;
            QString formatAllPacketsForClipboard() const;
            
            // ==================== UI Components ====================
            QTableView* table_view_;
            PacketTableModel* model_;
            QLabel* status_label_;
            
            // ==================== Context Menus ====================
            QMenu* context_menu_;
            QMenu* header_menu_;
            QMenu* filter_menu_;
            QMenu* follow_menu_;
            QMenu* export_menu_;
            
            // ==================== Actions ====================
            // Marking
            QAction* action_mark_;
            QAction* action_unmark_;
            QAction* action_toggle_mark_;
            QAction* action_mark_all_;
            QAction* action_unmark_all_;
            
            // Filtering
            QAction* action_apply_filter_;
            QAction* action_prepare_filter_;
            QAction* action_apply_column_;
            
            // Following
            QAction* action_follow_tcp_;
            QAction* action_follow_udp_;
            
            // Copy & Export
            QAction* action_copy_;
            QAction* action_copy_all_;
            QAction* action_export_;
            QAction* action_export_all_;
            QAction* action_export_marked_;
            
            // Details
            QAction* action_show_details_;
            QAction* action_show_bytes_;
            
            // ==================== Color Rules ====================
            ColorRules* color_rules_;
            bool coloring_enabled_;
            
            // ==================== Display Settings ====================
            PacketTableModel::TimeFormat time_format_;
            bool auto_scroll_;
            int selected_row_;
            
            // ==================== Update Timer ====================
            QTimer* update_timer_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_LIST_WIDGET_HPP
