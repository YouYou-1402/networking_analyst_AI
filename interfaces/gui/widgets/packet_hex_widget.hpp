// src/gui/widgets/packet_hex_widget.hpp

#ifndef PACKET_HEX_WIDGET_HPP
#define PACKET_HEX_WIDGET_HPP

#include <QWidget>
#include <QTextEdit>
#include <QScrollBar>
#include <QPainter>
#include <QMenu>
#include <QAction>
#include <vector>

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Hex dump widget (like Wireshark hex view)
         */
        class PacketHexWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit PacketHexWidget(QWidget* parent = nullptr);
            ~PacketHexWidget();

            // ==================== Display ====================
            void displayData(const std::vector<uint8_t>& data);
            void clearDisplay();
            
            // ==================== Selection ====================
            void selectBytes(int offset, int length);
            void clearSelection();
            QByteArray getSelectedBytes() const;
            
            // ==================== Display Options ====================
            void setBytesPerLine(int bytes);
            void setShowASCII(bool show);
            void setShowOffset(bool show);
            void setHighlightSelection(bool highlight);
            
            // ==================== Export ====================
            void copyHex();
            void copyASCII();
            void copyBoth();
            void exportToFile(const QString& filename);

        signals:
            void bytesSelected(int offset, int length);
            void offsetClicked(int offset);

        protected:
            void paintEvent(QPaintEvent* event) override;
            void mousePressEvent(QMouseEvent* event) override;
            void mouseMoveEvent(QMouseEvent* event) override;
            void mouseReleaseEvent(QMouseEvent* event) override;
            void contextMenuEvent(QContextMenuEvent* event) override;
            void wheelEvent(QWheelEvent* event) override;
            void resizeEvent(QResizeEvent* event) override;

        private slots:
            void onScrollValueChanged(int value);
            void onCopyHex();
            void onCopyASCII();
            void onCopyBoth();
            void onExport();

        private:
            void setupUI();
            void setupContextMenu();
            void updateScrollBar();
            void calculateLayout();
            
            // Drawing methods
            void drawOffsets(QPainter& painter, int y_start);
            void drawHexData(QPainter& painter, int y_start);
            void drawASCIIData(QPainter& painter, int y_start);
            void drawSelection(QPainter& painter);
            void drawHighlight(QPainter& painter);
            
            // Helper methods
            int getOffsetFromPosition(const QPoint& pos) const;
            QRect getByteRect(int offset) const;
            QString formatHexLine(int offset, int length) const;
            QString formatASCIILine(int offset, int length) const;
            char toASCII(uint8_t byte) const;

            // UI Components
            QScrollBar* scroll_bar_;
            QMenu* context_menu_;
            
            // Actions
            QAction* action_copy_hex_;
            QAction* action_copy_ascii_;
            QAction* action_copy_both_;
            QAction* action_export_;
            QAction* action_select_all_;
            
            // Data
            std::vector<uint8_t> data_;
            
            // Selection
            int selection_start_;
            int selection_end_;
            bool is_selecting_;
            
            // Highlight (from packet detail)
            int highlight_start_;
            int highlight_length_;
            
            // Display settings
            int bytes_per_line_;
            bool show_ascii_;
            bool show_offset_;
            bool highlight_selection_;
            
            // Layout
            int offset_width_;
            int hex_width_;
            int ascii_width_;
            int char_width_;
            int char_height_;
            int line_height_;
            int visible_lines_;
            int total_lines_;
            int scroll_position_;
            
            // Colors
            QColor bg_color_;
            QColor fg_color_;
            QColor selection_color_;
            QColor highlight_color_;
            QColor offset_color_;
            QColor ascii_color_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PACKET_HEX_WIDGET_HPP
