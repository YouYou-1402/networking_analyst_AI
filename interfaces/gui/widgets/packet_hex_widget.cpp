// src/gui/widgets/packet_hex_widget.cpp

#include "packet_hex_widget.hpp"
#include <QVBoxLayout>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QWheelEvent>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        PacketHexWidget::PacketHexWidget(QWidget* parent)
            : QWidget(parent),
              selection_start_(-1),
              selection_end_(-1),
              is_selecting_(false),
              highlight_start_(-1),
              highlight_length_(0),
              bytes_per_line_(16),
              show_ascii_(true),
              show_offset_(true),
              highlight_selection_(true),
              scroll_position_(0)
        {
            setupUI();
            setupContextMenu();
            calculateLayout();

            // Colors
            bg_color_ = QColor(255, 255, 255);
            fg_color_ = QColor(0, 0, 0);
            selection_color_ = QColor(173, 216, 230);
            highlight_color_ = QColor(255, 255, 0, 100);
            offset_color_ = QColor(128, 128, 128);
            ascii_color_ = QColor(0, 0, 128);

            setMouseTracking(true);
        }

        PacketHexWidget::~PacketHexWidget()
        {
        }

        void PacketHexWidget::setupUI()
        {
            QVBoxLayout* layout = new QVBoxLayout(this);
            layout->setContentsMargins(0, 0, 0, 0);
            layout->setSpacing(0);

            // Scroll bar
            scroll_bar_ = new QScrollBar(Qt::Vertical, this);
            scroll_bar_->setVisible(false);
            connect(scroll_bar_, &QScrollBar::valueChanged,
                    this, &PacketHexWidget::onScrollValueChanged);

            // Layout with scroll bar on the right
            QHBoxLayout* h_layout = new QHBoxLayout();
            h_layout->setContentsMargins(0, 0, 0, 0);
            h_layout->setSpacing(0);
            h_layout->addStretch();
            h_layout->addWidget(scroll_bar_);

            layout->addLayout(h_layout);

            setContextMenuPolicy(Qt::CustomContextMenu);
        }

        void PacketHexWidget::setupContextMenu()
        {
            context_menu_ = new QMenu(this);

            action_copy_hex_ = context_menu_->addAction(tr("Copy as Hex"));
            action_copy_hex_->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
            connect(action_copy_hex_, &QAction::triggered, this, &PacketHexWidget::onCopyHex);

            action_copy_ascii_ = context_menu_->addAction(tr("Copy as ASCII"));
            connect(action_copy_ascii_, &QAction::triggered, this, &PacketHexWidget::onCopyASCII);

            action_copy_both_ = context_menu_->addAction(tr("Copy as Hex + ASCII"));
            connect(action_copy_both_, &QAction::triggered, this, &PacketHexWidget::onCopyBoth);

            context_menu_->addSeparator();

            action_select_all_ = context_menu_->addAction(tr("Select All"));
            action_select_all_->setShortcut(QKeySequence::SelectAll);
            connect(action_select_all_, &QAction::triggered, [this]() {
                selectBytes(0, data_.size());
            });

            context_menu_->addSeparator();

            action_export_ = context_menu_->addAction(tr("Export Bytes..."));
            connect(action_export_, &QAction::triggered, this, &PacketHexWidget::onExport);
        }

        void PacketHexWidget::calculateLayout()
        {
            QFontMetrics fm(font());
            char_width_ = fm.horizontalAdvance('0');
            char_height_ = fm.height();
            line_height_ = char_height_ + 2;

            // Calculate widths
            offset_width_ = show_offset_ ? (char_width_ * 8 + 10) : 0;
            hex_width_ = char_width_ * (bytes_per_line_ * 3 + 2);
            ascii_width_ = show_ascii_ ? (char_width_ * (bytes_per_line_ + 2)) : 0;

            // Calculate visible lines
            visible_lines_ = height() / line_height_;
            total_lines_ = (data_.size() + bytes_per_line_ - 1) / bytes_per_line_;

            updateScrollBar();
        }

        void PacketHexWidget::updateScrollBar()
        {
            if (total_lines_ > visible_lines_) {
                scroll_bar_->setVisible(true);
                scroll_bar_->setMaximum(total_lines_ - visible_lines_);
                scroll_bar_->setPageStep(visible_lines_);
            } else {
                scroll_bar_->setVisible(false);
                scroll_position_ = 0;
            }
        }

        // ==================== Display ====================

        void PacketHexWidget::displayData(const std::vector<uint8_t>& data)
        {
            data_ = data;
            selection_start_ = -1;
            selection_end_ = -1;
            highlight_start_ = -1;
            highlight_length_ = 0;
            scroll_position_ = 0;

            calculateLayout();
            update();
        }

        void PacketHexWidget::clearDisplay()
        {
            data_.clear();
            selection_start_ = -1;
            selection_end_ = -1;
            highlight_start_ = -1;
            highlight_length_ = 0;
            scroll_position_ = 0;

            calculateLayout();
            update();
        }

        // ==================== Selection ====================

        void PacketHexWidget::selectBytes(int offset, int length)
        {
            if (offset < 0 || offset >= static_cast<int>(data_.size())) {
                return;
            }

            selection_start_ = offset;
            selection_end_ = std::min(offset + length, static_cast<int>(data_.size()));

            // Scroll to selection
            int line = offset / bytes_per_line_;
            if (line < scroll_position_ || line >= scroll_position_ + visible_lines_) {
                scroll_position_ = std::max(0, line - visible_lines_ / 2);
                scroll_bar_->setValue(scroll_position_);
            }

            update();
            emit bytesSelected(selection_start_, selection_end_ - selection_start_);
        }

        void PacketHexWidget::clearSelection()
        {
            selection_start_ = -1;
            selection_end_ = -1;
            update();
        }

        QByteArray PacketHexWidget::getSelectedBytes() const
        {
            if (selection_start_ < 0 || selection_end_ <= selection_start_) {
                return QByteArray();
            }

            int length = selection_end_ - selection_start_;
            return QByteArray(reinterpret_cast<const char*>(data_.data() + selection_start_), length);
        }

        // ==================== Display Options ====================

        void PacketHexWidget::setBytesPerLine(int bytes)
        {
            bytes_per_line_ = bytes;
            calculateLayout();
            update();
        }

        void PacketHexWidget::setShowASCII(bool show)
        {
            show_ascii_ = show;
            calculateLayout();
            update();
        }

        void PacketHexWidget::setShowOffset(bool show)
        {
            show_offset_ = show;
            calculateLayout();
            update();
        }

        void PacketHexWidget::setHighlightSelection(bool highlight)
        {
            highlight_selection_ = highlight;
            update();
        }

        // ==================== Export ====================

        void PacketHexWidget::copyHex()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            QString hex = bytes.toHex(' ').toUpper();
            QApplication::clipboard()->setText(hex);
        }

        void PacketHexWidget::copyASCII()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            QString ascii;
            for (uint8_t byte : bytes) {
                ascii += toASCII(byte);
            }
            QApplication::clipboard()->setText(ascii);
        }

        void PacketHexWidget::copyBoth()
        {
            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                return;
            }

            QString hex = bytes.toHex(' ').toUpper();
            QString ascii;
            for (uint8_t byte : bytes) {
                ascii += toASCII(byte);
            }

            QString combined = QString("Hex: %1\nASCII: %2").arg(hex).arg(ascii);
            QApplication::clipboard()->setText(combined);
        }

        void PacketHexWidget::exportToFile(const QString& filename)
        {
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly)) {
                spdlog::error("Failed to open file for export: {}", filename.toStdString());
                return;
            }

            QByteArray bytes = getSelectedBytes();
            if (bytes.isEmpty()) {
                bytes = QByteArray(reinterpret_cast<const char*>(data_.data()), data_.size());
            }

            file.write(bytes);
            file.close();

            spdlog::info("Exported {} bytes to {}", bytes.size(), filename.toStdString());
        }

        // ==================== Painting ====================

        void PacketHexWidget::paintEvent(QPaintEvent* event)
        {
            Q_UNUSED(event);

            QPainter painter(this);
            painter.fillRect(rect(), bg_color_);

            if (data_.empty()) {
                return;
            }

            int y = 5;

            // Draw visible lines
            for (int line = scroll_position_; 
                 line < scroll_position_ + visible_lines_ && line < total_lines_; 
                 line++) {
                int offset = line * bytes_per_line_;
                int length = std::min(bytes_per_line_, static_cast<int>(data_.size()) - offset);

                // Draw offset
                if (show_offset_) {
                    drawOffsets(painter, y);
                }

                // Draw hex data
                drawHexData(painter, y);

                // Draw ASCII data
                if (show_ascii_) {
                    drawASCIIData(painter, y);
                }

                y += line_height_;
            }

            // Draw selection
            if (selection_start_ >= 0 && selection_end_ > selection_start_) {
                drawSelection(painter);
            }

            // Draw highlight
            if (highlight_start_ >= 0 && highlight_length_ > 0) {
                drawHighlight(painter);
            }
        }

        void PacketHexWidget::drawOffsets(QPainter& painter, int y_start)
        {
            painter.setPen(offset_color_);
            
            for (int line = scroll_position_; 
                 line < scroll_position_ + visible_lines_ && line < total_lines_; 
                 line++) {
                int offset = line * bytes_per_line_;
                QString offset_str = QString("%1").arg(offset, 8, 16, QChar('0')).toUpper();
                painter.drawText(5, y_start + (line - scroll_position_) * line_height_ + char_height_, offset_str);
            }
        }

        void PacketHexWidget::drawHexData(QPainter& painter, int y_start)
        {
            painter.setPen(fg_color_);
            
            for (int line = scroll_position_; 
                 line < scroll_position_ + visible_lines_ && line < total_lines_; 
                 line++) {
                int offset = line * bytes_per_line_;
                int length = std::min(bytes_per_line_, static_cast<int>(data_.size()) - offset);
                
                QString hex_line = formatHexLine(offset, length);
                int x = offset_width_;
                int y = y_start + (line - scroll_position_) * line_height_ + char_height_;
                painter.drawText(x, y, hex_line);
            }
        }

        void PacketHexWidget::drawASCIIData(QPainter& painter, int y_start)
        {
            painter.setPen(ascii_color_);
            
            for (int line = scroll_position_; 
                 line < scroll_position_ + visible_lines_ && line < total_lines_; 
                 line++) {
                int offset = line * bytes_per_line_;
                int length = std::min(bytes_per_line_, static_cast<int>(data_.size()) - offset);
                
                QString ascii_line = formatASCIILine(offset, length);
                int x = offset_width_ + hex_width_ + 10;
                int y = y_start + (line - scroll_position_) * line_height_ + char_height_;
                painter.drawText(x, y, ascii_line);
            }
        }

        void PacketHexWidget::drawSelection(QPainter& painter)
        {
            if (!highlight_selection_) {
                return;
            }

            painter.fillRect(getByteRect(selection_start_), selection_color_);
            
            for (int i = selection_start_ + 1; i < selection_end_; i++) {
                painter.fillRect(getByteRect(i), selection_color_);
            }
        }

        void PacketHexWidget::drawHighlight(QPainter& painter)
        {
            painter.fillRect(getByteRect(highlight_start_), highlight_color_);
            
            for (int i = 1; i < highlight_length_; i++) {
                painter.fillRect(getByteRect(highlight_start_ + i), highlight_color_);
            }
        }

        // ==================== Helper Methods ====================

        int PacketHexWidget::getOffsetFromPosition(const QPoint& pos) const
        {
            int line = (pos.y() / line_height_) + scroll_position_;
            int x = pos.x() - offset_width_;
            
            if (x < 0 || line >= total_lines_) {
                return -1;
            }

            int byte_in_line = x / (char_width_ * 3);
            if (byte_in_line >= bytes_per_line_) {
                return -1;
            }

            int offset = line * bytes_per_line_ + byte_in_line;
            return (offset < static_cast<int>(data_.size())) ? offset : -1;
        }

        QRect PacketHexWidget::getByteRect(int offset) const
        {
            if (offset < 0 || offset >= static_cast<int>(data_.size())) {
                return QRect();
            }

            int line = offset / bytes_per_line_ - scroll_position_;
            int byte_in_line = offset % bytes_per_line_;

            int x = offset_width_ + byte_in_line * char_width_ * 3;
            int y = line * line_height_;
            int w = char_width_ * 2;
            int h = line_height_;

            return QRect(x, y, w, h);
        }

        QString PacketHexWidget::formatHexLine(int offset, int length) const
        {
            QString line;
            for (int i = 0; i < length; i++) {
                line += QString("%1 ").arg(data_[offset + i], 2, 16, QChar('0')).toUpper();
            }
            return line;
        }

        QString PacketHexWidget::formatASCIILine(int offset, int length) const
        {
            QString line;
            for (int i = 0; i < length; i++) {
                line += toASCII(data_[offset + i]);
            }
            return line;
        }

        char PacketHexWidget::toASCII(uint8_t byte) const
        {
            return (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.';
        }

        // ==================== Event Handlers ====================

        void PacketHexWidget::mousePressEvent(QMouseEvent* event)
        {
            if (event->button() == Qt::LeftButton) {
                int offset = getOffsetFromPosition(event->pos());
                if (offset >= 0) {
                    selection_start_ = offset;
                    selection_end_ = offset + 1;
                    is_selecting_ = true;
                    update();
                    emit bytesSelected(selection_start_, 1);
                }
            }
        }

        void PacketHexWidget::mouseMoveEvent(QMouseEvent* event)
        {
            if (is_selecting_) {
                int offset = getOffsetFromPosition(event->pos());
                if (offset >= 0) {
                    if (offset >= selection_start_) {
                        selection_end_ = offset + 1;
                    } else {
                        selection_end_ = selection_start_ + 1;
                        selection_start_ = offset;
                    }
                    update();
                    emit bytesSelected(selection_start_, selection_end_ - selection_start_);
                }
            }
        }

        void PacketHexWidget::mouseReleaseEvent(QMouseEvent* event)
        {
            if (event->button() == Qt::LeftButton) {
                is_selecting_ = false;
            }
        }

        void PacketHexWidget::contextMenuEvent(QContextMenuEvent* event)
        {
            if (selection_start_ >= 0 && selection_end_ > selection_start_) {
                context_menu_->exec(event->globalPos());
            }
        }

        void PacketHexWidget::wheelEvent(QWheelEvent* event)
        {
            int delta = -event->angleDelta().y() / 120;
            int new_pos = std::max(0, std::min(scroll_position_ + delta, 
                                              total_lines_ - visible_lines_));
            
            if (new_pos != scroll_position_) {
                scroll_position_ = new_pos;
                scroll_bar_->setValue(scroll_position_);
                update();
            }
        }

        void PacketHexWidget::resizeEvent(QResizeEvent* event)
        {
            Q_UNUSED(event);
            calculateLayout();
            update();
        }

        // ==================== Slots ====================

        void PacketHexWidget::onScrollValueChanged(int value)
        {
            scroll_position_ = value;
            update();
        }

        void PacketHexWidget::onCopyHex()
        {
            copyHex();
        }

        void PacketHexWidget::onCopyASCII()
        {
            copyASCII();
        }

        void PacketHexWidget::onCopyBoth()
        {
            copyBoth();
        }

        void PacketHexWidget::onExport()
        {
            QString filename = QFileDialog::getSaveFileName(
                this,
                tr("Export Bytes"),
                QString(),
                tr("Binary Files (*.bin);;All Files (*)")
            );

            if (!filename.isEmpty()) {
                exportToFile(filename);
            }
        }

    } // namespace GUI
} // namespace NetworkSecurity
