// interfaces/gui/widgets/status_bar_widget.cpp

#include "status_bar_widget.hpp"
#include <QHBoxLayout>
#include <QStyle>
#include <chrono>

namespace NetworkSecurity
{
    namespace GUI
    {
        StatusBarWidget::StatusBarWidget(QWidget* parent)
            : QWidget(parent)
            , total_packets_(0)
            , displayed_packets_(0)
            , marked_packets_(0)
            , dropped_packets_(0)
            , total_bytes_(0)
            , capture_duration_(0.0)
            , current_bandwidth_(0.0)
            , capture_start_time_(0)
        {
            setupUI();
            
            // Update timer for elapsed time
            update_timer_ = new QTimer(this);
            connect(update_timer_, &QTimer::timeout, this, &StatusBarWidget::updateElapsedTime);
            
            // Message timer for temporary messages
            message_timer_ = new QTimer(this);
            message_timer_->setSingleShot(true);
            connect(message_timer_, &QTimer::timeout, this, &StatusBarWidget::clearMessage);
        }

        StatusBarWidget::~StatusBarWidget()
        {
            if (update_timer_->isActive())
                update_timer_->stop();
            if (message_timer_->isActive())
                message_timer_->stop();
        }

        void StatusBarWidget::setupUI()
        {
            auto* layout = new QHBoxLayout(this);
            layout->setContentsMargins(2, 2, 2, 2);
            layout->setSpacing(10);

            // Packet count label
            packet_label_ = new QLabel("Packets: 0", this);
            packet_label_->setMinimumWidth(150);
            layout->addWidget(packet_label_);

            // Marked packets label
            marked_label_ = new QLabel("Marked: 0", this);
            marked_label_->setMinimumWidth(80);
            marked_label_->setVisible(false); // Hidden by default
            layout->addWidget(marked_label_);

            // Dropped packets label
            dropped_label_ = new QLabel("Dropped: 0", this);
            dropped_label_->setMinimumWidth(90);
            dropped_label_->setVisible(false); // Hidden by default
            dropped_label_->setStyleSheet("QLabel { color: red; }");
            layout->addWidget(dropped_label_);

            // Separator
            layout->addSpacing(10);

            // Capture status label
            capture_label_ = new QLabel("Ready", this);
            capture_label_->setMinimumWidth(120);
            layout->addWidget(capture_label_);

            // Bandwidth label
            bandwidth_label_ = new QLabel("", this);
            bandwidth_label_->setMinimumWidth(80);
            layout->addWidget(bandwidth_label_);

            // Time label
            time_label_ = new QLabel("00:00:00", this);
            time_label_->setMinimumWidth(70);
            layout->addWidget(time_label_);

            // File info label
            file_label_ = new QLabel("", this);
            file_label_->setVisible(false);
            layout->addWidget(file_label_);

            // Profile label
            profile_label_ = new QLabel("Profile: Default", this);
            profile_label_->setMinimumWidth(100);
            layout->addWidget(profile_label_);

            layout->addStretch();

            // Progress bar (hidden by default)
            progress_bar_ = new QProgressBar(this);
            progress_bar_->setMaximumWidth(200);
            progress_bar_->setMaximumHeight(16);
            progress_bar_->setVisible(false);
            layout->addWidget(progress_bar_);

            // Message label
            message_label_ = new QLabel("", this);
            message_label_->setMinimumWidth(150);
            layout->addWidget(message_label_);

            // Expert Info button
            expert_button_ = new QPushButton("Expert Info", this);
            expert_button_->setFlat(true);
            expert_button_->setMaximumHeight(20);
            connect(expert_button_, &QPushButton::clicked, 
                    this, &StatusBarWidget::onExpertInfoClicked);
            layout->addWidget(expert_button_);

            // Comments button
            comments_button_ = new QPushButton("Comments", this);
            comments_button_->setFlat(true);
            comments_button_->setMaximumHeight(20);
            connect(comments_button_, &QPushButton::clicked, 
                    this, &StatusBarWidget::onCommentsClicked);
            layout->addWidget(comments_button_);

            setLayout(layout);
        }

        void StatusBarWidget::setPacketCount(uint64_t total, uint64_t displayed)
        {
            total_packets_ = total;
            displayed_packets_ = displayed;
            updatePacketLabel();
        }

        void StatusBarWidget::setMarkedCount(uint64_t marked)
        {
            marked_packets_ = marked;
            
            if (marked > 0)
            {
                marked_label_->setText(QString("Marked: %1").arg(marked));
                marked_label_->setVisible(true);
            }
            else
            {
                marked_label_->setVisible(false);
            }
        }

        void StatusBarWidget::setDroppedCount(uint64_t dropped)
        {
            dropped_packets_ = dropped;
            
            if (dropped > 0)
            {
                dropped_label_->setText(QString("Dropped: %1").arg(dropped));
                dropped_label_->setVisible(true);
            }
            else
            {
                dropped_label_->setVisible(false);
            }
        }

        void StatusBarWidget::setCaptureStatus(const QString& status)
        {
            capture_label_->setText(status);
            
            // Start/stop timer based on status
            if (status.contains("Capturing", Qt::CaseInsensitive))
            {
                if (!update_timer_->isActive())
                {
                    capture_start_time_ = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    update_timer_->start(1000); // Update every second
                }
            }
            else if (status.contains("Stopped", Qt::CaseInsensitive) || 
                     status.contains("Ready", Qt::CaseInsensitive))
            {
                update_timer_->stop();
            }
        }

        void StatusBarWidget::setFileInfo(const QString& filename, qint64 size)
        {
            QString sizeStr;
            formatBytes(size, sizeStr);
            
            file_label_->setText(QString("File: %1 (%2)").arg(filename).arg(sizeStr));
            file_label_->setVisible(true);
        }

        void StatusBarWidget::setProfileInfo(const QString& profile)
        {
            profile_label_->setText(QString("Profile: %1").arg(profile));
        }

        void StatusBarWidget::updateCaptureStats(uint64_t packets, 
                                                 uint64_t bytes,
                                                 double duration)
        {
            total_packets_ = packets;
            total_bytes_ = bytes;
            capture_duration_ = duration;
            
            updatePacketLabel();
            updateCaptureLabel();
        }

        void StatusBarWidget::updateBandwidth(double mbps)
        {
            current_bandwidth_ = mbps;
            
            if (mbps >= 1000.0)
            {
                bandwidth_label_->setText(QString("%1 Gbps").arg(mbps / 1000.0, 0, 'f', 2));
            }
            else if (mbps >= 1.0)
            {
                bandwidth_label_->setText(QString("%1 Mbps").arg(mbps, 0, 'f', 2));
            }
            else if (mbps >= 0.001)
            {
                bandwidth_label_->setText(QString("%1 Kbps").arg(mbps * 1000.0, 0, 'f', 2));
            }
            else
            {
                bandwidth_label_->setText(QString("%1 bps").arg(mbps * 1000000.0, 0, 'f', 0));
            }
        }

        void StatusBarWidget::showProgress(const QString& message, int maximum)
        {
            message_label_->setText(message);
            progress_bar_->setMaximum(maximum);
            progress_bar_->setValue(0);
            progress_bar_->setVisible(true);
        }

        void StatusBarWidget::updateProgress(int value)
        {
            progress_bar_->setValue(value);
        }

        void StatusBarWidget::hideProgress()
        {
            progress_bar_->setVisible(false);
            message_label_->clear();
        }

        void StatusBarWidget::showMessage(const QString& message, int timeout)
        {
            message_label_->setText(message);
            message_label_->setStyleSheet("QLabel { color: black; }");
            
            if (timeout > 0)
            {
                message_timer_->start(timeout);
            }
        }

        void StatusBarWidget::showError(const QString& error)
        {
            message_label_->setText(error);
            message_label_->setStyleSheet("QLabel { color: red; font-weight: bold; }");
            message_timer_->start(5000); // Show errors longer
        }

        void StatusBarWidget::showWarning(const QString& warning)
        {
            message_label_->setText(warning);
            message_label_->setStyleSheet("QLabel { color: orange; font-weight: bold; }");
            message_timer_->start(4000);
        }

        void StatusBarWidget::clearMessage()
        {
            message_label_->clear();
            message_label_->setStyleSheet("");
        }

        void StatusBarWidget::onExpertInfoClicked()
        {
            emit expertInfoClicked();
        }

        void StatusBarWidget::onCommentsClicked()
        {
            emit commentsClicked();
        }

        void StatusBarWidget::updateElapsedTime()
        {
            if (capture_start_time_ == 0)
                return;
                
            uint64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            uint64_t elapsed = current_time - capture_start_time_;
            
            QString timeStr;
            formatDuration(static_cast<double>(elapsed), timeStr);
            time_label_->setText(timeStr);
        }

        void StatusBarWidget::updatePacketLabel()
        {
            uint64_t total = total_packets_.load();
            uint64_t displayed = displayed_packets_.load();
            
            if (displayed < total)
            {
                packet_label_->setText(QString("Packets: %1 Displayed: %2")
                    .arg(total).arg(displayed));
            }
            else
            {
                packet_label_->setText(QString("Packets: %1").arg(total));
            }
        }

        void StatusBarWidget::updateCaptureLabel()
        {
            // This can be expanded to show more detailed capture info
            // For now, it's updated via setCaptureStatus()
        }

        void StatusBarWidget::formatBytes(uint64_t bytes, QString& text)
        {
            const double KB = 1024.0;
            const double MB = KB * 1024.0;
            const double GB = MB * 1024.0;
            const double TB = GB * 1024.0;
            
            if (bytes >= TB)
            {
                text = QString("%1 TB").arg(bytes / TB, 0, 'f', 2);
            }
            else if (bytes >= GB)
            {
                text = QString("%1 GB").arg(bytes / GB, 0, 'f', 2);
            }
            else if (bytes >= MB)
            {
                text = QString("%1 MB").arg(bytes / MB, 0, 'f', 2);
            }
            else if (bytes >= KB)
            {
                text = QString("%1 KB").arg(bytes / KB, 0, 'f', 2);
            }
            else
            {
                text = QString("%1 bytes").arg(bytes);
            }
        }

        void StatusBarWidget::formatDuration(double seconds, QString& text)
        {
            int hours = static_cast<int>(seconds) / 3600;
            int minutes = (static_cast<int>(seconds) % 3600) / 60;
            int secs = static_cast<int>(seconds) % 60;
            
            text = QString("%1:%2:%3")
                .arg(hours, 2, 10, QChar('0'))
                .arg(minutes, 2, 10, QChar('0'))
                .arg(secs, 2, 10, QChar('0'));
        }

    } // namespace GUI
} // namespace NetworkSecurity
