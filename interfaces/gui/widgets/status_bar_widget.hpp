// src/gui/widgets/status_bar_widget.hpp

#ifndef STATUS_BAR_WIDGET_HPP
#define STATUS_BAR_WIDGET_HPP

#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QHBoxLayout>
#include <QTimer>
#include <atomic>

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Status bar widget (like Wireshark status bar)
         */
        class StatusBarWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit StatusBarWidget(QWidget* parent = nullptr);
            ~StatusBarWidget();

            // ==================== Status Updates ====================
            void setPacketCount(uint64_t total, uint64_t displayed);
            void setMarkedCount(uint64_t marked);
            void setDroppedCount(uint64_t dropped);
            void setCaptureStatus(const QString& status);
            void setFileInfo(const QString& filename, qint64 size);
            void setProfileInfo(const QString& profile);
            
            // ==================== Capture Statistics ====================
            void updateCaptureStats(uint64_t packets, 
                                   uint64_t bytes,
                                   double duration);
            void updateBandwidth(double mbps);
            
            // ==================== Progress ====================
            void showProgress(const QString& message, int maximum = 0);
            void updateProgress(int value);
            void hideProgress();
            
            // ==================== Messages ====================
            void showMessage(const QString& message, int timeout = 3000);
            void showError(const QString& error);
            void showWarning(const QString& warning);
            void clearMessage();

        signals:
            void expertInfoClicked();
            void commentsClicked();

        private slots:
            void onExpertInfoClicked();
            void onCommentsClicked();
            void updateElapsedTime();

        private:
            void setupUI();
            void updatePacketLabel();
            void updateCaptureLabel();
            void formatBytes(uint64_t bytes, QString& text);
            void formatDuration(double seconds, QString& text);

            // UI Components
            QLabel* packet_label_;        // "Packets: 1234 Displayed: 567"
            QLabel* marked_label_;        // "Marked: 10"
            QLabel* dropped_label_;       // "Dropped: 5"
            QLabel* capture_label_;       // "Capturing on eth0"
            QLabel* file_label_;          // "File: capture.pcap (10 MB)"
            QLabel* profile_label_;       // "Profile: Default"
            QLabel* bandwidth_label_;     // "100 Mbps"
            QLabel* time_label_;          // "00:05:23"
            QPushButton* expert_button_;  // Expert Info button
            QPushButton* comments_button_;// Comments button
            QProgressBar* progress_bar_;  // Progress bar
            QLabel* message_label_;       // Temporary messages

            // Data
            std::atomic<uint64_t> total_packets_;
            std::atomic<uint64_t> displayed_packets_;
            std::atomic<uint64_t> marked_packets_;
            std::atomic<uint64_t> dropped_packets_;
            std::atomic<uint64_t> total_bytes_;
            
            double capture_duration_;
            double current_bandwidth_;
            
            QTimer* update_timer_;
            QTimer* message_timer_;
            
            uint64_t capture_start_time_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // STATUS_BAR_WIDGET_HPP
