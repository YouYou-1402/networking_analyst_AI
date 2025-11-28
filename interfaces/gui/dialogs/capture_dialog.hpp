// src/gui/dialogs/capture_dialog.hpp

#ifndef CAPTURE_DIALOG_HPP
#define CAPTURE_DIALOG_HPP

#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QGroupBox>
#include <QLabel>
#include <QToolButton>
#include <QStringListModel>
#include <QTimer>
#include <vector>

// Include network interface definition
#include "core/layer1/network_interface.hpp"

// Forward declarations
#include <pcap/pcap.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        class CaptureDialog : public QDialog
        {
            Q_OBJECT

        public:
            struct CaptureOptions {
                std::string interface;
                std::string capture_filter;
                bool promiscuous_mode;
                int buffer_size_mb;
                int snapshot_length;
                bool resolve_mac;
                bool resolve_network;
                bool resolve_transport;
                
                // Stop conditions
                bool stop_after_packets;
                uint64_t stop_packet_count;
                bool stop_after_files;
                int stop_file_count;
                bool stop_after_size;
                uint64_t stop_file_size_mb;
                bool stop_after_duration;
                int stop_duration_seconds;
                
                // Output
                std::string output_file;
                bool use_pcapng;
                bool create_new_file;
                int file_switch_interval;
                
                CaptureOptions()
                    : promiscuous_mode(true),
                      buffer_size_mb(2),
                      snapshot_length(65535),
                      resolve_mac(true),
                      resolve_network(true),
                      resolve_transport(true),
                      stop_after_packets(false),
                      stop_packet_count(0),
                      stop_after_files(false),
                      stop_file_count(1),
                      stop_after_size(false),
                      stop_file_size_mb(100),
                      stop_after_duration(false),
                      stop_duration_seconds(0),
                      use_pcapng(true),
                      create_new_file(false),
                      file_switch_interval(0)
                {}
            };

            explicit CaptureDialog(QWidget* parent = nullptr);
            ~CaptureDialog();

            CaptureOptions getOptions() const;
            void setOptions(const CaptureOptions& options);

        private slots:
            void onInterfaceSelected(QListWidgetItem* item);
            void onRefreshInterfaces();
            void onStartCapture();
            void onManageInterfaces();
            void onTestFilter();
            void onBrowseOutputFile();
            void updateInterfaceStats();

        private:
            void setupUI();
            void setupInputTab(QWidget* widget);
            void setupOutputTab(QWidget* widget);
            void setupOptionsTab(QWidget* widget);
            void setupStopConditionsTab(QWidget* widget);
            
            void loadInterfaces();
            void loadSettings();
            void saveSettings();
            
            bool validateOptions();

            // UI Components - Input Tab
            QListWidget* interface_list_;
            QPushButton* refresh_button_;
            QPushButton* manage_button_;
            QLabel* interface_info_label_;
            QLineEdit* capture_filter_edit_;
            QPushButton* test_filter_button_;
            QCheckBox* promiscuous_check_;
            QSpinBox* buffer_size_spin_;
            QSpinBox* snapshot_length_spin_;

            // UI Components - Output Tab
            QLineEdit* output_file_edit_;
            QPushButton* browse_button_;
            QCheckBox* use_pcapng_check_;
            QCheckBox* create_new_file_check_;
            QSpinBox* file_switch_spin_;

            // UI Components - Options Tab
            QCheckBox* resolve_mac_check_;
            QCheckBox* resolve_network_check_;
            QCheckBox* resolve_transport_check_;

            // UI Components - Stop Conditions Tab
            QCheckBox* stop_packets_check_;
            QSpinBox* stop_packets_spin_;
            QCheckBox* stop_files_check_;
            QSpinBox* stop_files_spin_;
            QCheckBox* stop_size_check_;
            QSpinBox* stop_size_spin_;
            QCheckBox* stop_duration_check_;
            QSpinBox* stop_duration_spin_;

            // Buttons
            QPushButton* start_button_;
            QPushButton* cancel_button_;

            // Data
            std::vector<Layer1::NetworkInterface> interfaces_;
            CaptureOptions options_;
            QTimer* stats_timer_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // CAPTURE_DIALOG_HPP
