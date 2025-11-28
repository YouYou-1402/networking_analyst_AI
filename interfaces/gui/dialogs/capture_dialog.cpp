// src/gui/dialogs/capture_dialog.cpp

#include "capture_dialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QTabWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QDateTime>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        CaptureDialog::CaptureDialog(QWidget* parent)
            : QDialog(parent),
              interface_list_(nullptr),
              refresh_button_(nullptr),
              manage_button_(nullptr),
              interface_info_label_(nullptr),
              capture_filter_edit_(nullptr),
              test_filter_button_(nullptr),
              promiscuous_check_(nullptr),
              buffer_size_spin_(nullptr),
              snapshot_length_spin_(nullptr),
              output_file_edit_(nullptr),
              browse_button_(nullptr),
              use_pcapng_check_(nullptr),
              create_new_file_check_(nullptr),
              file_switch_spin_(nullptr),
              resolve_mac_check_(nullptr),
              resolve_network_check_(nullptr),
              resolve_transport_check_(nullptr),
              stop_packets_check_(nullptr),
              stop_packets_spin_(nullptr),
              stop_files_check_(nullptr),
              stop_files_spin_(nullptr),
              stop_size_check_(nullptr),
              stop_size_spin_(nullptr),
              stop_duration_check_(nullptr),
              stop_duration_spin_(nullptr),
              start_button_(nullptr),
              cancel_button_(nullptr),
              stats_timer_(nullptr)
        {
            setWindowTitle(tr("Capture Options"));
            setMinimumSize(800, 600);
            
            setupUI();
            loadInterfaces();
            loadSettings();
            
            // Setup timer for interface stats updates
            stats_timer_ = new QTimer(this);
            connect(stats_timer_, &QTimer::timeout, 
                    this, &CaptureDialog::updateInterfaceStats);
            stats_timer_->start(1000); // Update every second
            
            spdlog::info("Capture dialog created");
        }

        CaptureDialog::~CaptureDialog()
        {
            saveSettings();
            
            if (stats_timer_) {
                stats_timer_->stop();
            }
            
            spdlog::info("Capture dialog destroyed");
        }

        void CaptureDialog::setupUI()
        {
            QVBoxLayout* main_layout = new QVBoxLayout(this);
            
            // Create tab widget
            QTabWidget* tab_widget = new QTabWidget(this);
            
            // Create tabs
            QWidget* input_tab = new QWidget();
            QWidget* output_tab = new QWidget();
            QWidget* options_tab = new QWidget();
            QWidget* stop_tab = new QWidget();
            
            setupInputTab(input_tab);
            setupOutputTab(output_tab);
            setupOptionsTab(options_tab);
            setupStopConditionsTab(stop_tab);
            
            tab_widget->addTab(input_tab, tr("Input"));
            tab_widget->addTab(output_tab, tr("Output"));
            tab_widget->addTab(options_tab, tr("Options"));
            tab_widget->addTab(stop_tab, tr("Stop Conditions"));
            
            main_layout->addWidget(tab_widget);
            
            // Buttons
            QHBoxLayout* button_layout = new QHBoxLayout();
            button_layout->addStretch();
            
            start_button_ = new QPushButton(tr("Start"), this);
            cancel_button_ = new QPushButton(tr("Cancel"), this);
            
            start_button_->setDefault(true);
            
            button_layout->addWidget(start_button_);
            button_layout->addWidget(cancel_button_);
            
            main_layout->addLayout(button_layout);
            
            // Connect buttons
            connect(start_button_, &QPushButton::clicked, 
                    this, &CaptureDialog::onStartCapture);
            connect(cancel_button_, &QPushButton::clicked, 
                    this, &QDialog::reject);
        }

        void CaptureDialog::setupInputTab(QWidget* widget)
        {
            QVBoxLayout* layout = new QVBoxLayout(widget);
            
            // Interface selection
            QGroupBox* interface_group = new QGroupBox(tr("Network Interface"), widget);
            QVBoxLayout* interface_layout = new QVBoxLayout(interface_group);
            
            // Interface list
            interface_list_ = new QListWidget(interface_group);
            interface_layout->addWidget(interface_list_);
            
            // Interface buttons
            QHBoxLayout* iface_button_layout = new QHBoxLayout();
            refresh_button_ = new QPushButton(tr("Refresh"), interface_group);
            manage_button_ = new QPushButton(tr("Manage Interfaces..."), interface_group);
            
            iface_button_layout->addWidget(refresh_button_);
            iface_button_layout->addWidget(manage_button_);
            iface_button_layout->addStretch();
            
            interface_layout->addLayout(iface_button_layout);
            
            // Interface info
            interface_info_label_ = new QLabel(tr("Select an interface"), interface_group);
            interface_info_label_->setTextFormat(Qt::RichText);
            interface_info_label_->setWordWrap(true);
            interface_info_label_->setFrameStyle(QFrame::Panel | QFrame::Sunken);
            interface_info_label_->setMinimumHeight(100);
            interface_layout->addWidget(interface_info_label_);
            
            layout->addWidget(interface_group);
            
            // Capture filter
            QGroupBox* filter_group = new QGroupBox(tr("Capture Filter"), widget);
            QVBoxLayout* filter_layout = new QVBoxLayout(filter_group);
            
            QHBoxLayout* filter_edit_layout = new QHBoxLayout();
            capture_filter_edit_ = new QLineEdit(filter_group);
            capture_filter_edit_->setPlaceholderText(tr("Enter BPF filter (e.g., tcp port 80)"));
            test_filter_button_ = new QPushButton(tr("Test"), filter_group);
            
            filter_edit_layout->addWidget(capture_filter_edit_);
            filter_edit_layout->addWidget(test_filter_button_);
            
            filter_layout->addLayout(filter_edit_layout);
            layout->addWidget(filter_group);
            
            // Capture options
            QGroupBox* capture_group = new QGroupBox(tr("Capture Options"), widget);
            QFormLayout* capture_form = new QFormLayout(capture_group);
            
            promiscuous_check_ = new QCheckBox(tr("Capture packets in promiscuous mode"), capture_group);
            promiscuous_check_->setChecked(true);
            capture_form->addRow(promiscuous_check_);
            
            buffer_size_spin_ = new QSpinBox(capture_group);
            buffer_size_spin_->setRange(1, 100);
            buffer_size_spin_->setValue(2);
            buffer_size_spin_->setSuffix(tr(" MB"));
            capture_form->addRow(tr("Buffer size:"), buffer_size_spin_);
            
            snapshot_length_spin_ = new QSpinBox(capture_group);
            snapshot_length_spin_->setRange(68, 65535);
            snapshot_length_spin_->setValue(65535);
            snapshot_length_spin_->setSuffix(tr(" bytes"));
            capture_form->addRow(tr("Snapshot length:"), snapshot_length_spin_);
            
            layout->addWidget(capture_group);
            layout->addStretch();
            
            // Connect signals
            connect(interface_list_, &QListWidget::currentItemChanged,
                    this, &CaptureDialog::onInterfaceSelected);
            connect(refresh_button_, &QPushButton::clicked,
                    this, &CaptureDialog::onRefreshInterfaces);
            connect(manage_button_, &QPushButton::clicked,
                    this, &CaptureDialog::onManageInterfaces);
            connect(test_filter_button_, &QPushButton::clicked,
                    this, &CaptureDialog::onTestFilter);
        }

        void CaptureDialog::setupOutputTab(QWidget* widget)
        {
            QVBoxLayout* layout = new QVBoxLayout(widget);
            
            QGroupBox* output_group = new QGroupBox(tr("Output File"), widget);
            QVBoxLayout* output_layout = new QVBoxLayout(output_group);
            
            QHBoxLayout* file_layout = new QHBoxLayout();
            output_file_edit_ = new QLineEdit(output_group);
            browse_button_ = new QPushButton(tr("Browse..."), output_group);
            
            file_layout->addWidget(output_file_edit_);
            file_layout->addWidget(browse_button_);
            
            output_layout->addLayout(file_layout);
            
            use_pcapng_check_ = new QCheckBox(tr("Use pcapng format"), output_group);
            use_pcapng_check_->setChecked(true);
            output_layout->addWidget(use_pcapng_check_);
            
            create_new_file_check_ = new QCheckBox(tr("Create a new file automatically"), output_group);
            output_layout->addWidget(create_new_file_check_);
            
            QFormLayout* file_form = new QFormLayout();
            file_switch_spin_ = new QSpinBox(output_group);
            file_switch_spin_->setRange(0, 3600);
            file_switch_spin_->setValue(0);
            file_switch_spin_->setSuffix(tr(" seconds"));
            file_switch_spin_->setEnabled(false);
            file_form->addRow(tr("Switch interval:"), file_switch_spin_);
            
            output_layout->addLayout(file_form);
            layout->addWidget(output_group);
            layout->addStretch();
            
            connect(browse_button_, &QPushButton::clicked,
                    this, &CaptureDialog::onBrowseOutputFile);
            connect(create_new_file_check_, &QCheckBox::toggled,
                    file_switch_spin_, &QSpinBox::setEnabled);
        }

        void CaptureDialog::setupOptionsTab(QWidget* widget)
        {
            QVBoxLayout* layout = new QVBoxLayout(widget);
            
            QGroupBox* resolve_group = new QGroupBox(tr("Name Resolution"), widget);
            QVBoxLayout* resolve_layout = new QVBoxLayout(resolve_group);
            
            resolve_mac_check_ = new QCheckBox(tr("Resolve MAC addresses"), resolve_group);
            resolve_mac_check_->setChecked(true);
            resolve_layout->addWidget(resolve_mac_check_);
            
            resolve_network_check_ = new QCheckBox(tr("Resolve network addresses"), resolve_group);
            resolve_network_check_->setChecked(true);
            resolve_layout->addWidget(resolve_network_check_);
            
            resolve_transport_check_ = new QCheckBox(tr("Resolve transport names"), resolve_group);
            resolve_transport_check_->setChecked(true);
            resolve_layout->addWidget(resolve_transport_check_);
            
            layout->addWidget(resolve_group);
            layout->addStretch();
        }

        void CaptureDialog::setupStopConditionsTab(QWidget* widget)
        {
            QVBoxLayout* layout = new QVBoxLayout(widget);
            
            QGroupBox* stop_group = new QGroupBox(tr("Stop Capture Automatically"), widget);
            QFormLayout* stop_form = new QFormLayout(stop_group);
            
            // Packets
            QHBoxLayout* packets_layout = new QHBoxLayout();
            stop_packets_check_ = new QCheckBox(stop_group);
            stop_packets_spin_ = new QSpinBox(stop_group);
            stop_packets_spin_->setRange(1, 1000000000);
            stop_packets_spin_->setValue(1000);
            stop_packets_spin_->setEnabled(false);
            packets_layout->addWidget(stop_packets_check_);
            packets_layout->addWidget(new QLabel(tr("after")));
            packets_layout->addWidget(stop_packets_spin_);
            packets_layout->addWidget(new QLabel(tr("packets")));
            packets_layout->addStretch();
            stop_form->addRow(tr("Packets:"), packets_layout);
            
            // Files
            QHBoxLayout* files_layout = new QHBoxLayout();
            stop_files_check_ = new QCheckBox(stop_group);
            stop_files_spin_ = new QSpinBox(stop_group);
            stop_files_spin_->setRange(1, 1000);
            stop_files_spin_->setValue(1);
            stop_files_spin_->setEnabled(false);
            files_layout->addWidget(stop_files_check_);
            files_layout->addWidget(new QLabel(tr("after")));
            files_layout->addWidget(stop_files_spin_);
            files_layout->addWidget(new QLabel(tr("files")));
            files_layout->addStretch();
            stop_form->addRow(tr("Files:"), files_layout);
            
            // Size
            QHBoxLayout* size_layout = new QHBoxLayout();
            stop_size_check_ = new QCheckBox(stop_group);
            stop_size_spin_ = new QSpinBox(stop_group);
            stop_size_spin_->setRange(1, 10000);
            stop_size_spin_->setValue(100);
            stop_size_spin_->setSuffix(tr(" MB"));
            stop_size_spin_->setEnabled(false);
            size_layout->addWidget(stop_size_check_);
            size_layout->addWidget(new QLabel(tr("after")));
            size_layout->addWidget(stop_size_spin_);
            size_layout->addStretch();
            stop_form->addRow(tr("File size:"), size_layout);
            
            // Duration
            QHBoxLayout* duration_layout = new QHBoxLayout();
            stop_duration_check_ = new QCheckBox(stop_group);
            stop_duration_spin_ = new QSpinBox(stop_group);
            stop_duration_spin_->setRange(1, 86400);
            stop_duration_spin_->setValue(60);
            stop_duration_spin_->setSuffix(tr(" seconds"));
            stop_duration_spin_->setEnabled(false);
            duration_layout->addWidget(stop_duration_check_);
            duration_layout->addWidget(new QLabel(tr("after")));
            duration_layout->addWidget(stop_duration_spin_);
            duration_layout->addStretch();
            stop_form->addRow(tr("Duration:"), duration_layout);
            
            layout->addWidget(stop_group);
            layout->addStretch();
            
            // Connect checkboxes to enable/disable spinboxes
            connect(stop_packets_check_, &QCheckBox::toggled,
                    stop_packets_spin_, &QSpinBox::setEnabled);
            connect(stop_files_check_, &QCheckBox::toggled,
                    stop_files_spin_, &QSpinBox::setEnabled);
            connect(stop_size_check_, &QCheckBox::toggled,
                    stop_size_spin_, &QSpinBox::setEnabled);
            connect(stop_duration_check_, &QCheckBox::toggled,
                    stop_duration_spin_, &QSpinBox::setEnabled);
        }

        CaptureDialog::CaptureOptions CaptureDialog::getOptions() const
        {
            return options_;
        }

        void CaptureDialog::setOptions(const CaptureOptions& options)
        {
            options_ = options;
            
            // Update UI with options
            capture_filter_edit_->setText(QString::fromStdString(options.capture_filter));
            promiscuous_check_->setChecked(options.promiscuous_mode);
            buffer_size_spin_->setValue(options.buffer_size_mb);
            snapshot_length_spin_->setValue(options.snapshot_length);
            
            output_file_edit_->setText(QString::fromStdString(options.output_file));
            use_pcapng_check_->setChecked(options.use_pcapng);
            create_new_file_check_->setChecked(options.create_new_file);
            file_switch_spin_->setValue(options.file_switch_interval);
            
            resolve_mac_check_->setChecked(options.resolve_mac);
            resolve_network_check_->setChecked(options.resolve_network);
            resolve_transport_check_->setChecked(options.resolve_transport);
            
            stop_packets_check_->setChecked(options.stop_after_packets);
            stop_packets_spin_->setValue(options.stop_packet_count);
            stop_files_check_->setChecked(options.stop_after_files);
            stop_files_spin_->setValue(options.stop_file_count);
            stop_size_check_->setChecked(options.stop_after_size);
            stop_size_spin_->setValue(options.stop_file_size_mb);
            stop_duration_check_->setChecked(options.stop_after_duration);
            stop_duration_spin_->setValue(options.stop_duration_seconds);
        }

        void CaptureDialog::loadSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            settings.beginGroup("Capture");
            
            // Load last used settings
            options_.promiscuous_mode = settings.value("promiscuous", true).toBool();
            options_.buffer_size_mb = settings.value("buffer_size", 2).toInt();
            options_.snapshot_length = settings.value("snapshot_length", 65535).toInt();
            options_.resolve_mac = settings.value("resolve_mac", true).toBool();
            options_.resolve_network = settings.value("resolve_network", true).toBool();
            options_.resolve_transport = settings.value("resolve_transport", true).toBool();
            
            settings.endGroup();
            
            setOptions(options_);
        }

        void CaptureDialog::saveSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            settings.beginGroup("Capture");
            
            settings.setValue("promiscuous", options_.promiscuous_mode);
            settings.setValue("buffer_size", options_.buffer_size_mb);
            settings.setValue("snapshot_length", options_.snapshot_length);
            settings.setValue("resolve_mac", options_.resolve_mac);
            settings.setValue("resolve_network", options_.resolve_network);
            settings.setValue("resolve_transport", options_.resolve_transport);
            
            settings.endGroup();
        }

        void CaptureDialog::loadInterfaces()
        {
            interface_list_->clear();
            interfaces_.clear();

            try {
                // Get available interfaces using pcap
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_if_t* alldevs;
                
                if (pcap_findalldevs(&alldevs, errbuf) == -1) {
                    throw std::runtime_error(std::string("Error finding devices: ") + errbuf);
                }

                // Convert to our interface structure
                for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
                    Layer1::NetworkInterface iface;
                    
                    // Basic info
                    iface.name = dev->name;
                    iface.description = dev->description ? dev->description : dev->name;
                    
                    // Flags
                    iface.is_up = (dev->flags & PCAP_IF_UP) != 0;
                    iface.is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
                    iface.is_wireless = (dev->flags & PCAP_IF_WIRELESS) != 0;

                    // Get addresses
                    for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
                        if (addr->addr) {
                            if (addr->addr->sa_family == AF_INET) {
                                // IPv4
                                char ip_str[INET_ADDRSTRLEN];
                                struct sockaddr_in* sa = (struct sockaddr_in*)addr->addr;
                                inet_ntop(AF_INET, &(sa->sin_addr), ip_str, INET_ADDRSTRLEN);
                                iface.addresses.push_back(std::string(ip_str));
                            }
                            else if (addr->addr->sa_family == AF_INET6) {
                                // IPv6
                                char ip_str[INET6_ADDRSTRLEN];
                                struct sockaddr_in6* sa = (struct sockaddr_in6*)addr->addr;
                                inet_ntop(AF_INET6, &(sa->sin6_addr), ip_str, INET6_ADDRSTRLEN);
                                iface.addresses.push_back(std::string(ip_str));
                            }
                        }
                    }

                    interfaces_.push_back(iface);

                    // Add to list widget
                    QString item_text;
                    if (iface.description != iface.name) {
                        item_text = QString("%1 (%2)")
                            .arg(QString::fromStdString(iface.name))
                            .arg(QString::fromStdString(iface.description));
                    } else {
                        item_text = QString::fromStdString(iface.name);
                    }

                    QListWidgetItem* item = new QListWidgetItem(item_text);
                    item->setData(Qt::UserRole, QString::fromStdString(iface.name));
                    
                    // Set icon based on interface type
                    if (iface.is_loopback) {
                        item->setIcon(QIcon::fromTheme("network-wired", 
                                                      QIcon(":/icons/network-loopback.png")));
                    } else if (iface.is_wireless) {
                        item->setIcon(QIcon::fromTheme("network-wireless", 
                                                      QIcon(":/icons/network-wireless.png")));
                    } else if (iface.is_up) {
                        item->setIcon(QIcon::fromTheme("network-wired", 
                                                      QIcon(":/icons/network-wired.png")));
                    } else {
                        item->setIcon(QIcon::fromTheme("network-offline", 
                                                      QIcon(":/icons/network-offline.png")));
                    }

                    // Set tooltip
                    QString tooltip = QString(
                        "Name: %1\n"
                        "Status: %2\n"
                        "Type: %3"
                    ).arg(QString::fromStdString(iface.name))
                     .arg(iface.is_up ? "Up" : "Down")
                     .arg(iface.is_loopback ? "Loopback" : 
                          (iface.is_wireless ? "Wireless" : "Wired"));
                    item->setToolTip(tooltip);

                    interface_list_->addItem(item);
                }

                pcap_freealldevs(alldevs);

                if (!interfaces_.empty()) {
                    interface_list_->setCurrentRow(0);
                    onInterfaceSelected(interface_list_->item(0));
                }

                spdlog::info("Loaded {} network interfaces", interfaces_.size());
            }
            catch (const std::exception& e) {
                spdlog::error("Failed to load interfaces: {}", e.what());
                QMessageBox::critical(this, tr("Error"),
                    tr("Failed to load network interfaces:\n%1\n\n"
                       "Make sure you have:\n"
                       "• libpcap installed\n"
                       "• Proper permissions (run as root/admin)\n"
                       "• Network interfaces available")
                    .arg(e.what()));
            }
        }

        void CaptureDialog::onInterfaceSelected(QListWidgetItem* item)
        {
            if (!item) {
                return;
            }

            QString iface_name = item->data(Qt::UserRole).toString();
            
            // Find interface info
            for (const auto& iface : interfaces_) {
                if (QString::fromStdString(iface.name) == iface_name) {
                    
                    // Format addresses
                    QString addresses_str = "None";
                    if (!iface.addresses.empty()) {
                        QStringList addr_list;
                        for (const auto& addr : iface.addresses) {
                            addr_list << QString::fromStdString(addr);
                        }
                        addresses_str = addr_list.join(", ");
                    }

                    // Format status with color
                    QString status_str = iface.is_up ? 
                        "<span style='color: green; font-weight: bold;'>Up</span>" : 
                        "<span style='color: red; font-weight: bold;'>Down</span>";

                    // Format interface type
                    QString type_str;
                    if (iface.is_loopback) {
                        type_str = "Loopback";
                    } else if (iface.is_wireless) {
                        type_str = "Wireless";
                    } else {
                        type_str = "Wired";
                    }

                    // Build info HTML
                    QString info = QString(
                        "<table cellpadding='3'>"
                        "<tr><td><b>Name:</b></td><td>%1</td></tr>"
                        "<tr><td><b>Description:</b></td><td>%2</td></tr>"
                        "<tr><td><b>Type:</b></td><td>%3</td></tr>"
                        "<tr><td><b>Status:</b></td><td>%4</td></tr>"
                        "<tr><td><b>Addresses:</b></td><td>%5</td></tr>"
                        "</table>"
                    ).arg(QString::fromStdString(iface.name))
                     .arg(QString::fromStdString(iface.description))
                     .arg(type_str)
                     .arg(status_str)
                     .arg(addresses_str);

                    // Add warning if interface is down
                    if (!iface.is_up) {
                        info += "<br><span style='color: orange;'>"
                               "⚠ Warning: This interface is currently down. "
                               "Capture may not work.</span>";
                    }

                    // Add note for loopback
                    if (iface.is_loopback) {
                        info += "<br><span style='color: blue;'>"
                               "ℹ Note: Loopback interface captures local traffic only.</span>";
                    }

                    interface_info_label_->setText(info);
                    
                    spdlog::debug("Selected interface: {} ({})", 
                                 iface.name, 
                                 iface.is_up ? "up" : "down");
                    
                    break;
                }
            }
        }

        void CaptureDialog::onRefreshInterfaces()
        {
            spdlog::info("Refreshing interface list...");
            loadInterfaces();
            
            QMessageBox::information(this, tr("Interfaces Refreshed"),
                tr("Network interface list has been refreshed.\n"
                   "Found %1 interface(s).")
                .arg(interfaces_.size()));
        }

        void CaptureDialog::onStartCapture()
        {
            if (validateOptions()) {
                spdlog::info("Starting capture on interface: {}", options_.interface);
                accept();
            }
        }

        void CaptureDialog::onManageInterfaces()
        {
            QString help_text = tr(
                "<h3>Managing Network Interfaces</h3>"
                "<p><b>To configure network interfaces:</b></p>"
                "<ul>"
                "<li><b>Linux:</b> Use <code>ip</code> or <code>ifconfig</code> commands</li>"
                "<li><b>Windows:</b> Use Network Connections in Control Panel</li>"
                "<li><b>macOS:</b> Use System Preferences → Network</li>"
                "</ul>"
                "<p><b>Common issues:</b></p>"
                "<ul>"
                "<li>Interface is down: Bring it up with <code>ip link set &lt;interface&gt; up</code></li>"
                "<li>No permissions: Run application with sudo/administrator rights</li>"
                "<li>No interfaces visible: Install libpcap/WinPcap/Npcap</li>"
                "</ul>"
                "<p><b>Click Refresh to update the interface list.</b></p>"
            );

            QMessageBox msg(this);
            msg.setWindowTitle(tr("Manage Interfaces"));
            msg.setTextFormat(Qt::RichText);
            msg.setText(help_text);
            msg.setIcon(QMessageBox::Information);
            msg.exec();
        }

        void CaptureDialog::onTestFilter()
        {
            QString filter = capture_filter_edit_->text().trimmed();
            
            if (filter.isEmpty()) {
                QMessageBox::information(this, tr("Test Filter"),
                    tr("No filter specified.\n\n"
                       "All packets will be captured without filtering."));
                return;
            }

            // Test BPF filter compilation
            struct bpf_program fp;
            char errbuf[PCAP_ERRBUF_SIZE];
            
            // Use pcap_open_dead to create a handle for filter compilation
            pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65535);
            
            if (!handle) {
                QMessageBox::critical(this, tr("Error"),
                    tr("Failed to create test handle."));
                return;
            }
            
            int result = pcap_compile(handle, &fp, filter.toStdString().c_str(), 
                                     1, PCAP_NETMASK_UNKNOWN);
            
            if (result == -1) {
                QString error = QString::fromUtf8(pcap_geterr(handle));
                pcap_close(handle);
                
                QMessageBox::critical(this, tr("Invalid Filter"),
                    tr("<b>Filter syntax error:</b><br><br>"
                       "<code>%1</code><br><br>"
                       "<b>Error:</b> %2<br><br>"
                       "<b>Examples of valid filters:</b><br>"
                       "• <code>tcp port 80</code><br>"
                       "• <code>host 192.168.1.1</code><br>"
                       "• <code>not arp and not icmp</code><br>"
                       "• <code>tcp[tcpflags] & tcp-syn != 0</code>")
                    .arg(filter)
                    .arg(error));
                return;
            }

            pcap_freecode(&fp);
            pcap_close(handle);

            QMessageBox::information(this, tr("Valid Filter"),
                tr("<b>Filter syntax is valid!</b><br><br>"
                   "<code>%1</code><br><br>"
                   "This filter will be applied during capture.")
                .arg(filter));
            
            spdlog::info("Filter validated: {}", filter.toStdString());
        }

        void CaptureDialog::onBrowseOutputFile()
        {
            QString default_name = QString("capture_%1.pcap")
                .arg(QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss"));

            QString filename = QFileDialog::getSaveFileName(
                this,
                tr("Select Output File"),
                default_name,
                tr("PCAP Files (*.pcap);;PCAPNG Files (*.pcapng);;All Files (*)")
            );

            if (!filename.isEmpty()) {
                output_file_edit_->setText(filename);
                spdlog::debug("Output file selected: {}", filename.toStdString());
            }
        }

        void CaptureDialog::updateInterfaceStats()
        {
            // TODO: Update real-time interface statistics
            // This could show:
            // - Current packet rate
            // - Current bandwidth usage
            // - Interface errors/drops
            // - Link status changes
        }

        bool CaptureDialog::validateOptions()
        {
            // Check if interface is selected
            if (interface_list_->selectedItems().isEmpty()) {
                QMessageBox::warning(this, tr("No Interface Selected"),
                    tr("Please select a network interface to capture from."));
                return false;
            }

            // Get selected interface
            QListWidgetItem* item = interface_list_->currentItem();
            QString iface_name = item->data(Qt::UserRole).toString();
            
            // Check if interface is up
            for (const auto& iface : interfaces_) {
                if (QString::fromStdString(iface.name) == iface_name) {
                    if (!iface.is_up) {
                        QMessageBox::StandardButton reply = QMessageBox::warning(
                            this, 
                            tr("Interface Down"),
                            tr("The selected interface '%1' is currently down.\n\n"
                               "Capture may not work properly.\n\n"
                               "Do you want to continue anyway?")
                            .arg(iface_name),
                            QMessageBox::Yes | QMessageBox::No
                        );
                        
                        if (reply == QMessageBox::No) {
                            return false;
                        }
                    }
                    break;
                }
            }

            options_.interface = iface_name.toStdString();

            // Get other options
            options_.capture_filter = capture_filter_edit_->text().trimmed().toStdString();
            options_.promiscuous_mode = promiscuous_check_->isChecked();
            options_.buffer_size_mb = buffer_size_spin_->value();
            options_.snapshot_length = snapshot_length_spin_->value();

            options_.output_file = output_file_edit_->text().trimmed().toStdString();
            options_.use_pcapng = use_pcapng_check_->isChecked();
            options_.create_new_file = create_new_file_check_->isChecked();
            options_.file_switch_interval = file_switch_spin_->value();

            options_.resolve_mac = resolve_mac_check_->isChecked();
            options_.resolve_network = resolve_network_check_->isChecked();
            options_.resolve_transport = resolve_transport_check_->isChecked();

            options_.stop_after_packets = stop_packets_check_->isChecked();
            options_.stop_packet_count = stop_packets_spin_->value();
            options_.stop_after_files = stop_files_check_->isChecked();
            options_.stop_file_count = stop_files_spin_->value();
            options_.stop_after_size = stop_size_check_->isChecked();
            options_.stop_file_size_mb = stop_size_spin_->value();
            options_.stop_after_duration = stop_duration_check_->isChecked();
            options_.stop_duration_seconds = stop_duration_spin_->value();

            return true;
        }

    } // namespace GUI
} // namespace NetworkSecurity
