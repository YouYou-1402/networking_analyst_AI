// src/gui/dialogs/preferences_dialog.cpp

#include "preferences_dialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QMessageBox>
#include <QColorDialog>
#include <QFileDialog>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        PreferencesDialog::PreferencesDialog(QWidget* parent)
            : QDialog(parent),
              settings_("NetworkSecurity", "Analyzer"),
              settings_changed_(false)
        {
            setupUI();
            setupCategories();
            loadSettings();

            setWindowTitle(tr("Preferences"));
            resize(800, 600);
        }

        PreferencesDialog::~PreferencesDialog()
        {
        }

        // ==================== UI Setup ====================

        void PreferencesDialog::setupUI()
        {
            QHBoxLayout* main_layout = new QHBoxLayout(this);

            // Left side - Category tree
            category_tree_ = new QTreeWidget(this);
            category_tree_->setHeaderHidden(true);
            category_tree_->setMaximumWidth(200);
            category_tree_->setMinimumWidth(150);
            main_layout->addWidget(category_tree_);

            // Right side - Pages
            QVBoxLayout* right_layout = new QVBoxLayout();

            pages_stack_ = new QStackedWidget(this);
            right_layout->addWidget(pages_stack_);

            // Buttons
            QHBoxLayout* button_layout = new QHBoxLayout();
            button_layout->addStretch();

            defaults_button_ = new QPushButton(tr("Restore Defaults"), this);
            connect(defaults_button_, &QPushButton::clicked, this, &PreferencesDialog::onRestoreDefaults);
            button_layout->addWidget(defaults_button_);

            apply_button_ = new QPushButton(tr("Apply"), this);
            connect(apply_button_, &QPushButton::clicked, this, &PreferencesDialog::onApply);
            button_layout->addWidget(apply_button_);

            ok_button_ = new QPushButton(tr("OK"), this);
            ok_button_->setDefault(true);
            connect(ok_button_, &QPushButton::clicked, this, &PreferencesDialog::onOK);
            button_layout->addWidget(ok_button_);

            cancel_button_ = new QPushButton(tr("Cancel"), this);
            connect(cancel_button_, &QPushButton::clicked, this, &PreferencesDialog::onCancel);
            button_layout->addWidget(cancel_button_);

            right_layout->addLayout(button_layout);

            main_layout->addLayout(right_layout, 1);

            // Connect category selection
            connect(category_tree_, &QTreeWidget::itemClicked,
                    this, &PreferencesDialog::onCategorySelected);
        }

        void PreferencesDialog::setupCategories()
        {
            // Create category items
            QTreeWidgetItem* appearance = new QTreeWidgetItem(category_tree_);
            appearance->setText(0, tr("Appearance"));
            appearance->setIcon(0, QIcon::fromTheme("preferences-desktop-theme"));
            pages_stack_->addWidget(createAppearancePage());

            QTreeWidgetItem* capture = new QTreeWidgetItem(category_tree_);
            capture->setText(0, tr("Capture"));
            capture->setIcon(0, QIcon::fromTheme("media-record"));
            pages_stack_->addWidget(createCapturePage());

            QTreeWidgetItem* display = new QTreeWidgetItem(category_tree_);
            display->setText(0, tr("Display"));
            display->setIcon(0, QIcon::fromTheme("video-display"));
            pages_stack_->addWidget(createDisplayPage());

            QTreeWidgetItem* filter = new QTreeWidgetItem(category_tree_);
            filter->setText(0, tr("Filter"));
            filter->setIcon(0, QIcon::fromTheme("view-filter"));
            pages_stack_->addWidget(createFilterPage());

            QTreeWidgetItem* name_resolution = new QTreeWidgetItem(category_tree_);
            name_resolution->setText(0, tr("Name Resolution"));
            name_resolution->setIcon(0, QIcon::fromTheme("network-server"));
            pages_stack_->addWidget(createNameResolutionPage());

            QTreeWidgetItem* protocols = new QTreeWidgetItem(category_tree_);
            protocols->setText(0, tr("Protocols"));
            protocols->setIcon(0, QIcon::fromTheme("network-wired"));
            pages_stack_->addWidget(createProtocolsPage());

            QTreeWidgetItem* statistics = new QTreeWidgetItem(category_tree_);
            statistics->setText(0, tr("Statistics"));
            statistics->setIcon(0, QIcon::fromTheme("office-chart-bar"));
            pages_stack_->addWidget(createStatisticsPage());

            QTreeWidgetItem* advanced = new QTreeWidgetItem(category_tree_);
            advanced->setText(0, tr("Advanced"));
            advanced->setIcon(0, QIcon::fromTheme("preferences-system"));
            pages_stack_->addWidget(createAdvancedPage());

            // Select first item
            category_tree_->setCurrentItem(appearance);
            pages_stack_->setCurrentIndex(0);
        }

        // ==================== Category Pages ====================

        QWidget* PreferencesDialog::createAppearancePage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Font settings
            QGroupBox* font_group = new QGroupBox(tr("Font"), page);
            QFormLayout* font_layout = new QFormLayout(font_group);

            font_combo_ = new QFontComboBox(font_group);
            connect(font_combo_, &QFontComboBox::currentFontChanged,
                    this, &PreferencesDialog::onFontChanged);
            font_layout->addRow(tr("Font family:"), font_combo_);

            font_size_spin_ = new QSpinBox(font_group);
            font_size_spin_->setRange(6, 24);
            font_size_spin_->setValue(10);
            font_layout->addRow(tr("Font size:"), font_size_spin_);

            layout->addWidget(font_group);

            // Theme settings
            QGroupBox* theme_group = new QGroupBox(tr("Theme"), page);
            QFormLayout* theme_layout = new QFormLayout(theme_group);

            theme_combo_ = new QComboBox(theme_group);
            theme_combo_->addItems({"System", "Light", "Dark"});
            connect(theme_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this, &PreferencesDialog::onThemeChanged);
            theme_layout->addRow(tr("Theme:"), theme_combo_);

            color_scheme_combo_ = new QComboBox(theme_group);
            color_scheme_combo_->addItems({"Default", "High Contrast", "Custom"});
            connect(color_scheme_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this, &PreferencesDialog::onColorSchemeChanged);
            theme_layout->addRow(tr("Color scheme:"), color_scheme_combo_);

            layout->addWidget(theme_group);

            // Color settings
            QGroupBox* color_group = new QGroupBox(tr("Colors"), page);
            QFormLayout* color_layout = new QFormLayout(color_group);

            fg_color_button_ = new QPushButton(tr("Choose..."), color_group);
            fg_color_button_->setAutoFillBackground(true);
            color_layout->addRow(tr("Foreground:"), fg_color_button_);

            bg_color_button_ = new QPushButton(tr("Choose..."), color_group);
            bg_color_button_->setAutoFillBackground(true);
            color_layout->addRow(tr("Background:"), bg_color_button_);

            selection_color_button_ = new QPushButton(tr("Choose..."), color_group);
            selection_color_button_->setAutoFillBackground(true);
            color_layout->addRow(tr("Selection:"), selection_color_button_);

            // Connect color buttons
            connect(fg_color_button_, &QPushButton::clicked, [this]() {
                QColor color = QColorDialog::getColor(Qt::black, this, tr("Select Foreground Color"));
                if (color.isValid()) {
                    QString style = QString("background-color: %1").arg(color.name());
                    fg_color_button_->setStyleSheet(style);
                    settings_changed_ = true;
                }
            });

            connect(bg_color_button_, &QPushButton::clicked, [this]() {
                QColor color = QColorDialog::getColor(Qt::white, this, tr("Select Background Color"));
                if (color.isValid()) {
                    QString style = QString("background-color: %1").arg(color.name());
                    bg_color_button_->setStyleSheet(style);
                    settings_changed_ = true;
                }
            });

            connect(selection_color_button_, &QPushButton::clicked, [this]() {
                QColor color = QColorDialog::getColor(Qt::blue, this, tr("Select Selection Color"));
                if (color.isValid()) {
                    QString style = QString("background-color: %1").arg(color.name());
                    selection_color_button_->setStyleSheet(style);
                    settings_changed_ = true;
                }
            });

            layout->addWidget(color_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createCapturePage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Default interface
            QGroupBox* interface_group = new QGroupBox(tr("Default Interface"), page);
            QFormLayout* interface_layout = new QFormLayout(interface_group);

            default_interface_combo_ = new QComboBox(interface_group);
            // TODO: Populate with available interfaces
            default_interface_combo_->addItem(tr("(Auto-detect)"));
            connect(default_interface_combo_, &QComboBox::currentTextChanged,
                    this, &PreferencesDialog::onDefaultInterfaceChanged);
            interface_layout->addRow(tr("Interface:"), default_interface_combo_);

            layout->addWidget(interface_group);

            // Capture options
            QGroupBox* options_group = new QGroupBox(tr("Capture Options"), page);
            QVBoxLayout* options_layout = new QVBoxLayout(options_group);

            promiscuous_check_ = new QCheckBox(tr("Enable promiscuous mode by default"), options_group);
            promiscuous_check_->setChecked(true);
            connect(promiscuous_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onPromiscuousModeChanged);
            options_layout->addWidget(promiscuous_check_);

            QFormLayout* buffer_layout = new QFormLayout();
            buffer_size_spin_ = new QSpinBox(options_group);
            buffer_size_spin_->setRange(1, 100);
            buffer_size_spin_->setValue(2);
            buffer_size_spin_->setSuffix(" MB");
            buffer_layout->addRow(tr("Buffer size:"), buffer_size_spin_);
            options_layout->addLayout(buffer_layout);

            layout->addWidget(options_group);

            // Update options
            QGroupBox* update_group = new QGroupBox(tr("Update Options"), page);
            QVBoxLayout* update_layout = new QVBoxLayout(update_group);

            update_list_check_ = new QCheckBox(tr("Update packet list in real time"), update_group);
            update_list_check_->setChecked(true);
            update_layout->addWidget(update_list_check_);

            QFormLayout* interval_layout = new QFormLayout();
            update_interval_spin_ = new QSpinBox(update_group);
            update_interval_spin_->setRange(10, 10000);
            update_interval_spin_->setValue(100);
            update_interval_spin_->setSuffix(" ms");
            interval_layout->addRow(tr("Update interval:"), update_interval_spin_);
            update_layout->addLayout(interval_layout);

            layout->addWidget(update_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createDisplayPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Time display
            QGroupBox* time_group = new QGroupBox(tr("Time Display"), page);
            QFormLayout* time_layout = new QFormLayout(time_group);

            time_format_combo_ = new QComboBox(time_group);
            time_format_combo_->addItems({
                tr("Absolute"),
                tr("Relative"),
                tr("Delta"),
                tr("Epoch")
            });
            connect(time_format_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
                    this, &PreferencesDialog::onTimeFormatChanged);
            time_layout->addRow(tr("Time format:"), time_format_combo_);

            layout->addWidget(time_group);

            // Display options
            QGroupBox* display_group = new QGroupBox(tr("Display Options"), page);
            QVBoxLayout* display_layout = new QVBoxLayout(display_group);

            auto_scroll_check_ = new QCheckBox(tr("Auto scroll packet list"), display_group);
            auto_scroll_check_->setChecked(true);
            connect(auto_scroll_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onAutoScrollChanged);
            display_layout->addWidget(auto_scroll_check_);

            show_hex_check_ = new QCheckBox(tr("Show hex dump by default"), display_group);
            show_hex_check_->setChecked(true);
            connect(show_hex_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onShowHexChanged);
            display_layout->addWidget(show_hex_check_);

            colorize_check_ = new QCheckBox(tr("Colorize packet list"), display_group);
            colorize_check_->setChecked(true);
            display_layout->addWidget(colorize_check_);

            QFormLayout* packets_layout = new QFormLayout();
            max_packets_spin_ = new QSpinBox(display_group);
            max_packets_spin_->setRange(1000, 10000000);
            max_packets_spin_->setValue(1000000);
            packets_layout->addRow(tr("Maximum packets in memory:"), max_packets_spin_);
            display_layout->addLayout(packets_layout);

            layout->addWidget(display_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createFilterPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Filter options
            QGroupBox* filter_group = new QGroupBox(tr("Filter Options"), page);
            QVBoxLayout* filter_layout = new QVBoxLayout(filter_group);

            save_filters_check_ = new QCheckBox(tr("Save filter history"), filter_group);
            save_filters_check_->setChecked(true);
            filter_layout->addWidget(save_filters_check_);

            auto_complete_check_ = new QCheckBox(tr("Enable filter auto-completion"), filter_group);
            auto_complete_check_->setChecked(true);
            filter_layout->addWidget(auto_complete_check_);

            QFormLayout* max_filters_layout = new QFormLayout();
            max_filters_spin_ = new QSpinBox(filter_group);
            max_filters_spin_->setRange(10, 1000);
            max_filters_spin_->setValue(50);
            max_filters_layout->addRow(tr("Maximum filter history:"), max_filters_spin_);
            filter_layout->addLayout(max_filters_layout);

            layout->addWidget(filter_group);

            // Filter bookmarks
            QGroupBox* bookmarks_group = new QGroupBox(tr("Filter Bookmarks"), page);
            QVBoxLayout* bookmarks_layout = new QVBoxLayout(bookmarks_group);

            QLabel* bookmarks_label = new QLabel(
                tr("Manage your saved filter bookmarks.\n"
                   "Bookmarks can be accessed from the filter toolbar."),
                bookmarks_group
            );
            bookmarks_label->setWordWrap(true);
            bookmarks_layout->addWidget(bookmarks_label);

            QPushButton* manage_bookmarks_btn = new QPushButton(tr("Manage Bookmarks..."), bookmarks_group);
            bookmarks_layout->addWidget(manage_bookmarks_btn);

            layout->addWidget(bookmarks_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createNameResolutionPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Resolution options
            QGroupBox* resolution_group = new QGroupBox(tr("Name Resolution"), page);
            QVBoxLayout* resolution_layout = new QVBoxLayout(resolution_group);

            resolve_mac_check_ = new QCheckBox(tr("Resolve MAC addresses"), resolution_group);
            resolve_mac_check_->setChecked(true);
            connect(resolve_mac_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onResolveMACChanged);
            resolution_layout->addWidget(resolve_mac_check_);

            resolve_network_check_ = new QCheckBox(tr("Resolve network (IP) addresses"), resolution_group);
            resolve_network_check_->setChecked(true);
            connect(resolve_network_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onResolveNetworkChanged);
            resolution_layout->addWidget(resolve_network_check_);

            resolve_transport_check_ = new QCheckBox(tr("Resolve transport names (ports)"), resolution_group);
            resolve_transport_check_->setChecked(true);
            connect(resolve_transport_check_, &QCheckBox::stateChanged,
                    this, &PreferencesDialog::onResolveTransportChanged);
            resolution_layout->addWidget(resolve_transport_check_);

            resolve_vlan_check_ = new QCheckBox(tr("Resolve VLAN IDs"), resolution_group);
            resolve_vlan_check_->setChecked(false);
            resolution_layout->addWidget(resolve_vlan_check_);

            layout->addWidget(resolution_group);

            // DNS settings
            QGroupBox* dns_group = new QGroupBox(tr("DNS Settings"), page);
            QVBoxLayout* dns_layout = new QVBoxLayout(dns_group);

            use_external_resolver_check_ = new QCheckBox(tr("Use external DNS resolver"), dns_group);
            use_external_resolver_check_->setChecked(false);
            dns_layout->addWidget(use_external_resolver_check_);

            QFormLayout* dns_form = new QFormLayout();
            
            dns_servers_edit_ = new QLineEdit(dns_group);
            dns_servers_edit_->setPlaceholderText(tr("8.8.8.8, 1.1.1.1"));
            dns_form->addRow(tr("DNS servers:"), dns_servers_edit_);

            max_concurrent_requests_spin_ = new QSpinBox(dns_group);
            max_concurrent_requests_spin_->setRange(1, 100);
            max_concurrent_requests_spin_->setValue(10);
            dns_form->addRow(tr("Max concurrent requests:"), max_concurrent_requests_spin_);

            dns_layout->addLayout(dns_form);

            layout->addWidget(dns_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createProtocolsPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            QLabel* label = new QLabel(
                tr("Configure protocol-specific settings.\n"
                   "Expand protocols to see available options."),
                page
            );
            label->setWordWrap(true);
            layout->addWidget(label);

            protocol_tree_ = new QTreeWidget(page);
            protocol_tree_->setHeaderLabels({tr("Protocol"), tr("Setting"), tr("Value")});
            protocol_tree_->setColumnWidth(0, 200);

            // Add some example protocols
            QTreeWidgetItem* tcp_item = new QTreeWidgetItem(protocol_tree_);
            tcp_item->setText(0, "TCP");
            tcp_item->setIcon(0, QIcon::fromTheme("network-wired"));

            QTreeWidgetItem* tcp_checksum = new QTreeWidgetItem(tcp_item);
            tcp_checksum->setText(0, "Validate checksum");
            tcp_checksum->setCheckState(1, Qt::Checked);

            QTreeWidgetItem* http_item = new QTreeWidgetItem(protocol_tree_);
            http_item->setText(0, "HTTP");
            http_item->setIcon(0, QIcon::fromTheme("text-html"));

            QTreeWidgetItem* http_decompress = new QTreeWidgetItem(http_item);
            http_decompress->setText(0, "Decompress body");
            http_decompress->setCheckState(1, Qt::Checked);

            layout->addWidget(protocol_tree_);

            return page;
        }

        QWidget* PreferencesDialog::createStatisticsPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            // Statistics options
            QGroupBox* stats_group = new QGroupBox(tr("Statistics"), page);
            QVBoxLayout* stats_layout = new QVBoxLayout(stats_group);

            enable_stats_check_ = new QCheckBox(tr("Enable real-time statistics"), stats_group);
            enable_stats_check_->setChecked(true);
            stats_layout->addWidget(enable_stats_check_);

            QFormLayout* interval_layout = new QFormLayout();
            update_stats_interval_spin_ = new QSpinBox(stats_group);
            update_stats_interval_spin_->setRange(100, 10000);
            update_stats_interval_spin_->setValue(1000);
            update_stats_interval_spin_->setSuffix(" ms");
            interval_layout->addRow(tr("Update interval:"), update_stats_interval_spin_);
            stats_layout->addLayout(interval_layout);

            layout->addWidget(stats_group);

            // Statistics types
            QGroupBox* types_group = new QGroupBox(tr("Statistics Types"), page);
            QVBoxLayout* types_layout = new QVBoxLayout(types_group);

            types_layout->addWidget(new QCheckBox(tr("Protocol hierarchy"), types_group));
            types_layout->addWidget(new QCheckBox(tr("Conversations"), types_group));
            types_layout->addWidget(new QCheckBox(tr("Endpoints"), types_group));
            types_layout->addWidget(new QCheckBox(tr("I/O Graph"), types_group));

            layout->addWidget(types_group);
            layout->addStretch();

            return page;
        }

        QWidget* PreferencesDialog::createAdvancedPage()
        {
            QWidget* page = new QWidget();
            QVBoxLayout* layout = new QVBoxLayout(page);

            QLabel* warning = new QLabel(
                tr("<b>Warning:</b> Changing these settings may affect application stability."),
                page
            );
            warning->setStyleSheet("QLabel { color: red; }");
            layout->addWidget(warning);

            advanced_tree_ = new QTreeWidget(page);
            advanced_tree_->setHeaderLabels({tr("Setting"), tr("Value")});
            advanced_tree_->setColumnWidth(0, 300);

            // Add some advanced settings
            QTreeWidgetItem* memory_item = new QTreeWidgetItem(advanced_tree_);
            memory_item->setText(0, "Memory Management");

            QTreeWidgetItem* max_memory = new QTreeWidgetItem(memory_item);
            max_memory->setText(0, "Maximum memory usage (MB)");
            max_memory->setText(1, "1024");

            QTreeWidgetItem* threading_item = new QTreeWidgetItem(advanced_tree_);
            threading_item->setText(0, "Threading");

            QTreeWidgetItem* worker_threads = new QTreeWidgetItem(threading_item);
            worker_threads->setText(0, "Worker threads");
            worker_threads->setText(1, "4");

            layout->addWidget(advanced_tree_);

            return page;
        }

        // ==================== Settings Management ====================

        void PreferencesDialog::loadSettings()
        {
            // Appearance
            font_combo_->setCurrentFont(settings_.value("appearance/font", QFont()).value<QFont>());
            font_size_spin_->setValue(settings_.value("appearance/font_size", 10).toInt());
            theme_combo_->setCurrentText(settings_.value("appearance/theme", "System").toString());

            // Capture
            promiscuous_check_->setChecked(settings_.value("capture/promiscuous", true).toBool());
            buffer_size_spin_->setValue(settings_.value("capture/buffer_size", 2).toInt());

            // Display
            time_format_combo_->setCurrentIndex(settings_.value("display/time_format", 0).toInt());
            auto_scroll_check_->setChecked(settings_.value("display/auto_scroll", true).toBool());
            show_hex_check_->setChecked(settings_.value("display/show_hex", true).toBool());
            colorize_check_->setChecked(settings_.value("display/colorize", true).toBool());

            // Name Resolution
            resolve_mac_check_->setChecked(settings_.value("resolution/mac", true).toBool());
            resolve_network_check_->setChecked(settings_.value("resolution/network", true).toBool());
            resolve_transport_check_->setChecked(settings_.value("resolution/transport", true).toBool());

            spdlog::debug("Preferences loaded from settings");
        }

        void PreferencesDialog::saveSettings()
        {
            // Appearance
            settings_.setValue("appearance/font", font_combo_->currentFont());
            settings_.setValue("appearance/font_size", font_size_spin_->value());
            settings_.setValue("appearance/theme", theme_combo_->currentText());

            // Capture
            settings_.setValue("capture/promiscuous", promiscuous_check_->isChecked());
            settings_.setValue("capture/buffer_size", buffer_size_spin_->value());

            // Display
            settings_.setValue("display/time_format", time_format_combo_->currentIndex());
            settings_.setValue("display/auto_scroll", auto_scroll_check_->isChecked());
            settings_.setValue("display/show_hex", show_hex_check_->isChecked());
            settings_.setValue("display/colorize", colorize_check_->isChecked());

            // Name Resolution
            settings_.setValue("resolution/mac", resolve_mac_check_->isChecked());
            settings_.setValue("resolution/network", resolve_network_check_->isChecked());
            settings_.setValue("resolution/transport", resolve_transport_check_->isChecked());

            settings_.sync();
            spdlog::info("Preferences saved");
        }

        void PreferencesDialog::applySettings()
        {
            saveSettings();
            settings_changed_ = false;
            
            QMessageBox::information(this, tr("Settings Applied"),
                tr("Settings have been applied.\n"
                   "Some changes may require restarting the application."));
        }

        void PreferencesDialog::restoreDefaults()
        {
            QMessageBox::StandardButton reply = QMessageBox::question(
                this,
                tr("Restore Defaults"),
                tr("Are you sure you want to restore all settings to their default values?"),
                QMessageBox::Yes | QMessageBox::No
            );

            if (reply == QMessageBox::Yes) {
                settings_.clear();
                loadSettings();
                settings_changed_ = true;
                spdlog::info("Settings restored to defaults");
            }
        }

        // ==================== Slots ====================

        void PreferencesDialog::onCategorySelected(QTreeWidgetItem* item, int column)
        {
            Q_UNUSED(column);
            
            if (!item) {
                return;
            }

            int index = category_tree_->indexOfTopLevelItem(item);
            if (index >= 0) {
                pages_stack_->setCurrentIndex(index);
            }
        }

        void PreferencesDialog::onApply()
        {
            applySettings();
        }

        void PreferencesDialog::onOK()
        {
            if (settings_changed_) {
                saveSettings();
            }
            accept();
        }

        void PreferencesDialog::onCancel()
        {
            if (settings_changed_) {
                QMessageBox::StandardButton reply = QMessageBox::question(
                    this,
                    tr("Discard Changes"),
                    tr("You have unsaved changes. Do you want to discard them?"),
                    QMessageBox::Yes | QMessageBox::No
                );

                if (reply == QMessageBox::No) {
                    return;
                }
            }
            reject();
        }

        void PreferencesDialog::onRestoreDefaults()
        {
            restoreDefaults();
        }

        // Appearance slots
        void PreferencesDialog::onFontChanged(const QFont& font)
        {
            Q_UNUSED(font);
            settings_changed_ = true;
        }

        void PreferencesDialog::onThemeChanged(int index)
        {
            Q_UNUSED(index);
            settings_changed_ = true;
        }

        void PreferencesDialog::onColorSchemeChanged(int index)
        {
            Q_UNUSED(index);
            settings_changed_ = true;
        }

        // Capture slots
        void PreferencesDialog::onDefaultInterfaceChanged(const QString& interface)
        {
            Q_UNUSED(interface);
            settings_changed_ = true;
        }

        void PreferencesDialog::onPromiscuousModeChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        // Display slots
        void PreferencesDialog::onTimeFormatChanged(int index)
        {
            Q_UNUSED(index);
            settings_changed_ = true;
        }

        void PreferencesDialog::onAutoScrollChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        void PreferencesDialog::onShowHexChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        // Name Resolution slots
        void PreferencesDialog::onResolveMACChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        void PreferencesDialog::onResolveNetworkChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        void PreferencesDialog::onResolveTransportChanged(int state)
        {
            Q_UNUSED(state);
            settings_changed_ = true;
        }

        // Protocol slots
        void PreferencesDialog::onProtocolSettingChanged()
        {
            settings_changed_ = true;
        }

        // Advanced slots
        void PreferencesDialog::onAdvancedSettingChanged()
        {
            settings_changed_ = true;
        }

    } // namespace GUI
} // namespace NetworkSecurity
