// src/gui/dialogs/preferences_dialog.hpp

#ifndef PREFERENCES_DIALOG_HPP
#define PREFERENCES_DIALOG_HPP

#include <QDialog>
#include <QTreeWidget>
#include <QStackedWidget>
#include <QCheckBox>
#include <QSpinBox>
#include <QComboBox>
#include <QLineEdit>
#include <QFontComboBox>
#include <QPushButton>
#include <QColorDialog>
#include <QSettings>

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Preferences dialog (like Wireshark preferences)
         */
        class PreferencesDialog : public QDialog
        {
            Q_OBJECT

        public:
            explicit PreferencesDialog(QWidget* parent = nullptr);
            ~PreferencesDialog();

        private slots:
            void onCategorySelected(QTreeWidgetItem* item, int column);
            void onApply();
            void onOK();
            void onCancel();
            void onRestoreDefaults();
            
            // Appearance
            void onFontChanged(const QFont& font);
            void onThemeChanged(int index);
            void onColorSchemeChanged(int index);
            
            // Capture
            void onDefaultInterfaceChanged(const QString& interface);
            void onPromiscuousModeChanged(int state);
            
            // Display
            void onTimeFormatChanged(int index);
            void onAutoScrollChanged(int state);
            void onShowHexChanged(int state);
            
            // Name Resolution
            void onResolveMACChanged(int state);
            void onResolveNetworkChanged(int state);
            void onResolveTransportChanged(int state);
            
            // Protocols
            void onProtocolSettingChanged();
            
            // Advanced
            void onAdvancedSettingChanged();

        private:
            void setupUI();
            void setupCategories();
            
            // Category pages
            QWidget* createAppearancePage();
            QWidget* createCapturePage();
            QWidget* createDisplayPage();
            QWidget* createFilterPage();
            QWidget* createNameResolutionPage();
            QWidget* createProtocolsPage();
            QWidget* createStatisticsPage();
            QWidget* createAdvancedPage();
            
            void loadSettings();
            void saveSettings();
            void applySettings();
            void restoreDefaults();

            // UI Components
            QTreeWidget* category_tree_;
            QStackedWidget* pages_stack_;
            
            // Appearance settings
            QFontComboBox* font_combo_;
            QSpinBox* font_size_spin_;
            QComboBox* theme_combo_;
            QComboBox* color_scheme_combo_;
            QPushButton* fg_color_button_;
            QPushButton* bg_color_button_;
            QPushButton* selection_color_button_;
            
            // Capture settings
            QComboBox* default_interface_combo_;
            QCheckBox* promiscuous_check_;
            QSpinBox* buffer_size_spin_;
            QCheckBox* update_list_check_;
            QSpinBox* update_interval_spin_;
            
            // Display settings
            QComboBox* time_format_combo_;
            QCheckBox* auto_scroll_check_;
            QCheckBox* show_hex_check_;
            QSpinBox* max_packets_spin_;
            QCheckBox* colorize_check_;
            
            // Filter settings
            QCheckBox* save_filters_check_;
            QSpinBox* max_filters_spin_;
            QCheckBox* auto_complete_check_;
            
            // Name resolution settings
            QCheckBox* resolve_mac_check_;
            QCheckBox* resolve_network_check_;
            QCheckBox* resolve_transport_check_;
            QCheckBox* use_external_resolver_check_;
            QLineEdit* dns_servers_edit_;
            QSpinBox* max_concurrent_requests_spin_;
            QCheckBox* resolve_vlan_check_;
            
            // Protocol settings
            QTreeWidget* protocol_tree_;
            
            // Statistics settings
            QCheckBox* enable_stats_check_;
            QSpinBox* update_stats_interval_spin_;
            
            // Advanced settings
            QTreeWidget* advanced_tree_;
            
            // Buttons
            QPushButton* ok_button_;
            QPushButton* cancel_button_;
            QPushButton* apply_button_;
            QPushButton* defaults_button_;
            
            // Settings storage
            QSettings settings_;
            bool settings_changed_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // PREFERENCES_DIALOG_HPP
