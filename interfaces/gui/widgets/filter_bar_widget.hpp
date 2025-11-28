// src/gui/widgets/filter_bar_widget.hpp

#ifndef FILTER_BAR_WIDGET_HPP
#define FILTER_BAR_WIDGET_HPP

#include <QWidget>
#include <QLineEdit>
#include <QCompleter>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QToolButton>
#include <QStringListModel>
#include <memory>

#include "core/layer1/filter/packet_filter.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Filter toolbar widget (like Wireshark filter bar)
         */
        class FilterBarWidget : public QWidget
        {
            Q_OBJECT

        public:
            explicit FilterBarWidget(QWidget* parent = nullptr);
            ~FilterBarWidget();

            // ==================== Filter Management ====================
            QString getFilter() const;
            void setFilter(const QString& filter);
            void clearFilter();
            void applyFilter();
            
            // ==================== History ====================
            void addToHistory(const QString& filter);
            void clearHistory();
            QStringList getHistory() const;
            
            // ==================== Bookmarks ====================
            void addBookmark(const QString& name, const QString& filter);
            void removeBookmark(const QString& name);
            QMap<QString, QString> getBookmarks() const;
            
            // ==================== Validation ====================
            bool validateFilter(const QString& filter);
            QString getValidationError() const;

        signals:
            void filterChanged(const QString& filter);
            void filterApplied(const QString& filter);
            void filterCleared();

        private slots:
            void onFilterTextChanged(const QString& text);
            void onFilterReturnPressed();
            void onApplyButtonClicked();
            void onClearButtonClicked();
            void onBookmarkButtonClicked();
            void onHistorySelected(const QString& filter);
            void onBookmarkSelected(QAction* action);
            void onExpressionButtonClicked();

        private:
            void setupUI();
            void setupCompleter();
            void setupBookmarkMenu();
            void updateFilterStyle();
            void loadHistory();
            void saveHistory();
            void loadBookmarks();
            void saveBookmarks();

            // UI Components
            QLineEdit* filter_edit_;
            QPushButton* apply_button_;
            QPushButton* clear_button_;
            QToolButton* bookmark_button_;
            QToolButton* expression_button_;
            QToolButton* history_button_;
            QComboBox* history_combo_;
            QLabel* status_label_;
            QCompleter* completer_;
            
            // Menus
            QMenu* bookmark_menu_;
            QMenu* history_menu_;
            
            // Data
            QStringList filter_history_;
            QMap<QString, QString> filter_bookmarks_;
            QString current_filter_;
            QString validation_error_;
            
            // Filter validator
            std::unique_ptr<Layer1::Filter::PacketFilter> filter_validator_;
            
            // Settings
            static constexpr int MAX_HISTORY_SIZE = 50;
            static constexpr int MAX_BOOKMARKS = 100;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // FILTER_BAR_WIDGET_HPP
