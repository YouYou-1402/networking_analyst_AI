// src/gui/widgets/filter_bar_widget.cpp

#include "filter_bar_widget.hpp"
#include <QHBoxLayout>
#include <QCompleter>
#include <QStringListModel>
#include <QSettings>
#include <QInputDialog>
#include <QMessageBox>
#include <QMenu>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        FilterBarWidget::FilterBarWidget(QWidget* parent)
            : QWidget(parent)
        {
            setupUI();
            setupCompleter();
            loadHistory();
            loadBookmarks();

            // Initialize filter validator
            filter_validator_ = std::make_unique<Layer1::Filter::PacketFilter>();
        }

        FilterBarWidget::~FilterBarWidget()
        {
            saveHistory();
            saveBookmarks();
        }

        void FilterBarWidget::setupUI()
        {
            QHBoxLayout* layout = new QHBoxLayout(this);
            layout->setContentsMargins(5, 5, 5, 5);

            // Filter label
            QLabel* label = new QLabel(tr("Filter:"), this);
            layout->addWidget(label);

            // Filter input
            filter_edit_ = new QLineEdit(this);
            filter_edit_->setPlaceholderText(tr("Enter display filter..."));
            filter_edit_->setClearButtonEnabled(true);
            layout->addWidget(filter_edit_, 1);

            // Apply button
            apply_button_ = new QPushButton(tr("Apply"), this);
            apply_button_->setToolTip(tr("Apply filter (Enter)"));
            layout->addWidget(apply_button_);

            // Clear button
            clear_button_ = new QPushButton(tr("Clear"), this);
            clear_button_->setToolTip(tr("Clear filter"));
            layout->addWidget(clear_button_);

            // Bookmark button
            bookmark_button_ = new QToolButton(this);
            bookmark_button_->setIcon(QIcon::fromTheme("bookmark-new"));
            bookmark_button_->setToolTip(tr("Bookmarks"));
            bookmark_button_->setPopupMode(QToolButton::InstantPopup);
            layout->addWidget(bookmark_button_);

            // Expression button
            expression_button_ = new QToolButton(this);
            expression_button_->setIcon(QIcon::fromTheme("insert-text"));
            expression_button_->setToolTip(tr("Expression..."));
            layout->addWidget(expression_button_);

            // History button
            history_button_ = new QToolButton(this);
            history_button_->setIcon(QIcon::fromTheme("document-open-recent"));
            history_button_->setToolTip(tr("Filter History"));
            history_button_->setPopupMode(QToolButton::InstantPopup);
            layout->addWidget(history_button_);

            // Status label
            status_label_ = new QLabel(this);
            status_label_->setMinimumWidth(100);
            layout->addWidget(status_label_);

            // Connect signals
            connect(filter_edit_, &QLineEdit::textChanged,
                    this, &FilterBarWidget::onFilterTextChanged);
            connect(filter_edit_, &QLineEdit::returnPressed,
                    this, &FilterBarWidget::onFilterReturnPressed);
            connect(apply_button_, &QPushButton::clicked,
                    this, &FilterBarWidget::onApplyButtonClicked);
            connect(clear_button_, &QPushButton::clicked,
                    this, &FilterBarWidget::onClearButtonClicked);
            connect(bookmark_button_, &QToolButton::clicked,
                    this, &FilterBarWidget::onBookmarkButtonClicked);
            connect(expression_button_, &QToolButton::clicked,
                    this, &FilterBarWidget::onExpressionButtonClicked);
        }

        void FilterBarWidget::setupCompleter()
        {
            // Create completer with filter field names
            QStringList completions;
            
            // Add common filter fields
            completions << "tcp" << "udp" << "icmp" << "arp" << "ip" << "ipv6"
                       << "tcp.port" << "tcp.srcport" << "tcp.dstport"
                       << "tcp.flags.syn" << "tcp.flags.ack" << "tcp.flags.fin"
                       << "tcp.stream" << "tcp.len"
                       << "udp.port" << "udp.srcport" << "udp.dstport"
                       << "ip.src" << "ip.dst" << "ip.addr"
                       << "ip.proto" << "ip.ttl"
                       << "eth.src" << "eth.dst" << "eth.addr"
                       << "frame.number" << "frame.len"
                       << "http" << "https" << "dns" << "ssh" << "ftp";

            completer_ = new QCompleter(completions, this);
            completer_->setCaseSensitivity(Qt::CaseInsensitive);
            completer_->setCompletionMode(QCompleter::PopupCompletion);
            filter_edit_->setCompleter(completer_);
        }

        void FilterBarWidget::setupBookmarkMenu()
        {
            bookmark_menu_ = new QMenu(this);
            
            // Add bookmarks
            for (auto it = filter_bookmarks_.begin(); it != filter_bookmarks_.end(); ++it) {
                QAction* action = bookmark_menu_->addAction(it.key());
                action->setData(it.value());
                connect(action, &QAction::triggered, [this, action]() {
                    setFilter(action->data().toString());
                    applyFilter();
                });
            }

            if (!filter_bookmarks_.isEmpty()) {
                bookmark_menu_->addSeparator();
            }

            // Add bookmark management actions
            QAction* add_action = bookmark_menu_->addAction(tr("Add Bookmark..."));
            connect(add_action, &QAction::triggered, [this]() {
                QString name = QInputDialog::getText(this, tr("Add Bookmark"),
                                                    tr("Bookmark name:"));
                if (!name.isEmpty()) {
                    addBookmark(name, filter_edit_->text());
                }
            });

            QAction* manage_action = bookmark_menu_->addAction(tr("Manage Bookmarks..."));
            connect(manage_action, &QAction::triggered, [this]() {
                // TODO: Implement bookmark management dialog
            });

            bookmark_button_->setMenu(bookmark_menu_);
        }

        // ==================== Filter Management ====================

        QString FilterBarWidget::getFilter() const
        {
            return filter_edit_->text();
        }

        void FilterBarWidget::setFilter(const QString& filter)
        {
            filter_edit_->setText(filter);
            current_filter_ = filter;
            updateFilterStyle();
        }

        void FilterBarWidget::clearFilter()
        {
            filter_edit_->clear();
            current_filter_.clear();
            validation_error_.clear();
            updateFilterStyle();
            emit filterCleared();
        }

        void FilterBarWidget::applyFilter()
        {
            QString filter = filter_edit_->text().trimmed();
            
            if (filter.isEmpty()) {
                clearFilter();
                return;
            }

            // Validate filter
            if (!validateFilter(filter)) {
                status_label_->setText(tr("Invalid filter"));
                status_label_->setStyleSheet("QLabel { color: red; }");
                return;
            }

            current_filter_ = filter;
            addToHistory(filter);
            
            status_label_->setText(tr("Filter applied"));
            status_label_->setStyleSheet("QLabel { color: green; }");
            
            emit filterApplied(filter);
            
            spdlog::info("Filter applied: {}", filter.toStdString());
        }

        // ==================== History ====================

        void FilterBarWidget::addToHistory(const QString& filter)
        {
            if (filter.isEmpty()) {
                return;
            }

            // Remove if already exists
            filter_history_.removeAll(filter);
            
            // Add to front
            filter_history_.prepend(filter);
            
            // Limit size
            while (filter_history_.size() > MAX_HISTORY_SIZE) {
                filter_history_.removeLast();
            }

            saveHistory();
        }

        void FilterBarWidget::clearHistory()
        {
            filter_history_.clear();
            saveHistory();
        }

        QStringList FilterBarWidget::getHistory() const
        {
            return filter_history_;
        }

        // ==================== Bookmarks ====================

        void FilterBarWidget::addBookmark(const QString& name, const QString& filter)
        {
            if (name.isEmpty() || filter.isEmpty()) {
                return;
            }

            if (filter_bookmarks_.size() >= MAX_BOOKMARKS) {
                QMessageBox::warning(this, tr("Bookmarks Full"),
                    tr("Maximum number of bookmarks reached."));
                return;
            }

            filter_bookmarks_[name] = filter;
            saveBookmarks();
            setupBookmarkMenu();
            
            spdlog::info("Bookmark added: {} = {}", name.toStdString(), filter.toStdString());
        }

        void FilterBarWidget::removeBookmark(const QString& name)
        {
            filter_bookmarks_.remove(name);
            saveBookmarks();
            setupBookmarkMenu();
        }

        QMap<QString, QString> FilterBarWidget::getBookmarks() const
        {
            return filter_bookmarks_;
        }

        // ==================== Validation ====================

        bool FilterBarWidget::validateFilter(const QString& filter)
        {
            if (filter.isEmpty()) {
                validation_error_.clear();
                return true;
            }

            std::string error;
            bool valid = Layer1::Filter::PacketFilter::validateFilter(
                filter.toStdString(), error);
            
            if (!valid) {
                validation_error_ = QString::fromStdString(error);
            } else {
                validation_error_.clear();
            }

            return valid;
        }

        QString FilterBarWidget::getValidationError() const
        {
            return validation_error_;
        }

        void FilterBarWidget::updateFilterStyle()
        {
            QString filter = filter_edit_->text();
            
            if (filter.isEmpty()) {
                filter_edit_->setStyleSheet("");
                status_label_->clear();
                return;
            }

            if (validateFilter(filter)) {
                filter_edit_->setStyleSheet("QLineEdit { background-color: #e8f5e9; }");
                status_label_->setText(tr("Valid filter"));
                status_label_->setStyleSheet("QLabel { color: green; }");
            } else {
                filter_edit_->setStyleSheet("QLineEdit { background-color: #ffebee; }");
                status_label_->setText(validation_error_);
                status_label_->setStyleSheet("QLabel { color: red; }");
            }
        }

        // ==================== Settings ====================

        void FilterBarWidget::loadHistory()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            filter_history_ = settings.value("filter/history").toStringList();
        }

        void FilterBarWidget::saveHistory()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            settings.setValue("filter/history", filter_history_);
        }

        void FilterBarWidget::loadBookmarks()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            int size = settings.beginReadArray("filter/bookmarks");
            
            for (int i = 0; i < size; i++) {
                settings.setArrayIndex(i);
                QString name = settings.value("name").toString();
                QString filter = settings.value("filter").toString();
                filter_bookmarks_[name] = filter;
            }
            
            settings.endArray();
            setupBookmarkMenu();
        }

        void FilterBarWidget::saveBookmarks()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            settings.beginWriteArray("filter/bookmarks");
            
            int i = 0;
            for (auto it = filter_bookmarks_.begin(); it != filter_bookmarks_.end(); ++it) {
                settings.setArrayIndex(i++);
                settings.setValue("name", it.key());
                settings.setValue("filter", it.value());
            }
            
            settings.endArray();
        }

        // ==================== Slots ====================

        void FilterBarWidget::onFilterTextChanged(const QString& text)
        {
            updateFilterStyle();
            emit filterChanged(text);
        }

        void FilterBarWidget::onFilterReturnPressed()
        {
            applyFilter();
        }

        void FilterBarWidget::onApplyButtonClicked()
        {
            applyFilter();
        }

        void FilterBarWidget::onClearButtonClicked()
        {
            clearFilter();
        }

        void FilterBarWidget::onBookmarkButtonClicked()
        {
            // Menu is shown automatically due to InstantPopup mode
        }

        void FilterBarWidget::onHistorySelected(const QString& filter)
        {
            setFilter(filter);
        }

        void FilterBarWidget::onBookmarkSelected(QAction* action)
        {
            setFilter(action->data().toString());
            applyFilter();
        }

        void FilterBarWidget::onExpressionButtonClicked()
        {
            // TODO: Implement expression builder dialog
            QMessageBox::information(this, tr("Expression Builder"),
                tr("Expression builder coming soon!"));
        }

    } // namespace GUI
} // namespace NetworkSecurity
