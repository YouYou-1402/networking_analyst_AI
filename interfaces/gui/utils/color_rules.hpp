// src/gui/utils/color_rules.hpp

#ifndef COLOR_RULES_HPP
#define COLOR_RULES_HPP

#include <QColor>
#include <QString>
#include <QList>
#include <memory>

#include "common/packet_parser.hpp"
#include "core/layer1/filter/packet_filter.hpp"

namespace NetworkSecurity
{
    namespace GUI
    {
        /**
         * @brief Color rule for packet coloring
         */
        struct ColorRule {
            QString name;
            QString filter;
            QColor foreground;
            QColor background;
            bool enabled;
            int priority;
            
            ColorRule()
                : enabled(true), priority(0) {}
            
            ColorRule(const QString& n, const QString& f,
                     const QColor& fg, const QColor& bg,
                     bool en = true, int pri = 0)
                : name(n), filter(f), foreground(fg), background(bg),
                  enabled(en), priority(pri) {}
        };

        /**
         * @brief Manages coloring rules for packets
         */
        class ColorRules
        {
        public:
            ColorRules();
            ~ColorRules();

            // ==================== Rule Management ====================
            void addRule(const ColorRule& rule);
            void removeRule(int index);
            void updateRule(int index, const ColorRule& rule);
            void moveRule(int from, int to);
            void clearRules();
            
            ColorRule getRule(int index) const;
            int getRuleCount() const;
            QList<ColorRule> getAllRules() const;
            
            // ==================== Enable/Disable ====================
            void setRuleEnabled(int index, bool enabled);
            bool isRuleEnabled(int index) const;
            
            void enableAll();
            void disableAll();
            
            // ==================== Matching ====================
            bool matchPacket(const Common::ParsedPacket& packet,
                           QColor& foreground,
                           QColor& background) const;
            
            // ==================== Import/Export ====================
            bool loadFromFile(const QString& filename);
            bool saveToFile(const QString& filename);
            
            void loadDefaults();
            void loadFromSettings();
            void saveToSettings();
            
            // ==================== Predefined Rules ====================
            static QList<ColorRule> getDefaultRules();
            static ColorRule createTCPRule();
            static ColorRule createUDPRule();
            static ColorRule createICMPRule();
            static ColorRule createARPRule();
            static ColorRule createHTTPRule();
            static ColorRule createHTTPSRule();
            static ColorRule createDNSRule();
            static ColorRule createErrorRule();
            static ColorRule createWarningRule();
            static ColorRule createRetransmissionRule();

        private:
            void sortRulesByPriority();
            bool evaluateFilter(const QString& filter,
                              const Common::ParsedPacket& packet) const;

            QList<ColorRule> rules_;
            mutable std::map<QString, std::unique_ptr<Layer1::Filter::PacketFilter>> filter_cache_;
        };

    } // namespace GUI
} // namespace NetworkSecurity

#endif // COLOR_RULES_HPP
