// src/gui/utils/color_rules.cpp

#include "color_rules.hpp"
#include <QSettings>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <spdlog/spdlog.h>

namespace NetworkSecurity
{
    namespace GUI
    {
        ColorRules::ColorRules()
        {
        }

        ColorRules::~ColorRules()
        {
        }

        // ==================== Rule Management ====================

        void ColorRules::addRule(const ColorRule& rule)
        {
            rules_.append(rule);
            sortRulesByPriority();
            spdlog::debug("Added color rule: {}", rule.name.toStdString());
        }

        void ColorRules::removeRule(int index)
        {
            if (index >= 0 && index < rules_.size()) {
                QString name = rules_[index].name;
                rules_.removeAt(index);
                spdlog::debug("Removed color rule: {}", name.toStdString());
            }
        }

        void ColorRules::updateRule(int index, const ColorRule& rule)
        {
            if (index >= 0 && index < rules_.size()) {
                rules_[index] = rule;
                sortRulesByPriority();
                spdlog::debug("Updated color rule: {}", rule.name.toStdString());
            }
        }

        void ColorRules::moveRule(int from, int to)
        {
            if (from >= 0 && from < rules_.size() && 
                to >= 0 && to < rules_.size()) {
                rules_.move(from, to);
                spdlog::debug("Moved color rule from {} to {}", from, to);
            }
        }

        void ColorRules::clearRules()
        {
            rules_.clear();
            filter_cache_.clear();
            spdlog::info("Cleared all color rules");
        }

        ColorRule ColorRules::getRule(int index) const
        {
            if (index >= 0 && index < rules_.size()) {
                return rules_[index];
            }
            return ColorRule();
        }

        int ColorRules::getRuleCount() const
        {
            return rules_.size();
        }

        QList<ColorRule> ColorRules::getAllRules() const
        {
            return rules_;
        }

        // ==================== Enable/Disable ====================

        void ColorRules::setRuleEnabled(int index, bool enabled)
        {
            if (index >= 0 && index < rules_.size()) {
                rules_[index].enabled = enabled;
                spdlog::debug("Rule '{}' {}", 
                             rules_[index].name.toStdString(),
                             enabled ? "enabled" : "disabled");
            }
        }

        bool ColorRules::isRuleEnabled(int index) const
        {
            if (index >= 0 && index < rules_.size()) {
                return rules_[index].enabled;
            }
            return false;
        }

        void ColorRules::enableAll()
        {
            for (auto& rule : rules_) {
                rule.enabled = true;
            }
            spdlog::info("Enabled all color rules");
        }

        void ColorRules::disableAll()
        {
            for (auto& rule : rules_) {
                rule.enabled = false;
            }
            spdlog::info("Disabled all color rules");
        }

        // ==================== Matching ====================

        bool ColorRules::matchPacket(const Common::ParsedPacket& packet,
                                    QColor& foreground,
                                    QColor& background) const
        {
            // Try each rule in priority order
            for (const auto& rule : rules_) {
                if (!rule.enabled) {
                    continue;
                }

                if (evaluateFilter(rule.filter, packet)) {
                    foreground = rule.foreground;
                    background = rule.background;
                    return true;
                }
            }

            return false;
        }

        // ==================== Import/Export ====================

        bool ColorRules::loadFromFile(const QString& filename)
        {
            QFile file(filename);
            if (!file.open(QIODevice::ReadOnly)) {
                spdlog::error("Failed to open color rules file: {}", 
                             filename.toStdString());
                return false;
            }

            QByteArray data = file.readAll();
            file.close();

            QJsonDocument doc = QJsonDocument::fromJson(data);
            if (!doc.isObject()) {
                spdlog::error("Invalid color rules file format");
                return false;
            }

            QJsonObject root = doc.object();
            QJsonArray rulesArray = root["rules"].toArray();

            rules_.clear();

            for (const auto& ruleValue : rulesArray) {
                QJsonObject ruleObj = ruleValue.toObject();
                
                ColorRule rule;
                rule.name = ruleObj["name"].toString();
                rule.filter = ruleObj["filter"].toString();
                rule.foreground = QColor(ruleObj["foreground"].toString());
                rule.background = QColor(ruleObj["background"].toString());
                rule.enabled = ruleObj["enabled"].toBool(true);
                rule.priority = ruleObj["priority"].toInt(0);

                rules_.append(rule);
            }

            sortRulesByPriority();

            spdlog::info("Loaded {} color rules from {}", 
                        rules_.size(), filename.toStdString());
            return true;
        }

        bool ColorRules::saveToFile(const QString& filename)
        {
            QJsonArray rulesArray;

            for (const auto& rule : rules_) {
                QJsonObject ruleObj;
                ruleObj["name"] = rule.name;
                ruleObj["filter"] = rule.filter;
                ruleObj["foreground"] = rule.foreground.name();
                ruleObj["background"] = rule.background.name();
                ruleObj["enabled"] = rule.enabled;
                ruleObj["priority"] = rule.priority;

                rulesArray.append(ruleObj);
            }

            QJsonObject root;
            root["version"] = "1.0";
            root["rules"] = rulesArray;

            QJsonDocument doc(root);

            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly)) {
                spdlog::error("Failed to save color rules to {}", 
                             filename.toStdString());
                return false;
            }

            file.write(doc.toJson());
            file.close();

            spdlog::info("Saved {} color rules to {}", 
                        rules_.size(), filename.toStdString());
            return true;
        }

        void ColorRules::loadDefaults()
        {
            rules_ = getDefaultRules();
            spdlog::info("Loaded {} default color rules", rules_.size());
        }

        void ColorRules::loadFromSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            int size = settings.beginReadArray("color_rules");
            rules_.clear();

            for (int i = 0; i < size; i++) {
                settings.setArrayIndex(i);
                
                ColorRule rule;
                rule.name = settings.value("name").toString();
                rule.filter = settings.value("filter").toString();
                rule.foreground = QColor(settings.value("foreground").toString());
                rule.background = QColor(settings.value("background").toString());
                rule.enabled = settings.value("enabled", true).toBool();
                rule.priority = settings.value("priority", 0).toInt();

                rules_.append(rule);
            }

            settings.endArray();

            if (rules_.isEmpty()) {
                loadDefaults();
            } else {
                sortRulesByPriority();
                spdlog::info("Loaded {} color rules from settings", rules_.size());
            }
        }

        void ColorRules::saveToSettings()
        {
            QSettings settings("NetworkSecurity", "Analyzer");
            
            settings.beginWriteArray("color_rules");

            for (int i = 0; i < rules_.size(); i++) {
                settings.setArrayIndex(i);
                const auto& rule = rules_[i];

                settings.setValue("name", rule.name);
                settings.setValue("filter", rule.filter);
                settings.setValue("foreground", rule.foreground.name());
                settings.setValue("background", rule.background.name());
                settings.setValue("enabled", rule.enabled);
                settings.setValue("priority", rule.priority);
            }

            settings.endArray();

            spdlog::info("Saved {} color rules to settings", rules_.size());
        }

        // ==================== Predefined Rules ====================

        QList<ColorRule> ColorRules::getDefaultRules()
        {
            QList<ColorRule> rules;

            // TCP
            rules.append(ColorRule(
                "TCP",
                "tcp",
                QColor(0, 0, 0),        // Black text
                QColor(231, 230, 255),  // Light blue background
                true, 10
            ));

            // UDP
            rules.append(ColorRule(
                "UDP",
                "udp",
                QColor(0, 0, 0),
                QColor(218, 238, 255),  // Light cyan
                true, 10
            ));

            // ICMP
            rules.append(ColorRule(
                "ICMP",
                "icmp",
                QColor(0, 0, 0),
                QColor(252, 224, 255),  // Light purple
                true, 10
            ));

            // ARP
            rules.append(ColorRule(
                "ARP",
                "arp",
                QColor(0, 0, 0),
                QColor(255, 255, 224),  // Light yellow
                true, 10
            ));

            // HTTP
            rules.append(ColorRule(
                "HTTP",
                "http",
                QColor(0, 0, 0),
                QColor(228, 255, 199),  // Light green
                true, 20
            ));

            // HTTPS/TLS
            rules.append(ColorRule(
                "HTTPS",
                "ssl || tls",
                QColor(0, 0, 0),
                QColor(164, 224, 255),  // Sky blue
                true, 20
            ));

            // DNS
            rules.append(ColorRule(
                "DNS",
                "dns",
                QColor(0, 0, 0),
                QColor(255, 255, 199),  // Pale yellow
                true, 20
            ));

            // SSH
            rules.append(ColorRule(
                "SSH",
                "ssh",
                QColor(255, 255, 255),
                QColor(70, 130, 180),   // Steel blue
                true, 20
            ));

            // FTP
            rules.append(ColorRule(
                "FTP",
                "ftp || ftp-data",
                QColor(0, 0, 0),
                QColor(255, 192, 203),  // Pink
                true, 20
            ));

            // SMTP
            rules.append(ColorRule(
                "SMTP",
                "smtp",
                QColor(0, 0, 0),
                QColor(255, 228, 196),  // Bisque
                true, 20
            ));

            // TCP SYN
            rules.append(ColorRule(
                "TCP SYN",
                "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                QColor(0, 0, 0),
                QColor(160, 160, 255),  // Light blue
                true, 30
            ));

            // TCP RST
            rules.append(ColorRule(
                "TCP RST",
                "tcp.flags.reset == 1",
                QColor(255, 255, 255),
                QColor(255, 0, 0),      // Red
                true, 40
            ));

            // TCP Retransmission
            rules.append(ColorRule(
                "TCP Retransmission",
                "tcp.analysis.retransmission",
                QColor(0, 0, 0),
                QColor(255, 165, 0),    // Orange
                true, 50
            ));

            // Bad TCP
            rules.append(ColorRule(
                "Bad TCP",
                "tcp.analysis.flags",
                QColor(255, 255, 255),
                QColor(128, 0, 0),      // Dark red
                true, 60
            ));

            // Broadcast
            rules.append(ColorRule(
                "Broadcast",
                "eth.dst == ff:ff:ff:ff:ff:ff",
                QColor(0, 0, 0),
                QColor(255, 255, 0),    // Yellow
                true, 15
            ));

            // Multicast
            rules.append(ColorRule(
                "Multicast",
                "eth.dst[0] & 1",
                QColor(0, 0, 0),
                QColor(255, 255, 224),  // Light yellow
                true, 15
            ));

            return rules;
        }

        ColorRule ColorRules::createTCPRule()
        {
            return ColorRule("TCP", "tcp", 
                           QColor(0, 0, 0), QColor(231, 230, 255));
        }

        ColorRule ColorRules::createUDPRule()
        {
            return ColorRule("UDP", "udp",
                           QColor(0, 0, 0), QColor(218, 238, 255));
        }

        ColorRule ColorRules::createICMPRule()
        {
            return ColorRule("ICMP", "icmp",
                           QColor(0, 0, 0), QColor(252, 224, 255));
        }

        ColorRule ColorRules::createARPRule()
        {
            return ColorRule("ARP", "arp",
                           QColor(0, 0, 0), QColor(255, 255, 224));
        }

        ColorRule ColorRules::createHTTPRule()
        {
            return ColorRule("HTTP", "http",
                           QColor(0, 0, 0), QColor(228, 255, 199));
        }

        ColorRule ColorRules::createHTTPSRule()
        {
            return ColorRule("HTTPS", "ssl || tls",
                           QColor(0, 0, 0), QColor(164, 224, 255));
        }

        ColorRule ColorRules::createDNSRule()
        {
            return ColorRule("DNS", "dns",
                           QColor(0, 0, 0), QColor(255, 255, 199));
        }

        ColorRule ColorRules::createErrorRule()
        {
            return ColorRule("Error", "tcp.analysis.flags",
                           QColor(255, 255, 255), QColor(128, 0, 0));
        }

        ColorRule ColorRules::createWarningRule()
        {
            return ColorRule("Warning", "tcp.analysis.retransmission",
                           QColor(0, 0, 0), QColor(255, 165, 0));
        }

        ColorRule ColorRules::createRetransmissionRule()
        {
            return ColorRule("Retransmission", "tcp.analysis.retransmission",
                           QColor(0, 0, 0), QColor(255, 165, 0));
        }

        // ==================== Helper Methods ====================

        void ColorRules::sortRulesByPriority()
        {
            std::sort(rules_.begin(), rules_.end(),
                [](const ColorRule& a, const ColorRule& b) {
                    return a.priority > b.priority;  // Higher priority first
                });
        }

        bool ColorRules::evaluateFilter(const QString& filter,
                                        const Common::ParsedPacket& packet) const
        {
            if (filter.isEmpty()) {
                return false;
            }

            // Simple filter evaluation (can be extended)
            QString f = filter.toLower();

            // Protocol filters
            if (f == "tcp") return packet.has_tcp;
            if (f == "udp") return packet.has_udp;
            if (f == "icmp") return packet.has_icmp;
            if (f == "arp") return packet.has_arp;
            if (f == "ipv4" || f == "ip") return packet.has_ipv4;
            if (f == "ipv6") return packet.has_ipv6;

            // Application protocols
            if (f == "http") return packet.app_protocol == Common::AppProtocol::HTTP;
            if (f == "https" || f == "ssl" || f == "tls") 
                return packet.app_protocol == Common::AppProtocol::HTTPS;
            if (f == "dns") return packet.app_protocol == Common::AppProtocol::DNS;
            if (f == "ssh") return packet.app_protocol == Common::AppProtocol::SSH;
            if (f == "ftp") return packet.app_protocol == Common::AppProtocol::FTP;
            if (f == "smtp") return packet.app_protocol == Common::AppProtocol::SMTP;

            // TCP flags
            if (f.contains("tcp.flags.syn") && packet.has_tcp) {
                if (f.contains("== 1")) return packet.tcp.flag_syn;
                if (f.contains("== 0")) return !packet.tcp.flag_syn;
            }
            if (f.contains("tcp.flags.ack") && packet.has_tcp) {
                if (f.contains("== 1")) return packet.tcp.flag_ack;
                if (f.contains("== 0")) return !packet.tcp.flag_ack;
            }
            if (f.contains("tcp.flags.reset") && packet.has_tcp) {
                if (f.contains("== 1")) return packet.tcp.flag_rst;
            }

            // TCP analysis
            if (f.contains("tcp.analysis.retransmission") && packet.has_tcp) {
                return packet.tcp.analysis.is_retransmission;
            }
            if (f.contains("tcp.analysis.flags") && packet.has_tcp) {
                return packet.tcp.analysis.is_retransmission ||
                       packet.tcp.analysis.is_dup_ack ||
                       packet.tcp.analysis.is_zero_window ||
                       packet.tcp.analysis.is_out_of_order;
            }

            // Broadcast
            if (f.contains("eth.dst == ff:ff:ff:ff:ff:ff") && packet.has_ethernet) {
                return packet.ethernet.dst_mac[0] == 0xff &&
                       packet.ethernet.dst_mac[1] == 0xff &&
                       packet.ethernet.dst_mac[2] == 0xff &&
                       packet.ethernet.dst_mac[3] == 0xff &&
                       packet.ethernet.dst_mac[4] == 0xff &&
                       packet.ethernet.dst_mac[5] == 0xff;
            }

            // Multicast (first bit of MAC is 1)
            if (f.contains("eth.dst[0] & 1") && packet.has_ethernet) {
                return (packet.ethernet.dst_mac[0] & 0x01) != 0;
            }

            // OR operator
            if (f.contains("||")) {
                QStringList parts = f.split("||");
                for (const QString& part : parts) {
                    if (evaluateFilter(part.trimmed(), packet)) {
                        return true;
                    }
                }
                return false;
            }

            // AND operator
            if (f.contains("&&")) {
                QStringList parts = f.split("&&");
                for (const QString& part : parts) {
                    if (!evaluateFilter(part.trimmed(), packet)) {
                        return false;
                    }
                }
                return true;
            }

            return false;
        }

    } // namespace GUI
} // namespace NetworkSecurity
