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

            // ==================== CRITICAL ERRORS (Priority 100+) ====================
            
            // TCP RST - Đỏ đậm (ngắt kết nối)
            rules.append(ColorRule(
                "TCP RST",
                "tcp.flags.reset == 1",
                QColor(139, 0, 0),      // Chữ đỏ đậm
                QColor(255, 200, 200),  // Nền đỏ nhạt
                true, 100
            ));

            // Bad TCP - Đỏ (lỗi nghiêm trọng)
            rules.append(ColorRule(
                "Bad TCP",
                "tcp.analysis.flags",
                QColor(139, 0, 0),
                QColor(255, 220, 220),
                true, 95
            ));

            // ==================== WARNINGS (Priority 50-90) ====================

            // TCP Retransmission - Cam (cảnh báo)
            rules.append(ColorRule(
                "TCP Retransmission",
                "tcp.analysis.retransmission",
                QColor(184, 92, 0),     // Chữ cam đậm
                QColor(255, 235, 200),  // Nền cam nhạt
                true, 80
            ));

            // TCP SYN - Xanh dương nhạt (bắt đầu kết nối)
            rules.append(ColorRule(
                "TCP SYN",
                "tcp.flags.syn == 1 && tcp.flags.ack == 0",
                QColor(0, 0, 139),      // Chữ xanh đậm
                QColor(200, 230, 255),  // Nền xanh nhạt
                true, 70
            ));

            // Broadcast - Vàng (gói tin broadcast)
            rules.append(ColorRule(
                "Broadcast",
                "eth.dst == ff:ff:ff:ff:ff:ff",
                QColor(139, 117, 0),    // Chữ vàng đậm
                QColor(255, 255, 200),  // Nền vàng nhạt
                true, 60
            ));

            // Multicast - Xanh lá nhạt
            rules.append(ColorRule(
                "Multicast",
                "eth.dst[0] & 1",
                QColor(0, 100, 0),      // Chữ xanh lá đậm
                QColor(235, 255, 235),  // Nền xanh lá nhạt
                true, 55
            ));

            // ==================== WEB SERVICES (Priority 30-40) ====================

            // HTTPS/TLS - Xanh dương đậm (bảo mật)
            rules.append(ColorRule(
                "HTTPS/TLS",
                "ssl || tls",
                QColor(0, 0, 0),
                QColor(200, 220, 255),  // Nền xanh dương nhạt
                true, 40
            ));

            // HTTP - Xanh lục (web không mã hóa)
            rules.append(ColorRule(
                "HTTP",
                "http",
                QColor(0, 0, 0),
                QColor(220, 255, 220),  // Nền xanh lục nhạt
                true, 35
            ));

            // WebSocket - Xanh tím
            rules.append(ColorRule(
                "WebSocket",
                "websocket",
                QColor(0, 0, 0),
                QColor(230, 220, 255),  // Nền tím nhạt
                true, 38
            ));

            // ==================== REMOTE ACCESS (Priority 30-35) ====================

            // SSH - Xanh đậm (truy cập từ xa bảo mật)
            rules.append(ColorRule(
                "SSH",
                "ssh || tcp.port == 22",
                QColor(255, 255, 255),  // Chữ trắng
                QColor(70, 130, 180),   // Nền xanh đậm
                true, 35
            ));

            // Telnet - Đỏ nhạt (không bảo mật)
            rules.append(ColorRule(
                "Telnet",
                "telnet || tcp.port == 23",
                QColor(139, 0, 0),
                QColor(255, 230, 230),
                true, 34
            ));

            // RDP - Xanh navy
            rules.append(ColorRule(
                "RDP",
                "rdp || tcp.port == 3389",
                QColor(255, 255, 255),
                QColor(65, 105, 225),   // Royal blue
                true, 33
            ));

            // VNC - Tím
            rules.append(ColorRule(
                "VNC",
                "vnc || tcp.port == 5900",
                QColor(255, 255, 255),
                QColor(138, 43, 226),   // Blue violet
                true, 32
            ));

            // ==================== FILE TRANSFER (Priority 25-30) ====================

            // FTP - Hồng (truyền file)
            rules.append(ColorRule(
                "FTP",
                "ftp || ftp-data || tcp.port == 21 || tcp.port == 20",
                QColor(0, 0, 0),
                QColor(255, 220, 240),  // Nền hồng nhạt
                true, 30
            ));

            // SFTP - Hồng đậm hơn (FTP bảo mật)
            rules.append(ColorRule(
                "SFTP",
                "sftp || tcp.port == 115",
                QColor(0, 0, 0),
                QColor(255, 200, 230),
                true, 31
            ));

            // SMB/CIFS - Cam nhạt (chia sẻ file Windows)
            rules.append(ColorRule(
                "SMB/CIFS",
                "smb || smb2 || tcp.port == 445 || tcp.port == 139",
                QColor(0, 0, 0),
                QColor(255, 228, 196),  // Bisque
                true, 28
            ));

            // NFS - Cam vàng (chia sẻ file Unix)
            rules.append(ColorRule(
                "NFS",
                "nfs || tcp.port == 2049",
                QColor(0, 0, 0),
                QColor(255, 239, 213),  // Papaya whip
                true, 27
            ));

            // ==================== EMAIL (Priority 25-28) ====================

            // SMTP - Cam nhạt (gửi mail)
            rules.append(ColorRule(
                "SMTP",
                "smtp || tcp.port == 25 || tcp.port == 587",
                QColor(0, 0, 0),
                QColor(255, 245, 220),  // Nền cam rất nhạt
                true, 28
            ));

            // POP3 - Vàng nhạt (nhận mail)
            rules.append(ColorRule(
                "POP3",
                "pop || tcp.port == 110 || tcp.port == 995",
                QColor(0, 0, 0),
                QColor(255, 250, 205),  // Lemon chiffon
                true, 27
            ));

            // IMAP - Vàng xanh (nhận mail)
            rules.append(ColorRule(
                "IMAP",
                "imap || tcp.port == 143 || tcp.port == 993",
                QColor(0, 0, 0),
                QColor(240, 255, 240),  // Honeydew
                true, 26
            ));

            // ==================== DNS & DHCP (Priority 20-25) ====================

            // DNS - Tím nhạt (phân giải tên miền)
            rules.append(ColorRule(
                "DNS",
                "dns",
                QColor(0, 0, 0),
                QColor(240, 230, 255),  // Nền tím nhạt
                true, 25
            ));

            // DHCP - Xanh lơ (cấp phát IP)
            rules.append(ColorRule(
                "DHCP",
                "dhcp || bootp",
                QColor(0, 0, 0),
                QColor(224, 255, 255),  // Light cyan
                true, 24
            ));

            // mDNS/Bonjour - Tím nhạt hơn
            rules.append(ColorRule(
                "mDNS",
                "mdns || udp.port == 5353",
                QColor(0, 0, 0),
                QColor(245, 240, 255),
                true, 23
            ));

            // ==================== DATABASE (Priority 20-25) ====================

            // MySQL - Xanh dương nhạt
            rules.append(ColorRule(
                "MySQL",
                "mysql || tcp.port == 3306",
                QColor(0, 0, 0),
                QColor(220, 235, 255),
                true, 23
            ));

            // PostgreSQL - Xanh dương đậm hơn
            rules.append(ColorRule(
                "PostgreSQL",
                "pgsql || tcp.port == 5432",
                QColor(0, 0, 0),
                QColor(200, 225, 255),
                true, 22
            ));

            // MongoDB - Xanh lá
            rules.append(ColorRule(
                "MongoDB",
                "mongodb || tcp.port == 27017",
                QColor(0, 0, 0),
                QColor(220, 255, 220),
                true, 21
            ));

            // Redis - Đỏ nhạt
            rules.append(ColorRule(
                "Redis",
                "redis || tcp.port == 6379",
                QColor(0, 0, 0),
                QColor(255, 230, 230),
                true, 20
            ));

            // ==================== NETWORK PROTOCOLS (Priority 15-20) ====================

            // ARP - Vàng cam (địa chỉ MAC)
            rules.append(ColorRule(
                "ARP",
                "arp",
                QColor(0, 0, 0),
                QColor(255, 245, 220),  // Nền vàng cam nhạt
                true, 18
            ));

            // ICMP - Xanh lơ (ping, traceroute)
            rules.append(ColorRule(
                "ICMP",
                "icmp",
                QColor(0, 0, 0),
                QColor(230, 250, 255),  // Nền xanh lơ nhạt
                true, 17
            ));

            // IGMP - Xanh lục nhạt (multicast)
            rules.append(ColorRule(
                "IGMP",
                "igmp",
                QColor(0, 0, 0),
                QColor(240, 255, 240),
                true, 16
            ));

            // ==================== STREAMING & MEDIA (Priority 15-18) ====================

            // RTP - Tím hồng (voice/video)
            rules.append(ColorRule(
                "RTP",
                "rtp",
                QColor(0, 0, 0),
                QColor(255, 230, 255),  // Lavender
                true, 18
            ));

            // RTSP - Tím nhạt (streaming control)
            rules.append(ColorRule(
                "RTSP",
                "rtsp || tcp.port == 554",
                QColor(0, 0, 0),
                QColor(245, 230, 255),
                true, 17
            ));

            // SIP - Hồng nhạt (VoIP)
            rules.append(ColorRule(
                "SIP",
                "sip",
                QColor(0, 0, 0),
                QColor(255, 240, 245),
                true, 16
            ));

            // ==================== TRANSPORT LAYER (Priority 5-10) ====================

            // TCP - Xanh nhạt (mặc định)
            rules.append(ColorRule(
                "TCP",
                "tcp",
                QColor(0, 0, 0),
                QColor(240, 248, 255),  // Nền xanh rất nhạt
                true, 10
            ));

            // UDP - Xanh lá rất nhạt (mặc định)
            rules.append(ColorRule(
                "UDP",
                "udp",
                QColor(0, 0, 0),
                QColor(245, 255, 245),  // Nền xanh lá rất nhạt
                true, 10
            ));

            // SCTP - Xanh tím nhạt
            rules.append(ColorRule(
                "SCTP",
                "sctp",
                QColor(0, 0, 0),
                QColor(240, 240, 255),
                true, 10
            ));

            // ==================== SECURITY & VPN (Priority 30-35) ====================

            // IPsec - Xanh đậm (VPN)
            rules.append(ColorRule(
                "IPsec",
                "esp || ah || isakmp",
                QColor(255, 255, 255),
                QColor(100, 149, 237),  // Cornflower blue
                true, 35
            ));

            // OpenVPN - Xanh lục đậm
            rules.append(ColorRule(
                "OpenVPN",
                "openvpn || udp.port == 1194",
                QColor(255, 255, 255),
                QColor(60, 179, 113),   // Medium sea green
                true, 34
            ));

            // WireGuard - Xanh navy
            rules.append(ColorRule(
                "WireGuard",
                "udp.port == 51820",
                QColor(255, 255, 255),
                QColor(25, 25, 112),    // Midnight blue
                true, 33
            ));

            // ==================== MONITORING & MANAGEMENT (Priority 15-20) ====================

            // SNMP - Vàng nhạt (giám sát)
            rules.append(ColorRule(
                "SNMP",
                "snmp || udp.port == 161 || udp.port == 162",
                QColor(0, 0, 0),
                QColor(255, 255, 224),
                true, 20
            ));

            // Syslog - Cam nhạt (log)
            rules.append(ColorRule(
                "Syslog",
                "syslog || udp.port == 514",
                QColor(0, 0, 0),
                QColor(255, 248, 220),
                true, 19
            ));

            // NetFlow - Xanh lơ (phân tích traffic)
            rules.append(ColorRule(
                "NetFlow",
                "cflow || udp.port == 2055",
                QColor(0, 0, 0),
                QColor(230, 245, 255),
                true, 18
            ));

            return rules;
        }

        // ==================== Create Helper Functions ====================

        ColorRule ColorRules::createTCPRule()
        {
            return ColorRule("TCP", "tcp", 
                           QColor(0, 0, 0), QColor(240, 248, 255));
        }

        ColorRule ColorRules::createUDPRule()
        {
            return ColorRule("UDP", "udp",
                           QColor(0, 0, 0), QColor(245, 255, 245));
        }

        ColorRule ColorRules::createICMPRule()
        {
            return ColorRule("ICMP", "icmp",
                           QColor(0, 0, 0), QColor(230, 250, 255));
        }

        ColorRule ColorRules::createARPRule()
        {
            return ColorRule("ARP", "arp",
                           QColor(0, 0, 0), QColor(255, 245, 220));
        }

        ColorRule ColorRules::createHTTPRule()
        {
            return ColorRule("HTTP", "http",
                           QColor(0, 0, 0), QColor(220, 255, 220));
        }

        ColorRule ColorRules::createHTTPSRule()
        {
            return ColorRule("HTTPS", "ssl || tls",
                           QColor(0, 0, 0), QColor(200, 220, 255));
        }

        ColorRule ColorRules::createDNSRule()
        {
            return ColorRule("DNS", "dns",
                           QColor(0, 0, 0), QColor(240, 230, 255));
        }

        ColorRule ColorRules::createErrorRule()
        {
            return ColorRule("Error", "tcp.analysis.flags",
                           QColor(139, 0, 0), QColor(255, 220, 220));
        }

        ColorRule ColorRules::createWarningRule()
        {
            return ColorRule("Warning", "tcp.analysis.retransmission",
                           QColor(184, 92, 0), QColor(255, 235, 200));
        }

        ColorRule ColorRules::createRetransmissionRule()
        {
            return ColorRule("Retransmission", "tcp.analysis.retransmission",
                           QColor(184, 92, 0), QColor(255, 235, 200));
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
            if (f == "ftp" || f == "ftp-data") return packet.app_protocol == Common::AppProtocol::FTP;
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

            // Port-based detection
            if (f.contains("tcp.port") && packet.has_tcp) {
                QString port_str = f.mid(f.indexOf("==") + 2).trimmed();
                uint16_t port = port_str.toUInt();
                return packet.tcp.src_port == port || packet.tcp.dst_port == port;
            }
            if (f.contains("udp.port") && packet.has_udp) {
                QString port_str = f.mid(f.indexOf("==") + 2).trimmed();
                uint16_t port = port_str.toUInt();
                return packet.udp.src_port == port || packet.udp.dst_port == port;
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
