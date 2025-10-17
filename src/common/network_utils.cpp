// src/common/network_utils.cpp
#include "network_utils.hpp"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <map>
#include <cstring>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <cctype>      
#include <stdexcept>

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== IP address utilities ====================
        
        bool NetworkUtils::isValidIPv4(const std::string &ip)
        {
            struct sockaddr_in sa;
            return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
        }

        bool NetworkUtils::isValidIPv6(const std::string &ip)
        {
            struct sockaddr_in6 sa;
            return inet_pton(AF_INET6, ip.c_str(), &(sa.sin6_addr)) != 0;
        }

        uint32_t NetworkUtils::ipStringToInt(const std::string &ip)
        {
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) {
                return ntohl(sa.sin_addr.s_addr);
            }
            return 0;
        }

        std::string NetworkUtils::ipIntToString(uint32_t ip)
        {
            struct in_addr addr;
            addr.s_addr = htonl(ip);
            char str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN)) {
                return std::string(str);
            }
            return "";
        }

        bool NetworkUtils::isPrivateIP(const std::string &ip)
        {
            if (!isValidIPv4(ip)) {
                return false;
            }

            uint32_t ip_int = ipStringToInt(ip);
            
            // 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
            if ((ip_int >= 0x0A000000) && (ip_int <= 0x0AFFFFFF)) {
                return true;
            }
            
            // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            if ((ip_int >= 0xAC100000) && (ip_int <= 0xAC1FFFFF)) {
                return true;
            }
            
            // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
            if ((ip_int >= 0xC0A80000) && (ip_int <= 0xC0A8FFFF)) {
                return true;
            }
            
            return false;
        }

        bool NetworkUtils::isLoopbackIP(const std::string &ip)
        {
            if (!isValidIPv4(ip)) {
                return false;
            }

            uint32_t ip_int = ipStringToInt(ip);
            // 127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
            return (ip_int >= 0x7F000000) && (ip_int <= 0x7FFFFFFF);
        }

        bool NetworkUtils::isMulticastIP(const std::string &ip)
        {
            if (!isValidIPv4(ip)) {
                return false;
            }

            uint32_t ip_int = ipStringToInt(ip);
            // 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
            return (ip_int >= 0xE0000000) && (ip_int <= 0xEFFFFFFF);
        }

        // ==================== Network range utilities ====================
        
        bool NetworkUtils::isIPInRange(const std::string &ip, const std::string &network, int prefix_len)
        {
            if (!isValidIPv4(ip) || !isValidIPv4(network) || prefix_len < 0 || prefix_len > 32) {
                return false;
            }

            uint32_t ip_int = ipStringToInt(ip);
            uint32_t network_int = ipStringToInt(network);
            uint32_t mask = calculateSubnetMask(prefix_len);

            return (ip_int & mask) == (network_int & mask);
        }

        // Helper function to safely parse integer
        bool NetworkUtils::safeStringToInt(const std::string& str, int& result)
        {
            if (str.empty()) {
                return false;
            }
            
            // Check if string contains only digits (and optional leading minus)
            size_t start = 0;
            if (str[0] == '-') {
                start = 1;
                if (str.length() == 1) {
                    return false;
                }
            }
            
            for (size_t i = start; i < str.length(); ++i) {
                if (!std::isdigit(str[i])) {
                    return false;
                }
            }
            
            try {
                result = std::stoi(str);
                return true;
            } catch (const std::exception&) {
                return false;
            }
        }
                
        bool NetworkUtils::isIPInCIDR(const std::string &ip, const std::string &cidr)
        {
            size_t slash_pos = cidr.find('/');
            if (slash_pos == std::string::npos) {
                return false;
            }

            std::string network = cidr.substr(0, slash_pos);
            std::string prefix_str = cidr.substr(slash_pos + 1);
            
            // Validate prefix string
            if (prefix_str.empty()) {
                return false;
            }
            
            // Check if prefix string contains only digits
            for (char c : prefix_str) {
                if (!std::isdigit(c)) {
                    return false;
                }
            }
            
            try {
                int prefix_len = std::stoi(prefix_str);
                return isIPInRange(ip, network, prefix_len);
            } catch (const std::exception&) {
                return false;
            }
        }

        std::vector<std::string> NetworkUtils::expandCIDR(const std::string &cidr)
        {
            std::vector<std::string> result;
            
            size_t slash_pos = cidr.find('/');
            if (slash_pos == std::string::npos) {
                return result;
            }

            std::string network = cidr.substr(0, slash_pos);
            std::string prefix_str = cidr.substr(slash_pos + 1);
            
            // Validate prefix string
            if (prefix_str.empty()) {
                return result;
            }
            
            // Check if prefix string contains only digits
            for (char c : prefix_str) {
                if (!std::isdigit(c)) {
                    return result;
                }
            }

            int prefix_len;
            try {
                prefix_len = std::stoi(prefix_str);
            } catch (const std::exception&) {
                return result;
            }

            if (!isValidIPv4(network) || prefix_len < 0 || prefix_len > 32) {
                return result;
            }

            uint32_t network_int = ipStringToInt(network);
            uint32_t mask = calculateSubnetMask(prefix_len);
            uint32_t network_addr = network_int & mask;
            uint32_t host_bits = 32 - prefix_len;
            
            // Avoid overflow for large networks
            if (host_bits >= 32) {
                return result;
            }
            
            uint64_t num_addresses = 1ULL << host_bits;
            
            // Limit expansion size to prevent memory issues
            if (num_addresses > 65536) { // Max 64K addresses
                return result;
            }
            
            uint32_t num_hosts = static_cast<uint32_t>(num_addresses) - 2; // Exclude network and broadcast

            // Handle special cases
            if (prefix_len >= 31) {
                return result; // /31 and /32 have no host addresses
            }

            for (uint32_t i = 1; i <= num_hosts; ++i) {
                result.push_back(ipIntToString(network_addr + i));
            }

            return result;
        }

        // ==================== Port utilities ====================
        
        bool NetworkUtils::isValidPort(int port)
        {
            return port >= 1 && port <= 65535;
        }

        bool NetworkUtils::isWellKnownPort(int port)
        {
            return port >= 1 && port <= 1023;
        }

        bool NetworkUtils::isRegisteredPort(int port)
        {
            return port >= 1024 && port <= 49151;
        }

        bool NetworkUtils::isDynamicPort(int port)
        {
            return port >= 49152 && port <= 65535;
        }

        std::string NetworkUtils::getPortService(int port)
        {
            static std::map<int, std::string> well_known_ports = {
                {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"},
                {25, "SMTP"}, {53, "DNS"}, {67, "DHCP-SERVER"}, {68, "DHCP-CLIENT"},
                {69, "TFTP"}, {80, "HTTP"}, {110, "POP3"}, {123, "NTP"},
                {143, "IMAP"}, {161, "SNMP"}, {162, "SNMP-TRAP"}, {179, "BGP"},
                {389, "LDAP"}, {443, "HTTPS"}, {465, "SMTPS"}, {514, "SYSLOG"},
                {587, "SMTP-SUBMISSION"}, {636, "LDAPS"}, {993, "IMAPS"}, {995, "POP3S"},
                {1433, "MSSQL"}, {1521, "ORACLE"}, {3306, "MYSQL"}, {3389, "RDP"},
                {5432, "POSTGRESQL"}, {5900, "VNC"}, {6379, "REDIS"}, {8080, "HTTP-ALT"}
            };

            auto it = well_known_ports.find(port);
            if (it != well_known_ports.end()) {
                return it->second;
            }

            // Try system service lookup
            struct servent *service = getservbyport(htons(port), nullptr);
            if (service) {
                return std::string(service->s_name);
            }

            return "UNKNOWN";
        }

        // ==================== Protocol utilities ====================
        
        std::string NetworkUtils::getProtocolName(int protocol_number)
        {
            static std::map<int, std::string> protocols = {
                {1, "ICMP"}, {2, "IGMP"}, {6, "TCP"}, {17, "UDP"},
                {41, "IPv6"}, {47, "GRE"}, {50, "ESP"}, {51, "AH"},
                {58, "ICMPv6"}, {89, "OSPF"}, {132, "SCTP"}
            };

            auto it = protocols.find(protocol_number);
            if (it != protocols.end()) {
                return it->second;
            }

            struct protoent *proto = getprotobynumber(protocol_number);
            if (proto) {
                return std::string(proto->p_name);
            }

            return "UNKNOWN";
        }

        int NetworkUtils::getProtocolNumber(const std::string &protocol_name)
        {
            static std::map<std::string, int> protocols = {
                {"ICMP", 1}, {"IGMP", 2}, {"TCP", 6}, {"UDP", 17},
                {"IPv6", 41}, {"GRE", 47}, {"ESP", 50}, {"AH", 51},
                {"ICMPv6", 58}, {"OSPF", 89}, {"SCTP", 132}
            };

            std::string upper_name = protocol_name;
            std::transform(upper_name.begin(), upper_name.end(), upper_name.begin(), ::toupper);

            auto it = protocols.find(upper_name);
            if (it != protocols.end()) {
                return it->second;
            }

            struct protoent *proto = getprotobyname(protocol_name.c_str());
            if (proto) {
                return proto->p_proto;
            }

            return -1;
        }

        bool NetworkUtils::isTCPProtocol(int protocol)
        {
            return protocol == 6;
        }

        bool NetworkUtils::isUDPProtocol(int protocol)
        {
            return protocol == 17;
        }

        bool NetworkUtils::isICMPProtocol(int protocol)
        {
            return protocol == 1 || protocol == 58; // ICMP or ICMPv6
        }

        // ==================== MAC address utilities ====================
        
        bool NetworkUtils::isValidMAC(const std::string &mac)
        {
            // Support formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX
            std::regex mac_regex1("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
            std::regex mac_regex2("^[0-9A-Fa-f]{12}$");
            
            return std::regex_match(mac, mac_regex1) || std::regex_match(mac, mac_regex2);
        }

        std::string NetworkUtils::normalizeMACAddress(const std::string &mac)
        {
            if (!isValidMAC(mac)) {
                return "";
            }

            std::string normalized = mac;
            // Remove separators
            normalized.erase(std::remove(normalized.begin(), normalized.end(), ':'), normalized.end());
            normalized.erase(std::remove(normalized.begin(), normalized.end(), '-'), normalized.end());
            
            // Convert to uppercase
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::toupper);
            
            // Add colons
            std::string result;
            for (size_t i = 0; i < normalized.length(); i += 2) {
                if (i > 0) result += ":";
                result += normalized.substr(i, 2);
            }
            
            return result;
        }

        std::string NetworkUtils::getVendorFromMAC(const std::string &mac)
        {
            std::string normalized = normalizeMACAddress(mac);
            if (normalized.empty()) {
                return "UNKNOWN";
            }

            // Extract OUI (first 3 octets)
            std::string oui = normalized.substr(0, 8); // XX:XX:XX

            // Simple vendor lookup (in practice, you'd load from OUI database)
            static std::map<std::string, std::string> vendors = {
                {"00:00:0C", "Cisco Systems"},
                {"00:01:42", "Parallels"},
                {"00:03:47", "Intel Corporation"},
                {"00:0C:29", "VMware"},
                {"00:15:5D", "Microsoft Corporation"},
                {"00:16:3E", "Xensource"},
                {"00:1B:21", "Intel Corporation"},
                {"00:50:56", "VMware"},
                {"08:00:27", "PCS Systemtechnik GmbH"},
                {"52:54:00", "QEMU/KVM"}
            };

            auto it = vendors.find(oui);
            if (it != vendors.end()) {
                return it->second;
            }

            return "UNKNOWN";
        }

        // ==================== Network interface utilities ====================
        
        std::vector<std::string> NetworkUtils::getNetworkInterfaces()
        {
            std::vector<std::string> interfaces;
            struct ifaddrs *ifaddr, *ifa;

            if (getifaddrs(&ifaddr) == -1) {
                return interfaces;
            }

            for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == nullptr) continue;
                
                if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
                    std::string interface_name(ifa->ifa_name);
                    if (std::find(interfaces.begin(), interfaces.end(), interface_name) == interfaces.end()) {
                        interfaces.push_back(interface_name);
                    }
                }
            }

            freeifaddrs(ifaddr);
            return interfaces;
        }

        std::string NetworkUtils::getInterfaceIP(const std::string &interface)
        {
            struct ifaddrs *ifaddr, *ifa;
            char host[NI_MAXHOST];

            if (getifaddrs(&ifaddr) == -1) {
                return "";
            }

            for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == nullptr) continue;
                
                if (ifa->ifa_addr->sa_family == AF_INET && 
                    std::string(ifa->ifa_name) == interface) {
                    
                    int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                      host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
                    if (s == 0) {
                        freeifaddrs(ifaddr);
                        return std::string(host);
                    }
                }
            }

            freeifaddrs(ifaddr);
            return "";
        }

        std::string NetworkUtils::getInterfaceMAC(const std::string &interface)
        {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                return "";
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                close(fd);
                
                unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                
                return std::string(mac_str);
            }

            close(fd);
            return "";
        }

        bool NetworkUtils::isInterfaceUp(const std::string &interface)
        {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                return false;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
                close(fd);
                return (ifr.ifr_flags & IFF_UP) != 0;
            }

            close(fd);
            return false;
        }

        // ==================== DNS utilities ====================
        
        std::string NetworkUtils::resolveHostname(const std::string &ip)
        {
            struct sockaddr_in sa;
            char hostname[NI_MAXHOST];

            sa.sin_family = AF_INET;
            if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
                return "";
            }

            int result = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
                                   hostname, sizeof(hostname), nullptr, 0, 0);
            
            if (result == 0) {
                return std::string(hostname);
            }

            return "";
        }

        std::vector<std::string> NetworkUtils::resolveIP(const std::string &hostname)
        {
            std::vector<std::string> ips;
            struct addrinfo hints, *result, *rp;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET; // IPv4
            hints.ai_socktype = SOCK_STREAM;

            int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
            if (status != 0) {
                return ips;
            }

            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)rp->ai_addr;
                char ip_str[INET_ADDRSTRLEN];
                
                if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                    ips.push_back(std::string(ip_str));
                }
            }

            freeaddrinfo(result);
            return ips;
        }

        bool NetworkUtils::isValidDomainName(const std::string &domain)
        {
            if (domain.empty() || domain.length() > 253) {
                return false;
            }

            // Basic domain name validation
            std::regex domain_regex("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
            return std::regex_match(domain, domain_regex);
        }

        // ==================== Geolocation utilities ====================
        
        NetworkUtils::GeoLocation NetworkUtils::getIPGeolocation(const std::string &ip)
        {
            GeoLocation location;
            location.country = "Unknown";
            location.country_code = "XX";
            location.region = "Unknown";
            location.city = "Unknown";
            location.latitude = 0.0;
            location.longitude = 0.0;
            location.isp = "Unknown";
            location.organization = "Unknown";

            // In a real implementation, you would:
            // 1. Query a geolocation database (MaxMind GeoIP2, IP2Location, etc.)
            // 2. Or make API calls to geolocation services
            // 3. Parse the response and populate the GeoLocation struct

            // Simple example for private/local IPs
            if (isPrivateIP(ip) || isLoopbackIP(ip)) {
                location.country = "Private/Local";
                location.country_code = "PR";
            }

            return location;
        }

        bool NetworkUtils::isIPFromCountry(const std::string &ip, const std::string &country_code)
        {
            GeoLocation location = getIPGeolocation(ip);
            return location.country_code == country_code;
        }

        // ==================== Network calculation utilities ====================
        
        uint32_t NetworkUtils::calculateNetworkAddress(uint32_t ip, int prefix_len)
        {
            uint32_t mask = calculateSubnetMask(prefix_len);
            return ip & mask;
        }

        uint32_t NetworkUtils::calculateBroadcastAddress(uint32_t ip, int prefix_len)
        {
            uint32_t mask = calculateSubnetMask(prefix_len);
            uint32_t network = ip & mask;
            uint32_t host_mask = ~mask;
            return network | host_mask;
        }

        uint32_t NetworkUtils::calculateSubnetMask(int prefix_len)
        {
            if (prefix_len < 0 || prefix_len > 32) {
                return 0;
            }
            
            if (prefix_len == 0) {
                return 0;
            }
            
            return 0xFFFFFFFF << (32 - prefix_len);
        }

        int NetworkUtils::calculatePrefixLength(uint32_t subnet_mask)
        {
            if (subnet_mask == 0) {
                return 0;
            }
            
            int prefix_len = 0;
            while (subnet_mask & 0x80000000) {
                prefix_len++;
                subnet_mask <<= 1;
            }
            
            return prefix_len;
        }

        // ==================== Traffic analysis utilities ====================
        
        double NetworkUtils::calculatePacketRate(uint64_t packet_count, uint64_t time_window_ms)
        {
            if (time_window_ms == 0) {
                return 0.0;
            }
            
            return (double)packet_count * 1000.0 / (double)time_window_ms;
        }

        double NetworkUtils::calculateBitRate(uint64_t byte_count, uint64_t time_window_ms)
        {
            if (time_window_ms == 0) {
                return 0.0;
            }
            
            return (double)byte_count * 8.0 * 1000.0 / (double)time_window_ms;
        }

        double NetworkUtils::calculateUtilization(uint64_t bytes, uint64_t time_ms, uint64_t bandwidth_bps)
        {
            if (time_ms == 0 || bandwidth_bps == 0) {
                return 0.0;
            }
            
            double bit_rate = calculateBitRate(bytes, time_ms);
            return (bit_rate / (double)bandwidth_bps) * 100.0;
        }

        // ==================== Helper methods ====================
        
        bool NetworkUtils::isIPv4InRange(uint32_t ip, uint32_t network, uint32_t mask)
        {
            return (ip & mask) == (network & mask);
        }

        std::vector<std::string> NetworkUtils::loadOUIDatabase()
        {
            // In a real implementation, load OUI database from file
            // This is just a placeholder
            return std::vector<std::string>();
        }

        // ==================== NetworkStatsCollector implementation ====================
        
        NetworkStatsCollector::NetworkStatsCollector()
        {
            resetStats();
        }

        NetworkStatsCollector::~NetworkStatsCollector() = default;

        void NetworkStatsCollector::updateStats(size_t packet_size, uint8_t protocol)
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            
            auto now = std::chrono::steady_clock::now();
            
            stats_.total_packets++;
            stats_.total_bytes += packet_size;
            
            switch (protocol) {
                case 6:  // TCP
                    stats_.tcp_packets++;
                    break;
                case 17: // UDP
                    stats_.udp_packets++;
                    break;
                case 1:  // ICMP
                case 58: // ICMPv6
                    stats_.icmp_packets++;
                    break;
                default:
                    stats_.other_packets++;
                    break;
            }
            
            // Calculate rates
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - stats_.start_time);
            if (duration.count() > 0) {
                stats_.packet_rate = NetworkUtils::calculatePacketRate(stats_.total_packets, duration.count());
                stats_.byte_rate = NetworkUtils::calculateBitRate(stats_.total_bytes, duration.count());
            }
            
            // Calculate average packet size
            if (stats_.total_packets > 0) {
                stats_.average_packet_size = (double)stats_.total_bytes / (double)stats_.total_packets;
            }
            
            stats_.last_update = now;
        }

        NetworkStats NetworkStatsCollector::getStats() const
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            return stats_;
        }

        void NetworkStatsCollector::resetStats()
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            
            stats_.total_packets = 0;
            stats_.total_bytes = 0;
            stats_.tcp_packets = 0;
            stats_.udp_packets = 0;
            stats_.icmp_packets = 0;
            stats_.other_packets = 0;
            
            stats_.packet_rate = 0.0;
            stats_.byte_rate = 0.0;
            stats_.average_packet_size = 0.0;
            
            stats_.start_time = std::chrono::steady_clock::now();
            stats_.last_update = stats_.start_time;
        }

    } // namespace Common
} // namespace NetworkSecurity
