// src/common/network_utils.hpp
#ifndef NETWORK_UTILS_HPP
#define NETWORK_UTILS_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/in.h>
#include <chrono>
#include <mutex>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Tiện ích mạng
         */
        class NetworkUtils
        {
        public:
            /**
             * @brief IP address utilities
             */
            static bool isValidIPv4(const std::string &ip);
            static bool isValidIPv6(const std::string &ip);
            static uint32_t ipStringToInt(const std::string &ip);
            static std::string ipIntToString(uint32_t ip);
            static bool isPrivateIP(const std::string &ip);
            static bool isLoopbackIP(const std::string &ip);
            static bool isMulticastIP(const std::string &ip);

            /**
             * @brief Network range utilities
             */
            static bool isIPInRange(const std::string &ip, const std::string &network, int prefix_len);
            static bool isIPInCIDR(const std::string &ip, const std::string &cidr);
            static std::vector<std::string> expandCIDR(const std::string &cidr);

            /**
             * @brief Port utilities
             */
            static bool isValidPort(int port);
            static bool isWellKnownPort(int port);
            static bool isRegisteredPort(int port);
            static bool isDynamicPort(int port);
            static std::string getPortService(int port);

            /**
             * @brief Protocol utilities
             */
            static std::string getProtocolName(int protocol_number);
            static int getProtocolNumber(const std::string &protocol_name);
            static bool isTCPProtocol(int protocol);
            static bool isUDPProtocol(int protocol);
            static bool isICMPProtocol(int protocol);

            /**
             * @brief MAC address utilities
             */
            static bool isValidMAC(const std::string &mac);
            static std::string normalizeMACAddress(const std::string &mac);
            static std::string getVendorFromMAC(const std::string &mac);

            /**
             * @brief Network interface utilities
             */
            static std::vector<std::string> getNetworkInterfaces();
            static std::string getInterfaceIP(const std::string &interface);
            static std::string getInterfaceMAC(const std::string &interface);
            static bool isInterfaceUp(const std::string &interface);

            /**
             * @brief DNS utilities
             */
            static std::string resolveHostname(const std::string &ip);
            static std::vector<std::string> resolveIP(const std::string &hostname);
            static bool isValidDomainName(const std::string &domain);

            /**
             * @brief Geolocation utilities
             */
            struct GeoLocation
            {
                std::string country;
                std::string country_code;
                std::string region;
                std::string city;
                double latitude;
                double longitude;
                std::string isp;
                std::string organization;
            };

            static GeoLocation getIPGeolocation(const std::string &ip);
            static bool isIPFromCountry(const std::string &ip, const std::string &country_code);

            /**
             * @brief Network calculation utilities
             */
            static uint32_t calculateNetworkAddress(uint32_t ip, int prefix_len);
            static uint32_t calculateBroadcastAddress(uint32_t ip, int prefix_len);
            static uint32_t calculateSubnetMask(int prefix_len);
            static int calculatePrefixLength(uint32_t subnet_mask);

            /**
             * @brief Traffic analysis utilities
             */
            static double calculatePacketRate(uint64_t packet_count, uint64_t time_window_ms);
            static double calculateBitRate(uint64_t byte_count, uint64_t time_window_ms);
            static double calculateUtilization(uint64_t bytes, uint64_t time_ms, uint64_t bandwidth_bps);

        private:
            NetworkUtils() = default;
            static bool safeStringToInt(const std::string& str, int& result);
            // Helper methods
            static bool isIPv4InRange(uint32_t ip, uint32_t network, uint32_t mask);
            static std::vector<std::string> loadOUIDatabase();
        };

        /**
         * @brief Network statistics
         */
        struct NetworkStats
        {
            uint64_t total_packets;
            uint64_t total_bytes;
            uint64_t tcp_packets;
            uint64_t udp_packets;
            uint64_t icmp_packets;
            uint64_t other_packets;

            double packet_rate;
            double byte_rate;
            double average_packet_size;

            std::chrono::steady_clock::time_point start_time;
            std::chrono::steady_clock::time_point last_update;
        };

        /**
         * @brief Network statistics collector
         */
        class NetworkStatsCollector
        {
        public:
            NetworkStatsCollector();
            ~NetworkStatsCollector();

            void updateStats(size_t packet_size, uint8_t protocol);
            NetworkStats getStats() const;
            void resetStats();

        private:
            mutable std::mutex stats_mutex_;
            NetworkStats stats_;
        };

    } // namespace Common
} // namespace NetworkSecurity

#endif // NETWORK_UTILS_HPP
