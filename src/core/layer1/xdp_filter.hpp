// src/core/layer1/xdp_filter.hpp
#ifndef XDP_FILTER_HPP
#define XDP_FILTER_HPP

#include "../../common/utils.hpp"
#include "../../common/logger.hpp"
#include "../../common/config_manager.hpp"
#include "../../common/network_utils.hpp"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            /**
             * @brief XDP Action codes
             */
            enum class XDPAction : uint32_t
            {
                ABORTED = XDP_ABORTED,  // Error, drop packet
                DROP = XDP_DROP,        // Drop packet
                PASS = XDP_PASS,        // Pass to normal network stack
                TX = XDP_TX,            // Transmit packet
                REDIRECT = XDP_REDIRECT // Redirect to another interface
            };

            /**
             * @brief XDP Attach mode
             */
            enum class XDPMode : uint32_t
            {
                SKB = XDP_FLAGS_SKB_MODE,        // Generic mode (slowest, compatible)
                DRV = XDP_FLAGS_DRV_MODE,        // Driver mode (fast)
                HW = XDP_FLAGS_HW_MODE,          // Hardware offload (fastest)
                AUTO = XDP_FLAGS_UPDATE_IF_NOEXIST
            };

            /**
             * @brief Blacklist entry - simple structure
             */
            struct BlacklistEntry
            {
                uint32_t ip_addr;           // Network byte order
                uint32_t netmask;           // Network byte order (for CIDR)
                std::string ip_string;      // Human readable
                std::string comment;        // Comment from file
                uint64_t added_time;        // When added

                BlacklistEntry()
                    : ip_addr(0), netmask(0xFFFFFFFF), added_time(0) {}

                BlacklistEntry(uint32_t ip, uint32_t mask, const std::string& ip_str, const std::string& cmt)
                    : ip_addr(ip), netmask(mask), ip_string(ip_str), comment(cmt),
                      added_time(Common::Utils::getCurrentTimestampMs()) {}

                // Check if test_ip matches this entry
                bool matches(uint32_t test_ip) const
                {
                    return (test_ip & netmask) == (ip_addr & netmask);
                }
            };

            /**
             * @brief Rate limit entry (per IP)
             */
            struct RateLimitEntry
            {
                uint32_t ip_addr;
                uint64_t packet_count;
                uint64_t byte_count;
                uint64_t window_start;      // Timestamp của window hiện tại
                uint64_t last_packet_time;

                RateLimitEntry()
                    : ip_addr(0), packet_count(0), byte_count(0),
                      window_start(0), last_packet_time(0) {}
            };

            /**
             * @brief Rate limit configuration
             */
            struct RateLimitConfig
            {
                uint64_t max_packets_per_sec;
                uint64_t max_bytes_per_sec;
                uint64_t window_size_ms;        // Time window size (default 1000ms)

                RateLimitConfig()
                    : max_packets_per_sec(10000),
                      max_bytes_per_sec(100 * 1024 * 1024), // 100 MB/s
                      window_size_ms(1000) {}
            };

            /**
             * @brief XDP program statistics
             */
            struct XDPStatistics
            {
                std::atomic<uint64_t> total_packets{0};
                std::atomic<uint64_t> passed_packets{0};
                std::atomic<uint64_t> dropped_packets{0};
                std::atomic<uint64_t> malformed_packets{0};
                std::atomic<uint64_t> blacklisted_packets{0};
                std::atomic<uint64_t> rate_limited_packets{0};
                std::atomic<uint64_t> total_bytes{0};
                std::atomic<uint64_t> dropped_bytes{0};
                
                uint64_t start_time;
                uint64_t last_update_time;

                XDPStatistics() 
                    : start_time(Common::Utils::getCurrentTimestampMs()),
                      last_update_time(start_time) {}

                void reset()
                {
                    total_packets = 0;
                    passed_packets = 0;
                    dropped_packets = 0;
                    malformed_packets = 0;
                    blacklisted_packets = 0;
                    rate_limited_packets = 0;
                    total_bytes = 0;
                    dropped_bytes = 0;
                    start_time = Common::Utils::getCurrentTimestampMs();
                    last_update_time = start_time;
                }

                double getDropRate() const
                {
                    uint64_t total = total_packets.load();
                    if (total == 0) return 0.0;
                    return (double)dropped_packets.load() / total * 100.0;
                }

                double getThroughputMbps() const
                {
                    uint64_t duration_ms = Common::Utils::getCurrentTimestampMs() - start_time;
                    if (duration_ms == 0) return 0.0;
                    return (double)total_bytes.load() * 8 / duration_ms / 1000.0;
                }

                uint64_t getPacketsPerSecond() const
                {
                    uint64_t duration_ms = Common::Utils::getCurrentTimestampMs() - start_time;
                    if (duration_ms == 0) return 0;
                    return total_packets.load() * 1000 / duration_ms;
                }
            };

            /**
             * @brief XDP Filter Manager - Simplified Version
             */
            class XDPFilter
            {
            public:
                XDPFilter();
                ~XDPFilter();

                // Prevent copy
                XDPFilter(const XDPFilter&) = delete;
                XDPFilter& operator=(const XDPFilter&) = delete;

                // ==================== Initialization ====================
                /**
                 * @brief Initialize XDP filter
                 * @param interface Network interface name (e.g., "eth0")
                 * @param bpf_program_path Path to compiled BPF object file
                 * @param blacklist_file Path to blacklist.txt file
                 * @param mode XDP attach mode
                 * @return true if successful
                 */
                bool initialize(const std::string& interface,
                              const std::string& bpf_program_path,
                              const std::string& blacklist_file,
                              XDPMode mode = XDPMode::DRV);

                /**
                 * @brief Attach XDP program to interface
                 */
                bool attach();

                /**
                 * @brief Detach XDP program from interface
                 */
                bool detach();

                /**
                 * @brief Check if XDP is attached
                 */
                bool isAttached() const { return is_attached_; }

                /**
                 * @brief Reload BPF program (re-attach)
                 */
                bool reload();

                // ==================== Blacklist Management ====================
                /**
                 * @brief Load blacklist from file
                 * Format: IP_ADDRESS[/PREFIX] [# COMMENT]
                 * Example:
                 *   192.168.1.100
                 *   10.0.0.0/8 # Private network
                 *   203.0.113.50 # Malicious IP
                 */
                bool loadBlacklist(const std::string& file_path);

                /**
                 * @brief Reload blacklist from current file
                 */
                bool reloadBlacklist();

                /**
                 * @brief Add IP to blacklist (runtime)
                 * @param ip_addr IP address (string format)
                 * @param prefix_len CIDR prefix length (default 32 = single IP)
                 * @param comment Optional comment
                 */
                bool addBlacklistIP(const std::string& ip_addr, 
                                   int prefix_len = 32,
                                   const std::string& comment = "");

                /**
                 * @brief Remove IP from blacklist (runtime)
                 */
                bool removeBlacklistIP(const std::string& ip_addr);

                /**
                 * @brief Check if IP is blacklisted
                 */
                bool isBlacklisted(const std::string& ip_addr) const;

                /**
                 * @brief Check if IP (uint32_t) is blacklisted
                 */
                bool isBlacklisted(uint32_t ip_addr) const;

                /**
                 * @brief Clear all blacklist entries
                 */
                void clearBlacklist();

                /**
                 * @brief Get all blacklist entries
                 */
                std::vector<BlacklistEntry> getBlacklistEntries() const;

                /**
                 * @brief Get blacklist count
                 */
                size_t getBlacklistCount() const;

                /**
                 * @brief Save current blacklist to file
                 */
                bool saveBlacklist(const std::string& file_path) const;

                // ==================== Rate Limiting ====================
                /**
                 * @brief Enable/disable rate limiting
                 */
                void setRateLimitEnabled(bool enabled);

                /**
                 * @brief Check if rate limiting is enabled
                 */
                bool isRateLimitEnabled() const { return rate_limit_enabled_; }

                /**
                 * @brief Set global rate limit configuration
                 */
                void setRateLimitConfig(const RateLimitConfig& config);

                /**
                 * @brief Get current rate limit configuration
                 */
                RateLimitConfig getRateLimitConfig() const;

                /**
                 * @brief Clear all rate limit entries
                 */
                void clearRateLimits();

                // ==================== Malformed Packet Detection ====================
                /**
                 * @brief Enable/disable malformed packet detection
                 */
                void setMalformedDetectionEnabled(bool enabled);

                /**
                 * @brief Check if malformed detection is enabled
                 */
                bool isMalformedDetectionEnabled() const { return malformed_detection_enabled_; }

                // ==================== Statistics ====================
                /**
                 * @brief Get current statistics
                 */
                XDPStatistics getStatistics() const;

                /**
                 * @brief Reset statistics
                 */
                void resetStatistics();

                /**
                 * @brief Update statistics from BPF map (kernel-side)
                 */
                bool updateStatisticsFromKernel();

                /**
                 * @brief Print statistics to logger
                 */
                void printStatistics() const;

                /**
                 * @brief Get statistics as formatted string
                 */
                std::string getStatisticsString() const;

                // ==================== BPF Map Synchronization ====================
                /**
                 * @brief Sync blacklist to kernel BPF map
                 * Must be called after modifying blacklist
                 */
                bool syncBlacklistToKernel();

                /**
                 * @brief Sync rate limit config to kernel BPF map
                 */
                bool syncRateLimitConfigToKernel();

                // ==================== Utility ====================
                /**
                 * @brief Get interface name
                 */
                const std::string& getInterface() const { return interface_; }

                /**
                 * @brief Get interface index
                 */
                int getInterfaceIndex() const { return if_index_; }

                /**
                 * @brief Get XDP mode
                 */
                XDPMode getMode() const { return mode_; }

                /**
                 * @brief Get blacklist file path
                 */
                const std::string& getBlacklistFile() const { return blacklist_file_; }

                /**
                 * @brief Check if interface supports XDP
                 */
                static bool isXDPSupported(const std::string& interface);

                /**
                 * @brief Get XDP mode string
                 */
                static std::string xdpModeToString(XDPMode mode);

                /**
                 * @brief Parse CIDR notation (e.g., "192.168.1.0/24")
                 * @param cidr CIDR string
                 * @param ip_out Output IP address
                 * @param netmask_out Output netmask
                 * @return true if parsing successful
                 */
                static bool parseCIDR(const std::string& cidr, 
                                     uint32_t& ip_out, 
                                     uint32_t& netmask_out);

            private:
                // ==================== Internal Methods ====================
                bool loadBPFProgram(const std::string& bpf_program_path);
                bool setupBPFMaps();
                void cleanupBPFMaps();
                bool parseBlacklistLine(const std::string& line, BlacklistEntry& entry);
                uint32_t prefixLenToNetmask(int prefix_len);
                int netmaskToPrefixLen(uint32_t netmask);

                // ==================== Member Variables ====================
                // Interface info
                std::string interface_;
                int if_index_;
                XDPMode mode_;
                bool is_attached_;

                // BPF program
                struct bpf_object* bpf_obj_;
                struct bpf_program* bpf_prog_;
                int prog_fd_;
                std::string bpf_program_path_;

                // BPF maps file descriptors
                int blacklist_map_fd_;      // BPF map for blacklist
                int stats_map_fd_;          // BPF map for statistics
                int config_map_fd_;         // BPF map for configuration

                // Blacklist
                std::string blacklist_file_;
                std::vector<BlacklistEntry> blacklist_entries_;
                mutable std::mutex blacklist_mutex_;

                // Rate limiting
                RateLimitConfig rate_limit_config_;
                std::unordered_map<uint32_t, RateLimitEntry> rate_limit_entries_;
                mutable std::mutex rate_limit_mutex_;
                std::atomic<bool> rate_limit_enabled_;

                // Malformed detection
                std::atomic<bool> malformed_detection_enabled_;

                // Statistics
                mutable XDPStatistics statistics_;
                mutable std::mutex stats_mutex_;

                // Logger
                std::shared_ptr<Common::Logger> logger_;

                // Auto-reload thread
                std::atomic<bool> auto_reload_enabled_;
                std::unique_ptr<std::thread> reload_thread_;
                std::atomic<bool> reload_thread_running_;
                uint64_t last_blacklist_mtime_;  // Last modification time
            };

            /**
             * @brief XDP Filter Builder (Fluent Interface)
             */
            class XDPFilterBuilder
            {
            public:
                XDPFilterBuilder();

                XDPFilterBuilder& setInterface(const std::string& interface);
                XDPFilterBuilder& setBPFProgram(const std::string& path);
                XDPFilterBuilder& setBlacklistFile(const std::string& path);
                XDPFilterBuilder& setMode(XDPMode mode);
                XDPFilterBuilder& enableRateLimit(bool enable);
                XDPFilterBuilder& enableMalformedDetection(bool enable);
                XDPFilterBuilder& setRateLimitConfig(const RateLimitConfig& config);

                std::unique_ptr<XDPFilter> build();

            private:
                std::string interface_;
                std::string bpf_program_path_;
                std::string blacklist_file_;
                XDPMode mode_;
                bool rate_limit_enabled_;
                bool malformed_detection_enabled_;
                RateLimitConfig rate_limit_config_;
            };

        } // namespace Layer1
    }     // namespace Core
} // namespace NetworkSecurity

#endif // XDP_FILTER_HPP
