// src/core/layer1/xdp_filter.hpp
#ifndef NETWORK_SECURITY_XDP_FILTER_HPP
#define NETWORK_SECURITY_XDP_FILTER_HPP

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstring>

#include "../../common/logger.hpp"
#include "../../common/config_manager.hpp"

// Forward declarations to avoid header conflicts
struct bpf_object;
struct bpf_program;
struct bpf_link;
struct bpf_map;

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            // ==================== XDP Action Types ====================
            enum class XDPAction
            {
                PASS = 0,    // XDP_PASS - Cho phép gói tin đi qua
                DROP = 1,    // XDP_DROP - Loại bỏ gói tin
                ABORTED = 2, // XDP_ABORTED - Lỗi xử lý
                TX = 3,      // XDP_TX - Gửi lại gói tin
                REDIRECT = 4 // XDP_REDIRECT - Chuyển hướng
            };

            // ==================== XDP Statistics ====================
            struct XDPStats
            {
                uint64_t total_packets;
                uint64_t passed_packets;
                uint64_t dropped_packets;
                uint64_t blacklist_hits;
                uint64_t rate_limit_hits;
                uint64_t malformed_packets;
                uint64_t processing_errors;
                
                double drop_rate;
                double blacklist_hit_rate;
                
                XDPStats()
                    : total_packets(0), passed_packets(0), dropped_packets(0),
                      blacklist_hits(0), rate_limit_hits(0), malformed_packets(0),
                      processing_errors(0), drop_rate(0.0), blacklist_hit_rate(0.0)
                {
                }
            };

            // ==================== Blacklist Entry ====================
            struct BlacklistEntry
            {
                uint32_t ip_address;     // Network byte order
                uint64_t timestamp;      // Thời gian thêm vào blacklist
                std::string reason;      // Lý do blacklist
                bool is_permanent;       // Blacklist vĩnh viễn hay tạm thời
                
                BlacklistEntry()
                    : ip_address(0), timestamp(0), is_permanent(false)
                {
                }
            };

            // ==================== XDP Filter Configuration ====================
            struct XDPFilterConfig
            {
                std::string interface_name;           // Network interface (eth0, ens33, etc.)
                std::string xdp_program_path;         // Path to compiled eBPF object file
                bool enable_ip_blacklist;
                bool enable_domain_blacklist;
                bool enable_hash_blacklist;
                bool enable_rate_limiting;
                uint32_t rate_limit_pps;              // Packets per second limit
                uint32_t blacklist_sync_interval_sec; // Sync interval in seconds
                uint32_t xdp_flags;                   // XDP attach flags
                std::string ip_blacklist_file;
                std::string domain_blacklist_file;
                std::string hash_blacklist_file;
                
                XDPFilterConfig()
                    : interface_name("eth0"),
                      xdp_program_path("xdp_filter.bpf.o"),
                      enable_ip_blacklist(true),
                      enable_domain_blacklist(true),
                      enable_hash_blacklist(true),
                      enable_rate_limiting(true),
                      rate_limit_pps(100000),
                      blacklist_sync_interval_sec(60),
                      xdp_flags(0x04 | 0x02), // XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE
                      ip_blacklist_file("data/blacklists/ip_blacklist.txt"),
                      domain_blacklist_file("data/blacklists/domain_blacklist.txt"),
                      hash_blacklist_file("data/blacklists/malware_hashes.txt")
                {
                }
            };

            // ==================== XDP Filter Class ====================
            class XDPFilter
            {
            public:
                XDPFilter();
                ~XDPFilter();

                // ==================== Initialization ====================
                bool initialize(const XDPFilterConfig &config);
                bool loadXDPProgram();
                bool attachToInterface();
                bool detachFromInterface();
                void shutdown();

                // ==================== Blacklist Management ====================
                bool loadIPBlacklist(const std::string &file_path);
                bool loadDomainBlacklist(const std::string &file_path);
                bool loadHashBlacklist(const std::string &file_path);
                
                bool addIPToBlacklist(uint32_t ip_address, const std::string &reason, bool permanent = false);
                bool removeIPFromBlacklist(uint32_t ip_address);
                bool isIPBlacklisted(uint32_t ip_address) const;
                
                bool addDomainToBlacklist(const std::string &domain, const std::string &reason);
                bool removeDomainFromBlacklist(const std::string &domain);
                bool isDomainBlacklisted(const std::string &domain) const;
                
                bool addHashToBlacklist(const std::string &hash, const std::string &reason);
                bool removeHashFromBlacklist(const std::string &hash);
                bool isHashBlacklisted(const std::string &hash) const;

                // ==================== BPF Map Operations ====================
                bool updateBPFMap(const std::string &map_name, const void *key, const void *value);
                bool deleteBPFMapEntry(const std::string &map_name, const void *key);
                bool lookupBPFMap(const std::string &map_name, const void *key, void *value);
                bool syncBlacklistsToBPF();

                // ==================== Statistics ====================
                XDPStats getStatistics() const;
                void resetStatistics();
                void updateStatistics();
                void printStatistics() const;

                // ==================== Configuration ====================
                void setConfig(const XDPFilterConfig &config);
                XDPFilterConfig getConfig() const;
                
                bool setRateLimit(uint32_t pps);
                uint32_t getRateLimit() const;

                // ==================== Status ====================
                bool isRunning() const { return is_running_; }
                bool isAttached() const { return is_attached_; }
                std::string getInterfaceName() const { return config_.interface_name; }
                int getInterfaceIndex() const { return interface_index_; }

            private:
                // ==================== Internal Methods ====================
                int getInterfaceIndexByName(const std::string &interface_name);
                bool createBPFMaps();
                bool loadBPFObject();
                bool findBPFMaps();
                
                uint32_t ipStringToInt(const std::string &ip) const;
                std::string ipIntToString(uint32_t ip) const;
                
                bool validateIPAddress(const std::string &ip) const;
                bool validateDomain(const std::string &domain) const;
                bool validateHash(const std::string &hash) const;

                void startBlacklistSyncThread();
                void stopBlacklistSyncThread();
                void blacklistSyncLoop();

                // ==================== Member Variables ====================
                XDPFilterConfig config_;
                
                // BPF related (using forward declarations)
                struct bpf_object *bpf_obj_;
                struct bpf_program *bpf_prog_;
                struct bpf_link *bpf_link_;
                int prog_fd_;
                int interface_index_;
                
                // BPF Maps
                int ip_blacklist_map_fd_;
                int domain_blacklist_map_fd_;
                int hash_blacklist_map_fd_;
                int stats_map_fd_;
                int config_map_fd_;
                
                // Blacklist storage (userspace cache)
                std::unordered_set<uint32_t> ip_blacklist_;
                std::unordered_set<std::string> domain_blacklist_;
                std::unordered_set<std::string> hash_blacklist_;
                std::unordered_map<uint32_t, BlacklistEntry> ip_blacklist_details_;
                
                mutable std::mutex blacklist_mutex_;
                
                // Statistics
                mutable XDPStats stats_;
                mutable std::mutex stats_mutex_;
                
                // State
                std::atomic<bool> is_running_;
                std::atomic<bool> is_attached_;
                std::atomic<bool> sync_thread_stop_;
                
                std::thread sync_thread_;
                
                // Logger
                std::shared_ptr<Common::Logger> logger_;
            };

        } // namespace Layer1
    }     // namespace Core
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_XDP_FILTER_HPP
