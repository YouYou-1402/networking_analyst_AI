// src/core/layer1/xdp_filter.cpp
#include "xdp_filter.hpp"

// Include BPF headers AFTER our headers to avoid conflicts
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../../common/network_utils.hpp"
#include "../../common/utils.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>

// Linux networking
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            // ==================== Constructor/Destructor ====================
            
            XDPFilter::XDPFilter()
                : bpf_obj_(nullptr),
                  bpf_prog_(nullptr),
                  bpf_link_(nullptr),
                  prog_fd_(-1),
                  interface_index_(-1),
                  ip_blacklist_map_fd_(-1),
                  domain_blacklist_map_fd_(-1),
                  hash_blacklist_map_fd_(-1),
                  stats_map_fd_(-1),
                  config_map_fd_(-1),
                  is_running_(false),
                  is_attached_(false),
                  sync_thread_stop_(false)
            {
                logger_ = std::make_shared<Common::Logger>("XDPFilter");
            }

            XDPFilter::~XDPFilter()
            {
                shutdown();
            }

            // ==================== Initialization ====================
            
            bool XDPFilter::initialize(const XDPFilterConfig &config)
            {
                logger_->info("Initializing XDP Filter...");
                
                config_ = config;
                
                // Get interface index
                interface_index_ = getInterfaceIndexByName(config_.interface_name);
                if (interface_index_ < 0)
                {
                    logger_->error("Failed to get interface index for: " + config_.interface_name);
                    return false;
                }
                
                logger_->info("Interface index: " + std::to_string(interface_index_));
                
                // Load XDP program
                if (!loadXDPProgram())
                {
                    logger_->error("Failed to load XDP program");
                    return false;
                }
                
                // Load blacklists
                if (config_.enable_ip_blacklist)
                {
                    if (!loadIPBlacklist(config_.ip_blacklist_file))
                    {
                        logger_->warn("Failed to load IP blacklist from: " + config_.ip_blacklist_file);
                    }
                }
                
                if (config_.enable_domain_blacklist)
                {
                    if (!loadDomainBlacklist(config_.domain_blacklist_file))
                    {
                        logger_->warn("Failed to load domain blacklist from: " + config_.domain_blacklist_file);
                    }
                }
                
                if (config_.enable_hash_blacklist)
                {
                    if (!loadHashBlacklist(config_.hash_blacklist_file))
                    {
                        logger_->warn("Failed to load hash blacklist from: " + config_.hash_blacklist_file);
                    }
                }
                
                // Sync blacklists to BPF maps
                if (!syncBlacklistsToBPF())
                {
                    logger_->error("Failed to sync blacklists to BPF maps");
                    return false;
                }
                
                // Attach to interface
                if (!attachToInterface())
                {
                    logger_->error("Failed to attach XDP program to interface");
                    return false;
                }
                
                // Start blacklist sync thread
                startBlacklistSyncThread();
                
                is_running_ = true;
                logger_->info("XDP Filter initialized successfully");
                
                return true;
            }

            bool XDPFilter::loadXDPProgram()
            {
                logger_->info("Loading XDP program from: " + config_.xdp_program_path);
                
                // Load BPF object file
                if (!loadBPFObject())
                {
                    return false;
                }
                
                // Find BPF program
                bpf_prog_ = bpf_object__find_program_by_name(bpf_obj_, "xdp_filter_main");
                if (!bpf_prog_)
                {
                    logger_->error("Failed to find XDP program 'xdp_filter_main'");
                    return false;
                }
                
                prog_fd_ = bpf_program__fd(bpf_prog_);
                if (prog_fd_ < 0)
                {
                    logger_->error("Failed to get program FD");
                    return false;
                }
                
                logger_->info("XDP program loaded, FD: " + std::to_string(prog_fd_));
                
                // Find BPF maps
                if (!findBPFMaps())
                {
                    return false;
                }
                
                return true;
            }

            bool XDPFilter::loadBPFObject()
            {
                // Try multiple paths for BPF object file
                const char* bpf_paths[] = {
                    config_.xdp_program_path.c_str(),              // User-specified path
                    "/usr/local/share/nsai/bpf/xdp_filter.bpf.o",  // Installed path
                    "build/xdp_filter.bpf.o",                       // Local build
                    "./xdp_filter.bpf.o",                           // Current directory
                    "xdp_filter.bpf.o"                              // Relative path
                };
                
                bool loaded = false;
                for (const char* path : bpf_paths)
                {
                    // Skip empty paths
                    if (!path || strlen(path) == 0)
                        continue;
                        
                    logger_->debug("Trying to load BPF from: " + std::string(path));
                    
                    // Open BPF object file
                    bpf_obj_ = bpf_object__open(path);
                    if (bpf_obj_)
                    {
                        logger_->info("Successfully opened BPF object from: " + std::string(path));
                        loaded = true;
                        break;
                    }
                    else
                    {
                        logger_->debug("Failed to open: " + std::string(path));
                    }
                }
                
                if (!loaded || !bpf_obj_)
                {
                    logger_->error("Failed to open BPF object file from any location");
                    logger_->error("Tried paths:");
                    for (const char* path : bpf_paths)
                    {
                        if (path && strlen(path) > 0)
                            logger_->error("  - " + std::string(path));
                    }
                    return false;
                }
                
                // Load BPF object into kernel
                if (bpf_object__load(bpf_obj_) != 0)
                {
                    logger_->error("Failed to load BPF object into kernel");
                    bpf_object__close(bpf_obj_);
                    bpf_obj_ = nullptr;
                    return false;
                }
                
                return true;
            }


            bool XDPFilter::findBPFMaps()
            {
                // Find IP blacklist map
                struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj_, "ip_blacklist");
                if (map)
                {
                    ip_blacklist_map_fd_ = bpf_map__fd(map);
                    logger_->info("Found IP blacklist map, FD: " + std::to_string(ip_blacklist_map_fd_));
                }
                else
                {
                    logger_->warn("IP blacklist map not found");
                }
                
                // Find domain blacklist map
                map = bpf_object__find_map_by_name(bpf_obj_, "domain_blacklist");
                if (map)
                {
                    domain_blacklist_map_fd_ = bpf_map__fd(map);
                    logger_->info("Found domain blacklist map, FD: " + std::to_string(domain_blacklist_map_fd_));
                }
                else
                {
                    logger_->warn("Domain blacklist map not found");
                }
                
                // Find hash blacklist map
                map = bpf_object__find_map_by_name(bpf_obj_, "hash_blacklist");
                if (map)
                {
                    hash_blacklist_map_fd_ = bpf_map__fd(map);
                    logger_->info("Found hash blacklist map, FD: " + std::to_string(hash_blacklist_map_fd_));
                }
                else
                {
                    logger_->warn("Hash blacklist map not found");
                }
                
                // Find stats map
                map = bpf_object__find_map_by_name(bpf_obj_, "xdp_stats");
                if (map)
                {
                    stats_map_fd_ = bpf_map__fd(map);
                    logger_->info("Found stats map, FD: " + std::to_string(stats_map_fd_));
                }
                
                // Find config map
                map = bpf_object__find_map_by_name(bpf_obj_, "xdp_config");
                if (map)
                {
                    config_map_fd_ = bpf_map__fd(map);
                    logger_->info("Found config map, FD: " + std::to_string(config_map_fd_));
                }
                
                return true;
            }

            bool XDPFilter::attachToInterface()
            {
                logger_->info("Attaching XDP program to interface: " + config_.interface_name);
                
                // Use bpf_xdp_attach with proper options
                LIBBPF_OPTS(bpf_xdp_attach_opts, opts,
                    .old_prog_fd = -1,
                );
                
                int err = bpf_xdp_attach(interface_index_, prog_fd_, config_.xdp_flags, &opts);
                if (err)
                {
                    logger_->error("Failed to attach XDP program: " + std::string(strerror(-err)));
                    return false;
                }
                
                is_attached_ = true;
                logger_->info("XDP program attached successfully");
                
                return true;
            }

            bool XDPFilter::detachFromInterface()
            {
                if (!is_attached_)
                {
                    return true;
                }
                
                logger_->info("Detaching XDP program from interface: " + config_.interface_name);
                
                int err = bpf_xdp_detach(interface_index_, config_.xdp_flags, nullptr);
                if (err)
                {
                    logger_->error("Failed to detach XDP program: " + std::string(strerror(-err)));
                    return false;
                }
                
                is_attached_ = false;
                logger_->info("XDP program detached successfully");
                
                return true;
            }

            void XDPFilter::shutdown()
            {
                if (!is_running_)
                {
                    return;
                }
                
                logger_->info("Shutting down XDP Filter...");
                
                is_running_ = false;
                
                // Stop sync thread
                stopBlacklistSyncThread();
                
                // Detach from interface
                detachFromInterface();
                
                // Destroy bpf_link if exists
                if (bpf_link_)
                {
                    bpf_link__destroy(bpf_link_);
                    bpf_link_ = nullptr;
                }
                
                // Close BPF object
                if (bpf_obj_)
                {
                    bpf_object__close(bpf_obj_);
                    bpf_obj_ = nullptr;
                }
                
                logger_->info("XDP Filter shut down");
            }

            // ==================== Blacklist Management ====================
            
            bool XDPFilter::loadIPBlacklist(const std::string &file_path)
            {
                logger_->info("Loading IP blacklist from: " + file_path);
                
                std::ifstream file(file_path);
                if (!file.is_open())
                {
                    logger_->error("Failed to open IP blacklist file: " + file_path);
                    return false;
                }
                
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string line;
                int count = 0;
                
                while (std::getline(file, line))
                {
                    // Trim whitespace
                    line = Common::Utils::trim(line);
                    
                    // Skip empty lines and comments
                    if (line.empty() || line[0] == '#')
                    {
                        continue;
                    }
                    
                    // Parse IP address
                    if (validateIPAddress(line))
                    {
                        uint32_t ip_int = ipStringToInt(line);
                        ip_blacklist_.insert(ip_int);
                        
                        BlacklistEntry entry;
                        entry.ip_address = ip_int;
                        entry.timestamp = Common::Utils::getCurrentTimestampMs();
                        entry.reason = "Loaded from file";
                        entry.is_permanent = true;
                        
                        ip_blacklist_details_[ip_int] = entry;
                        count++;
                    }
                    else
                    {
                        logger_->warn("Invalid IP address in blacklist: " + line);
                    }
                }
                
                file.close();
                
                logger_->info("Loaded " + std::to_string(count) + " IP addresses to blacklist");
                
                return true;
            }

            bool XDPFilter::loadDomainBlacklist(const std::string &file_path)
            {
                logger_->info("Loading domain blacklist from: " + file_path);
                
                std::ifstream file(file_path);
                if (!file.is_open())
                {
                    logger_->error("Failed to open domain blacklist file: " + file_path);
                    return false;
                }
                
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string line;
                int count = 0;
                
                while (std::getline(file, line))
                {
                    line = Common::Utils::trim(line);
                    
                    if (line.empty() || line[0] == '#')
                    {
                        continue;
                    }
                    
                    if (validateDomain(line))
                    {
                        domain_blacklist_.insert(Common::Utils::toLowerCase(line));
                        count++;
                    }
                    else
                    {
                        logger_->warn("Invalid domain in blacklist: " + line);
                    }
                }
                
                file.close();
                
                logger_->info("Loaded " + std::to_string(count) + " domains to blacklist");
                
                return true;
            }

            bool XDPFilter::loadHashBlacklist(const std::string &file_path)
            {
                logger_->info("Loading hash blacklist from: " + file_path);
                
                std::ifstream file(file_path);
                if (!file.is_open())
                {
                    logger_->error("Failed to open hash blacklist file: " + file_path);
                    return false;
                }
                
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string line;
                int count = 0;
                
                while (std::getline(file, line))
                {
                    line = Common::Utils::trim(line);
                    
                    if (line.empty() || line[0] == '#')
                    {
                        continue;
                    }
                    
                    if (validateHash(line))
                    {
                        hash_blacklist_.insert(Common::Utils::toLowerCase(line));
                        count++;
                    }
                    else
                    {
                        logger_->warn("Invalid hash in blacklist: " + line);
                    }
                }
                
                file.close();
                
                logger_->info("Loaded " + std::to_string(count) + " hashes to blacklist");
                
                return true;
            }

            bool XDPFilter::addIPToBlacklist(uint32_t ip_address, const std::string &reason, bool permanent)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                ip_blacklist_.insert(ip_address);
                
                BlacklistEntry entry;
                entry.ip_address = ip_address;
                entry.timestamp = Common::Utils::getCurrentTimestampMs();
                entry.reason = reason;
                entry.is_permanent = permanent;
                
                ip_blacklist_details_[ip_address] = entry;
                
                // Update BPF map
                uint32_t value = 1;
                if (ip_blacklist_map_fd_ >= 0)
                {
                    if (bpf_map_update_elem(ip_blacklist_map_fd_, &ip_address, &value, BPF_ANY) != 0)
                    {
                        logger_->error("Failed to update IP blacklist BPF map");
                        return false;
                    }
                }
                
                logger_->info("Added IP to blacklist: " + ipIntToString(ip_address) + " (" + reason + ")");
                
                return true;
            }

            bool XDPFilter::removeIPFromBlacklist(uint32_t ip_address)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                ip_blacklist_.erase(ip_address);
                ip_blacklist_details_.erase(ip_address);
                
                if (ip_blacklist_map_fd_ >= 0)
                {
                    if (bpf_map_delete_elem(ip_blacklist_map_fd_, &ip_address) != 0)
                    {
                        logger_->error("Failed to delete IP from blacklist BPF map");
                        return false;
                    }
                }
                
                logger_->info("Removed IP from blacklist: " + ipIntToString(ip_address));
                
                return true;
            }

            bool XDPFilter::isIPBlacklisted(uint32_t ip_address) const
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                return ip_blacklist_.find(ip_address) != ip_blacklist_.end();
            }

            bool XDPFilter::addDomainToBlacklist(const std::string &domain, const std::string &reason)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string domain_lower = Common::Utils::toLowerCase(domain);
                domain_blacklist_.insert(domain_lower);
                
                logger_->info("Added domain to blacklist: " + domain + " (" + reason + ")");
                
                return true;
            }

            bool XDPFilter::removeDomainFromBlacklist(const std::string &domain)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string domain_lower = Common::Utils::toLowerCase(domain);
                domain_blacklist_.erase(domain_lower);
                
                logger_->info("Removed domain from blacklist: " + domain);
                
                return true;
            }

            bool XDPFilter::isDomainBlacklisted(const std::string &domain) const
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                std::string domain_lower = Common::Utils::toLowerCase(domain);
                return domain_blacklist_.find(domain_lower) != domain_blacklist_.end();
            }

            bool XDPFilter::addHashToBlacklist(const std::string &hash, const std::string &reason)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string hash_lower = Common::Utils::toLowerCase(hash);
                hash_blacklist_.insert(hash_lower);
                
                logger_->info("Added hash to blacklist: " + hash + " (" + reason + ")");
                
                return true;
            }

            bool XDPFilter::removeHashFromBlacklist(const std::string &hash)
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                std::string hash_lower = Common::Utils::toLowerCase(hash);
                hash_blacklist_.erase(hash_lower);
                
                logger_->info("Removed hash from blacklist: " + hash);
                
                return true;
            }

            bool XDPFilter::isHashBlacklisted(const std::string &hash) const
            {
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                std::string hash_lower = Common::Utils::toLowerCase(hash);
                return hash_blacklist_.find(hash_lower) != hash_blacklist_.end();
            }

            bool XDPFilter::syncBlacklistsToBPF()
            {
                logger_->info("Syncing blacklists to BPF maps...");
                
                std::lock_guard<std::mutex> lock(blacklist_mutex_);
                
                if (ip_blacklist_map_fd_ >= 0 && config_.enable_ip_blacklist)
                {
                    int count = 0;
                    uint32_t value = 1;
                    
                    for (uint32_t ip : ip_blacklist_)
                    {
                        if (bpf_map_update_elem(ip_blacklist_map_fd_, &ip, &value, BPF_ANY) == 0)
                        {
                            count++;
                        }
                    }
                    
                    logger_->info("Synced " + std::to_string(count) + " IPs to BPF map");
                }
                
                return true;
            }

            XDPStats XDPFilter::getStatistics() const
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                return stats_;
            }

            void XDPFilter::resetStatistics()
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_ = XDPStats();
                logger_->info("Statistics reset");
            }

            void XDPFilter::updateStatistics()
            {
                if (stats_map_fd_ < 0)
                {
                    return;
                }
                
                std::lock_guard<std::mutex> lock(stats_mutex_);
                
                if (stats_.total_packets > 0)
                {
                    stats_.drop_rate = static_cast<double>(stats_.dropped_packets) / stats_.total_packets;
                    stats_.blacklist_hit_rate = static_cast<double>(stats_.blacklist_hits) / stats_.total_packets;
                }
            }

            void XDPFilter::printStatistics() const
            {
                XDPStats stats = getStatistics();
                
                logger_->info("========== XDP Filter Statistics ==========");
                logger_->info("Total Packets:      " + std::to_string(stats.total_packets));
                logger_->info("Passed Packets:     " + std::to_string(stats.passed_packets));
                logger_->info("Dropped Packets:    " + std::to_string(stats.dropped_packets));
                logger_->info("Blacklist Hits:     " + std::to_string(stats.blacklist_hits));
                logger_->info("Rate Limit Hits:    " + std::to_string(stats.rate_limit_hits));
                logger_->info("Malformed Packets:  " + std::to_string(stats.malformed_packets));
                logger_->info("Processing Errors:  " + std::to_string(stats.processing_errors));
                logger_->info("Drop Rate:          " + std::to_string(stats.drop_rate * 100) + "%");
                logger_->info("Blacklist Hit Rate: " + std::to_string(stats.blacklist_hit_rate * 100) + "%");
                logger_->info("===========================================");
            }

            void XDPFilter::setConfig(const XDPFilterConfig &config)
            {
                config_ = config;
            }

            XDPFilterConfig XDPFilter::getConfig() const
            {
                return config_;
            }

            bool XDPFilter::setRateLimit(uint32_t pps)
            {
                config_.rate_limit_pps = pps;
                
                if (config_map_fd_ >= 0)
                {
                    uint32_t key = 0;
                    if (bpf_map_update_elem(config_map_fd_, &key, &pps, BPF_ANY) != 0)
                    {
                        logger_->error("Failed to update rate limit in BPF map");
                        return false;
                    }
                }
                
                logger_->info("Rate limit set to: " + std::to_string(pps) + " pps");
                
                return true;
            }

            uint32_t XDPFilter::getRateLimit() const
            {
                return config_.rate_limit_pps;
            }

            int XDPFilter::getInterfaceIndexByName(const std::string &interface_name)
            {
                int index = if_nametoindex(interface_name.c_str());
                if (index == 0)
                {
                    logger_->error("Interface not found: " + interface_name);
                    return -1;
                }
                return index;
            }

            uint32_t XDPFilter::ipStringToInt(const std::string &ip) const
            {
                return Common::NetworkUtils::ipStringToInt(ip);
            }

            std::string XDPFilter::ipIntToString(uint32_t ip) const
            {
                return Common::NetworkUtils::ipIntToString(ip);
            }

            bool XDPFilter::validateIPAddress(const std::string &ip) const
            {
                return Common::NetworkUtils::isValidIPv4(ip);
            }

            bool XDPFilter::validateDomain(const std::string &domain) const
            {
                std::regex domain_regex(R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)");
                return std::regex_match(domain, domain_regex);
            }

            bool XDPFilter::validateHash(const std::string &hash) const
            {
                if (hash.length() != 32 && hash.length() != 64)
                {
                    return false;
                }
                
                std::regex hex_regex("^[0-9a-fA-F]+$");
                return std::regex_match(hash, hex_regex);
            }

            void XDPFilter::startBlacklistSyncThread()
            {
                sync_thread_stop_ = false;
                sync_thread_ = std::thread(&XDPFilter::blacklistSyncLoop, this);
                logger_->info("Blacklist sync thread started");
            }

            void XDPFilter::stopBlacklistSyncThread()
            {
                sync_thread_stop_ = true;
                if (sync_thread_.joinable())
                {
                    sync_thread_.join();
                }
                logger_->info("Blacklist sync thread stopped");
            }

            void XDPFilter::blacklistSyncLoop()
            {
                while (!sync_thread_stop_)
                {
                    for (int i = 0; i < config_.blacklist_sync_interval_sec && !sync_thread_stop_; ++i)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }
                    
                    if (sync_thread_stop_)
                    {
                        break;
                    }
                    
                    logger_->debug("Reloading blacklists...");
                    
                    if (config_.enable_ip_blacklist)
                    {
                        loadIPBlacklist(config_.ip_blacklist_file);
                    }
                    
                    if (config_.enable_domain_blacklist)
                    {
                        loadDomainBlacklist(config_.domain_blacklist_file);
                    }
                    
                    if (config_.enable_hash_blacklist)
                    {
                        loadHashBlacklist(config_.hash_blacklist_file);
                    }
                    
                    syncBlacklistsToBPF();
                    updateStatistics();
                }
            }

        } // namespace Layer1
    }     // namespace Core
} // namespace NetworkSecurity
