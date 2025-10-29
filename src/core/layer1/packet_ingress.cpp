// src/core/layer1/packet_ingress.cpp
#include "packet_ingress.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            // ==================== Constructor/Destructor ====================
            
            PacketIngress::PacketIngress()
                : pcap_handle_(nullptr),
                  is_running_(false),
                  is_capturing_(false)
            {
                logger_ = std::make_shared<Common::Logger>();
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "PacketIngress initialized");
            }

            PacketIngress::~PacketIngress()
            {
                cleanup();
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "PacketIngress destroyed");
            }

            // ==================== Initialization ====================
            
            bool PacketIngress::initialize(const PacketIngressConfig& config)
            {
                std::lock_guard<std::mutex> lock(error_mutex_);
                
                if (is_running_.load())
                {
                    last_error_ = "PacketIngress is already running";
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                config_ = config;
                
                // Validate configuration
                if (config_.interface.empty())
                {
                    last_error_ = "Interface name is empty";
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                // Check if interface exists
                if (!isInterfaceAvailable(config_.interface) && config_.interface != "any")
                {
                    last_error_ = "Interface '" + config_.interface + "' not found";
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                // Open PCAP handle
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_handle_ = pcap_open_live(
                    config_.interface.c_str(),
                    config_.snaplen,
                    config_.promiscuous ? 1 : 0,
                    config_.timeout_ms,
                    errbuf
                );
                
                if (pcap_handle_ == nullptr)
                {
                    last_error_ = std::string("Failed to open interface: ") + errbuf;
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                // Set buffer size
                if (pcap_set_buffer_size(pcap_handle_, config_.buffer_size) != 0)
                {
                    logger_->log(Common::LogLevel::WARN, "PacketIngress", 
                               "Failed to set buffer size");
                }
                
                // Apply BPF filter if specified
                if (!config_.filter.empty())
                {
                    if (!updateFilter(config_.filter))
                    {
                        pcap_close(pcap_handle_);
                        pcap_handle_ = nullptr;
                        return false;
                    }
                }
                
                // Set non-blocking mode
                if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1)
                {
                    logger_->log(Common::LogLevel::WARN, "PacketIngress",
                               std::string("Failed to set non-blocking mode: ") + errbuf);
                }
                
                is_running_ = true;
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress",
                           "PacketIngress initialized successfully on interface: " + 
                           config_.interface);
                
                return true;
            }

            void PacketIngress::cleanup()
            {
                stopCapture();
                
                is_running_ = false;
                
                // Close PCAP handle
                if (pcap_handle_ != nullptr)
                {
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                }
                
                // Clear callbacks
                clearCallbacks();
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "PacketIngress cleaned up");
            }

            // ==================== Capture Control ====================
            
            bool PacketIngress::startCapture()
            {
                if (is_capturing_.load())
                {
                    logger_->log(Common::LogLevel::WARN, "PacketIngress", 
                               "Capture already running");
                    return false;
                }
                
                if (!is_running_.load() || pcap_handle_ == nullptr)
                {
                    last_error_ = "PacketIngress not initialized";
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                is_capturing_ = true;
                
                // Reset statistics
                resetStatistics();
                
                // Start capture thread
                capture_thread_ = std::thread(&PacketIngress::captureThread, this);
                
                // Start processing threads
                processing_threads_.clear();
                for (int i = 0; i < config_.num_threads; ++i)
                {
                    processing_threads_.emplace_back(&PacketIngress::processingThread, this);
                }
                
                // Start metrics update thread
                metrics_thread_ = std::thread(&PacketIngress::metricsUpdateThread, this);
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "Packet capture started");
                
                return true;
            }

            void PacketIngress::stopCapture()
            {
                if (!is_capturing_.load())
                {
                    return;
                }
                
                is_capturing_ = false;
                
                // Stop PCAP loop
                if (pcap_handle_ != nullptr)
                {
                    pcap_breakloop(pcap_handle_);
                }
                
                // Notify all processing threads
                queue_cv_.notify_all();
                
                // Wait for capture thread
                if (capture_thread_.joinable())
                {
                    capture_thread_.join();
                }
                
                // Wait for processing threads
                for (auto& thread : processing_threads_)
                {
                    if (thread.joinable())
                    {
                        thread.join();
                    }
                }
                processing_threads_.clear();
                
                // Wait for metrics thread
                if (metrics_thread_.joinable())
                {
                    metrics_thread_.join();
                }
                
                // Clear packet queue
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    while (!packet_queue_.empty())
                    {
                        packet_queue_.pop();
                    }
                }
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "Packet capture stopped");
                printStatistics();
            }

            // ==================== Callback Registration ====================
            
            void PacketIngress::registerCallback(const std::string& name, PacketCallback callback)
            {
                std::unique_lock<std::shared_mutex> lock(callbacks_mutex_);
                callbacks_[name] = callback;
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "Registered callback: " + name);
            }

            void PacketIngress::unregisterCallback(const std::string& name)
            {
                std::unique_lock<std::shared_mutex> lock(callbacks_mutex_);
                auto it = callbacks_.find(name);
                if (it != callbacks_.end())
                {
                    callbacks_.erase(it);
                    logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                               "Unregistered callback: " + name);
                }
            }

            void PacketIngress::clearCallbacks()
            {
                std::unique_lock<std::shared_mutex> lock(callbacks_mutex_);
                callbacks_.clear();
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "Cleared all callbacks");
            }

            // ==================== Statistics ====================
            
            PacketStatistics::Snapshot PacketIngress::getStatistics() const
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                return stats_.getSnapshot();
            }

            void PacketIngress::resetStatistics()
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.reset();
                logger_->log(Common::LogLevel::INFO, "PacketIngress", "Statistics reset");
            }

            void PacketIngress::printStatistics() const
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                
                auto snap = stats_.getSnapshot();
                auto now = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                    now - snap.start_time).count();
                
                std::stringstream ss;
                ss << "\n=== Packet Ingress Statistics ===\n";
                ss << "Duration: " << duration << " seconds\n";
                ss << "Total Packets: " << snap.total_packets << "\n";
                ss << "Total Bytes: " << snap.total_bytes << "\n";
                ss << "Dropped Packets: " << snap.dropped_packets << "\n";
                ss << "Filtered Packets: " << snap.filtered_packets << "\n";
                ss << "Error Packets: " << snap.error_packets << "\n";
                ss << "\nProtocol Distribution:\n";
                ss << "  TCP: " << snap.tcp_packets << "\n";
                ss << "  UDP: " << snap.udp_packets << "\n";
                ss << "  ICMP: " << snap.icmp_packets << "\n";
                ss << "  Other: " << snap.other_packets << "\n";
                ss << "\nPerformance:\n";
                ss << "  Packets/sec: " << snap.packets_per_second << "\n";
                ss << "  Bytes/sec: " << snap.bytes_per_second << "\n";
                
                if (duration > 0)
                {
                    ss << "  Average Packets/sec: " << (snap.total_packets / duration) << "\n";
                    ss << "  Average Bytes/sec: " << (snap.total_bytes / duration) << "\n";
                }
                
                ss << "================================\n";
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress", ss.str());
                std::cout << ss.str();
            }

            // ==================== Configuration ====================
            
            bool PacketIngress::updateFilter(const std::string& filter)
            {
                if (pcap_handle_ == nullptr)
                {
                    last_error_ = "PCAP handle not initialized";
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                struct bpf_program fp;
                
                // Compile filter
                if (pcap_compile(pcap_handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1)
                {
                    last_error_ = std::string("Failed to compile filter: ") + 
                                 pcap_geterr(pcap_handle_);
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    return false;
                }
                
                // Apply filter
                if (pcap_setfilter(pcap_handle_, &fp) == -1)
                {
                    last_error_ = std::string("Failed to set filter: ") + 
                                 pcap_geterr(pcap_handle_);
                    logger_->log(Common::LogLevel::ERROR, "PacketIngress", last_error_);
                    pcap_freecode(&fp);
                    return false;
                }
                
                pcap_freecode(&fp);
                
                config_.filter = filter;
                logger_->log(Common::LogLevel::INFO, "PacketIngress", 
                           "Filter updated: " + filter);
                
                return true;
            }

            std::vector<std::string> PacketIngress::getAvailableInterfaces()
            {
                std::vector<std::string> interfaces;
                
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_if_t* alldevs;
                
                if (pcap_findalldevs(&alldevs, errbuf) == -1)
                {
                    return interfaces;
                }
                
                for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next)
                {
                    interfaces.push_back(dev->name);
                }
                
                pcap_freealldevs(alldevs);
                
                return interfaces;
            }

            bool PacketIngress::isInterfaceAvailable(const std::string& interface)
            {
                auto interfaces = getAvailableInterfaces();
                return std::find(interfaces.begin(), interfaces.end(), interface) != 
                       interfaces.end();
            }

            // ==================== Internal Methods ====================
            
            void PacketIngress::captureThread()
            {
                logger_->log(Common::LogLevel::INFO, "PacketIngress", "Capture thread started");
                
                while (is_capturing_.load())
                {
                    int result = pcap_dispatch(pcap_handle_, -1, pcapCallback, 
                                              reinterpret_cast<u_char*>(this));
                    
                    if (result == -1)
                    {
                        logger_->log(Common::LogLevel::ERROR, "PacketIngress",
                                   std::string("pcap_dispatch error: ") + 
                                   pcap_geterr(pcap_handle_));
                        break;
                    }
                    else if (result == -2)
                    {
                        // pcap_breakloop() was called
                        break;
                    }
                    
                    // Small sleep to prevent busy waiting
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
                
                logger_->log(Common::LogLevel::INFO, "PacketIngress", "Capture thread stopped");
            }

            void PacketIngress::processingThread()
            {
                while (is_capturing_.load() || !packet_queue_.empty())
                {
                    PacketData packet_data;
                    
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this]() {
                            return !packet_queue_.empty() || !is_capturing_.load();
                        });
                        
                        if (packet_queue_.empty())
                        {
                            continue;
                        }
                        
                        packet_data = std::move(packet_queue_.front());
                        packet_queue_.pop();
                    }
                    
                    // Process packet
                    processPacket(packet_data.data.data(), packet_data.length);
                }
            }

            void PacketIngress::processPacket(const uint8_t* packet_data, size_t packet_len)
            {
                // Parse packet
                Common::ParsedPacket parsed;
                if (!parser_.parsePacket(packet_data, packet_len, parsed))
                {
                    stats_.error_packets.fetch_add(1);
                    return;
                }
                
                // Update protocol statistics
                switch (parsed.protocol_type)
                {
                    case Common::ProtocolType::TCP:
                        stats_.tcp_packets.fetch_add(1);
                        break;
                    case Common::ProtocolType::UDP:
                        stats_.udp_packets.fetch_add(1);
                        break;
                    case Common::ProtocolType::ICMP:
                    case Common::ProtocolType::ICMPV6:
                        stats_.icmp_packets.fetch_add(1);
                        break;
                    default:
                        stats_.other_packets.fetch_add(1);
                        break;
                }
                
                // Call registered callbacks
                {
                    std::shared_lock<std::shared_mutex> lock(callbacks_mutex_);
                    for (const auto& [name, callback] : callbacks_)
                    {
                        try
                        {
                            callback(parsed, packet_data, packet_len);
                        }
                        catch (const std::exception& e)
                        {
                            logger_->log(Common::LogLevel::ERROR, "PacketIngress",
                                       "Callback '" + name + "' threw exception: " + e.what());
                        }
                    }
                }
            }

            void PacketIngress::pcapCallback(u_char* user, 
                                            const struct pcap_pkthdr* header,
                                            const u_char* packet)
            {
                auto* ingress = reinterpret_cast<PacketIngress*>(user);
                
                if (!ingress->is_capturing_.load())
                {
                    return;
                }
                
                // Update statistics
                ingress->stats_.total_packets.fetch_add(1);
                ingress->stats_.total_bytes.fetch_add(header->caplen);
                
                // Add packet to queue
                PacketData packet_data;
                packet_data.data.assign(packet, packet + header->caplen);
                packet_data.length = header->caplen;
                packet_data.timestamp = std::chrono::steady_clock::now();
                
                {
                    std::lock_guard<std::mutex> lock(ingress->queue_mutex_);
                    
                    // Check queue size limit
                    if (ingress->packet_queue_.size() >= 
                        static_cast<size_t>(ingress->config_.buffer_size))
                    {
                        ingress->stats_.dropped_packets.fetch_add(1);
                        return;
                    }
                    
                    ingress->packet_queue_.push(std::move(packet_data));
                }
                
                ingress->queue_cv_.notify_one();
            }

            void PacketIngress::updatePerformanceMetrics()
            {
                auto now = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                    now - stats_.last_update);
                
                if (duration.count() >= 1)
                {
                    // Calculate packets per second
                    uint64_t current_packets = stats_.total_packets.load();
                    uint64_t current_bytes = stats_.total_bytes.load();
                    
                    static uint64_t last_packets = 0;
                    static uint64_t last_bytes = 0;
                    
                    stats_.packets_per_second = current_packets - last_packets;
                    stats_.bytes_per_second = current_bytes - last_bytes;
                    
                    last_packets = current_packets;
                    last_bytes = current_bytes;
                    
                    stats_.last_update = now;
                }
            }

            void PacketIngress::metricsUpdateThread()
            {
                while (is_capturing_.load())
                {
                    updatePerformanceMetrics();
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }

        } // namespace Layer1
    } // namespace Core
} // namespace NetworkSecurity
