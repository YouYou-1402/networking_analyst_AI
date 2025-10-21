// src/core/layer1/packet_ingress.cpp
#include "packet_ingress.hpp"
#include "xdp_filter.hpp"
#include "../../common/utils.hpp"
#include <algorithm>
#include <cstring>
#include <chrono>

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
                  is_capturing_(false),
                  stop_requested_(false)
            {
                logger_ = std::make_shared<Common::Logger>("PacketIngress");
                packet_parser_ = std::make_unique<Common::PacketParser>();
                std::memset(pcap_errbuf_, 0, PCAP_ERRBUF_SIZE);
            }

            PacketIngress::~PacketIngress()
            {
                shutdown();
            }

            // ==================== Initialization ====================
            
            bool PacketIngress::initialize(const IngressConfig &config)
            {
                logger_->info("Initializing Packet Ingress...");
                
                config_ = config;
                
                // Validate configuration
                if (!validateConfig())
                {
                    logger_->error("Invalid configuration");
                    return false;
                }
                
                // Initialize XDP filter if enabled
                if (config_.enable_xdp_filter && !xdp_filter_)
                {
                    logger_->info("XDP filter enabled but not set, creating default XDP filter");
                    xdp_filter_ = std::make_shared<XDPFilter>();
                    
                    XDPFilterConfig xdp_config;
                    xdp_config.interface_name = config_.interface_name;
                    
                    if (!xdp_filter_->initialize(xdp_config))
                    {
                        logger_->warn("Failed to initialize XDP filter, continuing without it");
                        xdp_filter_ = nullptr;
                    }
                }
                
                logger_->info("Packet Ingress initialized successfully");
                return true;
            }

            bool PacketIngress::start()
            {
                if (is_running_)
                {
                    logger_->warn("Packet Ingress already running");
                    return true;
                }
                
                logger_->info("Starting Packet Ingress...");
                
                // Open interface
                if (!openInterface())
                {
                    logger_->error("Failed to open interface");
                    return false;
                }
                
                // Set filter if specified
                if (!config_.capture_filter.empty())
                {
                    if (!setFilter(config_.capture_filter))
                    {
                        logger_->warn("Failed to set capture filter: " + config_.capture_filter);
                    }
                }
                
                // Reset statistics
                resetStatistics();
                
                // Start worker threads
                startWorkerThreads();
                
                // Start capture thread
                is_running_ = true;
                stop_requested_ = false;
                capture_thread_ = std::thread(&PacketIngress::captureLoop, this);
                
                logger_->info("Packet Ingress started successfully");
                return true;
            }

            void PacketIngress::stop()
            {
                if (!is_running_)
                {
                    return;
                }
                
                logger_->info("Stopping Packet Ingress...");
                
                stop_requested_ = true;
                is_running_ = false;
                
                // Break pcap loop
                if (pcap_handle_)
                {
                    pcap_breakloop(pcap_handle_);
                }
                
                // Wait for capture thread
                if (capture_thread_.joinable())
                {
                    capture_thread_.join();
                }
                
                // Stop worker threads
                stopWorkerThreads();
                
                // Close interface
                closeInterface();
                
                logger_->info("Packet Ingress stopped");
            }

            void PacketIngress::shutdown()
            {
                stop();
                
                // Clear packet queue
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    while (!packet_queue_.empty())
                    {
                        packet_queue_.pop();
                    }
                }
                
                logger_->info("Packet Ingress shut down");
            }

            // ==================== Packet Capture ====================
            
            bool PacketIngress::openInterface()
            {
                logger_->info("Opening interface: " + config_.interface_name);
                
                // Open live capture
                pcap_handle_ = pcap_open_live(
                    config_.interface_name.c_str(),
                    config_.snaplen,
                    config_.promiscuous_mode ? 1 : 0,
                    config_.timeout_ms,
                    pcap_errbuf_
                );
                
                if (!pcap_handle_)
                {
                    logger_->error("Failed to open interface: " + std::string(pcap_errbuf_));
                    return false;
                }
                
                // Set buffer size
                if (pcap_set_buffer_size(pcap_handle_, config_.buffer_size) != 0)
                {
                    logger_->warn("Failed to set buffer size");
                }
                
                // Set immediate mode (don't wait for buffer to fill)
                if (pcap_set_immediate_mode(pcap_handle_, 1) != 0)
                {
                    logger_->warn("Failed to set immediate mode");
                }
                
                logger_->info("Interface opened successfully");
                return true;
            }

            bool PacketIngress::closeInterface()
            {
                if (pcap_handle_)
                {
                    logger_->info("Closing interface: " + config_.interface_name);
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                }
                return true;
            }

            bool PacketIngress::setFilter(const std::string &filter_expression)
            {
                if (!pcap_handle_)
                {
                    logger_->error("Cannot set filter: interface not open");
                    return false;
                }
                
                logger_->info("Setting capture filter: " + filter_expression);
                
                struct bpf_program fp;
                bpf_u_int32 net = 0;
                bpf_u_int32 mask = 0;
                
                // Get network and mask
                if (pcap_lookupnet(config_.interface_name.c_str(), &net, &mask, pcap_errbuf_) == -1)
                {
                    logger_->warn("Failed to get network info: " + std::string(pcap_errbuf_));
                    net = 0;
                    mask = 0;
                }
                
                // Compile filter
                if (pcap_compile(pcap_handle_, &fp, filter_expression.c_str(), 1, mask) == -1)
                {
                    logger_->error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle_)));
                    return false;
                }
                
                // Set filter
                if (pcap_setfilter(pcap_handle_, &fp) == -1)
                {
                    logger_->error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle_)));
                    pcap_freecode(&fp);
                    return false;
                }
                
                pcap_freecode(&fp);
                logger_->info("Capture filter set successfully");
                return true;
            }

            void PacketIngress::captureLoop()
            {
                logger_->info("Capture loop started");
                is_capturing_ = true;
                
                // Use pcap_loop with callback
                int result = pcap_loop(pcap_handle_, -1, pcapCallbackStatic, reinterpret_cast<u_char *>(this));
                
                if (result == -1)
                {
                    logger_->error("pcap_loop error: " + std::string(pcap_geterr(pcap_handle_)));
                }
                else if (result == -2)
                {
                    logger_->info("pcap_loop stopped by breakloop");
                }
                
                is_capturing_ = false;
                logger_->info("Capture loop ended");
            }

            void PacketIngress::pcapCallbackStatic(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
            {
                PacketIngress *ingress = reinterpret_cast<PacketIngress *>(user);
                ingress->pcapCallback(header, packet);
            }

            void PacketIngress::pcapCallback(const struct pcap_pkthdr *header, const u_char *packet)
            {
                // Update statistics
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.total_packets_received++;
                    stats_.total_bytes_received += header->len;
                }
                
                // Create packet buffer
                PacketBuffer pkt_buffer;
                pkt_buffer.length = header->caplen;
                pkt_buffer.timestamp = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
                pkt_buffer.interface_name = config_.interface_name;
                
                // Copy packet data
                pkt_buffer.data = new uint8_t[header->caplen];
                std::memcpy(pkt_buffer.data, packet, header->caplen);
                
                // Enqueue packet
                if (!enqueuePacket(std::move(pkt_buffer)))
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.queue_full_drops++;
                }
            }

            // ==================== Queue Management ====================
            
            bool PacketIngress::enqueuePacket(PacketBuffer &&packet)
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                
                if (packet_queue_.size() >= config_.packet_queue_size)
                {
                    return false; // Queue full
                }
                
                packet_queue_.push(std::move(packet));
                
                {
                    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                    stats_.packets_queued++;
                }
                
                lock.unlock();
                queue_cv_.notify_one();
                
                return true;
            }

            bool PacketIngress::dequeuePacket(PacketBuffer &packet)
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                
                if (packet_queue_.empty())
                {
                    return false;
                }
                
                packet = std::move(packet_queue_.front());
                packet_queue_.pop();
                
                return true;
            }

            size_t PacketIngress::getQueueSize() const
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                return packet_queue_.size();
            }

            bool PacketIngress::isQueueFull() const
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                return packet_queue_.size() >= config_.packet_queue_size;
            }

            // ==================== Worker Threads ====================
            
            void PacketIngress::startWorkerThreads()
            {
                logger_->info("Starting " + std::to_string(config_.worker_threads) + " worker threads");
                
                for (int i = 0; i < config_.worker_threads; ++i)
                {
                    worker_threads_.emplace_back(&PacketIngress::workerThread, this, i);
                }
            }

            void PacketIngress::stopWorkerThreads()
            {
                logger_->info("Stopping worker threads...");
                
                // Notify all workers
                queue_cv_.notify_all();
                
                // Wait for all workers to finish
                for (auto &thread : worker_threads_)
                {
                    if (thread.joinable())
                    {
                        thread.join();
                    }
                }
                
                worker_threads_.clear();
                logger_->info("Worker threads stopped");
            }

            void PacketIngress::workerThread(int thread_id)
            {
                logger_->debug("Worker thread " + std::to_string(thread_id) + " started");
                
                while (is_running_ || !packet_queue_.empty())
                {
                    PacketBuffer packet;
                    
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        
                        // Wait for packet or stop signal
                        queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this]
                        {
                            return !packet_queue_.empty() || !is_running_;
                        });
                        
                        if (packet_queue_.empty())
                        {
                            continue;
                        }
                        
                        packet = std::move(packet_queue_.front());
                        packet_queue_.pop();
                    }
                    
                    // Process packet
                    {
                        std::lock_guard<std::mutex> lock(stats_mutex_);
                        stats_.packets_processed++;
                    }
                    
                    // Call registered callback
                    {
                        std::lock_guard<std::mutex> lock(callback_mutex_);
                        if (packet_callback_)
                        {
                            try
                            {
                                packet_callback_(packet);
                            }
                            catch (const std::exception &e)
                            {
                                logger_->error("Exception in packet callback: " + std::string(e.what()));
                            }
                        }
                    }
                }
                
                logger_->debug("Worker thread " + std::to_string(thread_id) + " stopped");
            }

            // ==================== Callback Registration ====================
            
            void PacketIngress::registerPacketCallback(PacketCallback callback)
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                packet_callback_ = callback;
                logger_->info("Packet callback registered");
            }

            void PacketIngress::unregisterPacketCallback()
            {
                std::lock_guard<std::mutex> lock(callback_mutex_);
                packet_callback_ = nullptr;
                logger_->info("Packet callback unregistered");
            }

            // ==================== Statistics ====================
            
            IngressStats PacketIngress::getStatistics() const
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                return stats_;
            }

            void PacketIngress::resetStatistics()
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_ = IngressStats();
                stats_.last_update_time = Common::Utils::getCurrentTimestampMs();
                logger_->info("Statistics reset");
            }

            void PacketIngress::updateStatistics()
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                calculateStatistics();
            }

            void PacketIngress::calculateStatistics()
            {
                uint64_t current_time = Common::Utils::getCurrentTimestampMs();
                uint64_t time_diff = current_time - stats_.last_update_time;
                
                if (time_diff > 0)
                {
                    double time_diff_sec = time_diff / 1000.0;
                    
                    stats_.packets_per_second = stats_.total_packets_received / time_diff_sec;
                    stats_.bytes_per_second = stats_.total_bytes_received / time_diff_sec;
                }
                
                if (stats_.total_packets_received > 0)
                {
                    stats_.avg_packet_size = static_cast<double>(stats_.total_bytes_received) / stats_.total_packets_received;
                }
                
                stats_.last_update_time = current_time;
            }

            void PacketIngress::printStatistics() const
            {
                IngressStats stats = getStatistics();
                
                logger_->info("========== Packet Ingress Statistics ==========");
                logger_->info("Total Packets Received:  " + std::to_string(stats.total_packets_received));
                logger_->info("Total Bytes Received:    " + std::to_string(stats.total_bytes_received));
                logger_->info("Packets Dropped:         " + std::to_string(stats.packets_dropped));
                logger_->info("Packets Queued:          " + std::to_string(stats.packets_queued));
                logger_->info("Packets Processed:       " + std::to_string(stats.packets_processed));
                logger_->info("Queue Full Drops:        " + std::to_string(stats.queue_full_drops));
                logger_->info("Parse Errors:            " + std::to_string(stats.parse_errors));
                logger_->info("Packets/sec:             " + std::to_string(stats.packets_per_second));
                logger_->info("Bytes/sec:               " + std::to_string(stats.bytes_per_second));
                logger_->info("Avg Packet Size:         " + std::to_string(stats.avg_packet_size) + " bytes");
                logger_->info("Current Queue Size:      " + std::to_string(getQueueSize()));
                logger_->info("===============================================");
            }

            // ==================== Configuration ====================
            
            void PacketIngress::setConfig(const IngressConfig &config)
            {
                config_ = config;
            }

            IngressConfig PacketIngress::getConfig() const
            {
                return config_;
            }

            bool PacketIngress::validateConfig() const
            {
                if (config_.interface_name.empty())
                {
                    logger_->error("Interface name is empty");
                    return false;
                }
                
                if (config_.snaplen <= 0)
                {
                    logger_->error("Invalid snaplen: " + std::to_string(config_.snaplen));
                    return false;
                }
                
                if (config_.timeout_ms < 0)
                {
                    logger_->error("Invalid timeout: " + std::to_string(config_.timeout_ms));
                    return false;
                }
                
                if (config_.packet_queue_size == 0)
                {
                    logger_->error("Invalid queue size: " + std::to_string(config_.packet_queue_size));
                    return false;
                }
                
                if (config_.worker_threads <= 0)
                {
                    logger_->error("Invalid worker threads: " + std::to_string(config_.worker_threads));
                    return false;
                }
                
                return true;
            }

            // ==================== XDP Filter Integration ====================
            
            void PacketIngress::setXDPFilter(std::shared_ptr<XDPFilter> xdp_filter)
            {
                xdp_filter_ = xdp_filter;
                logger_->info("XDP filter set");
            }

            std::shared_ptr<XDPFilter> PacketIngress::getXDPFilter() const
            {
                return xdp_filter_;
            }

        } // namespace Layer1
    }     // namespace Core
} // namespace NetworkSecurity
