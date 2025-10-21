// src/core/layer1/packet_ingress.hpp
#ifndef NETWORK_SECURITY_PACKET_INGRESS_HPP
#define NETWORK_SECURITY_PACKET_INGRESS_HPP

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <queue>
#include <functional>
#include <condition_variable>
#include <cstring>

// Include pcap FIRST to avoid BPF conflicts
#include <pcap.h>

#include "../../common/logger.hpp"
#include "../../common/config_manager.hpp"
#include "../../common/packet_parser.hpp"

// Forward declaration to avoid including xdp_filter.hpp here
namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            class XDPFilter;
        }
    }
}

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            // ... (rest of the header remains the same as before)
            
            struct PacketBuffer
            {
                uint8_t *data;
                size_t length;
                uint64_t timestamp;
                uint32_t interface_index;
                std::string interface_name;
                
                PacketBuffer()
                    : data(nullptr), length(0), timestamp(0), interface_index(0)
                {
                }
                
                ~PacketBuffer()
                {
                    if (data)
                    {
                        delete[] data;
                        data = nullptr;
                    }
                }
                
                PacketBuffer(const PacketBuffer &other)
                    : length(other.length),
                      timestamp(other.timestamp),
                      interface_index(other.interface_index),
                      interface_name(other.interface_name)
                {
                    if (other.data && other.length > 0)
                    {
                        data = new uint8_t[other.length];
                        std::memcpy(data, other.data, other.length);
                    }
                    else
                    {
                        data = nullptr;
                    }
                }
                
                PacketBuffer(PacketBuffer &&other) noexcept
                    : data(other.data),
                      length(other.length),
                      timestamp(other.timestamp),
                      interface_index(other.interface_index),
                      interface_name(std::move(other.interface_name))
                {
                    other.data = nullptr;
                    other.length = 0;
                }
                
                PacketBuffer &operator=(const PacketBuffer &other)
                {
                    if (this != &other)
                    {
                        if (data)
                        {
                            delete[] data;
                        }
                        
                        length = other.length;
                        timestamp = other.timestamp;
                        interface_index = other.interface_index;
                        interface_name = other.interface_name;
                        
                        if (other.data && other.length > 0)
                        {
                            data = new uint8_t[other.length];
                            std::memcpy(data, other.data, other.length);
                        }
                        else
                        {
                            data = nullptr;
                        }
                    }
                    return *this;
                }
                
                PacketBuffer &operator=(PacketBuffer &&other) noexcept
                {
                    if (this != &other)
                    {
                        if (data)
                        {
                            delete[] data;
                        }
                        
                        data = other.data;
                        length = other.length;
                        timestamp = other.timestamp;
                        interface_index = other.interface_index;
                        interface_name = std::move(other.interface_name);
                        
                        other.data = nullptr;
                        other.length = 0;
                    }
                    return *this;
                }
            };

            struct IngressStats
            {
                uint64_t total_packets_received;
                uint64_t total_bytes_received;
                uint64_t packets_dropped;
                uint64_t packets_queued;
                uint64_t packets_processed;
                uint64_t queue_full_drops;
                uint64_t parse_errors;
                
                double packets_per_second;
                double bytes_per_second;
                double avg_packet_size;
                
                uint64_t last_update_time;
                
                IngressStats()
                    : total_packets_received(0),
                      total_bytes_received(0),
                      packets_dropped(0),
                      packets_queued(0),
                      packets_processed(0),
                      queue_full_drops(0),
                      parse_errors(0),
                      packets_per_second(0.0),
                      bytes_per_second(0.0),
                      avg_packet_size(0.0),
                      last_update_time(0)
                {
                }
            };

            struct IngressConfig
            {
                std::string interface_name;
                std::string capture_filter;
                int snaplen;
                int timeout_ms;
                int buffer_size;
                bool promiscuous_mode;
                bool enable_xdp_filter;
                size_t packet_queue_size;
                int worker_threads;
                bool enable_zero_copy;
                
                IngressConfig()
                    : interface_name("eth0"),
                      capture_filter(""),
                      snaplen(65535),
                      timeout_ms(1000),
                      buffer_size(64 * 1024 * 1024),
                      promiscuous_mode(true),
                      enable_xdp_filter(true),
                      packet_queue_size(10000),
                      worker_threads(4),
                      enable_zero_copy(false)
                {
                }
            };

            using PacketCallback = std::function<void(const PacketBuffer &packet)>;

            class PacketIngress
            {
            public:
                PacketIngress();
                ~PacketIngress();

                bool initialize(const IngressConfig &config);
                bool start();
                void stop();
                void shutdown();

                bool openInterface();
                bool closeInterface();
                bool setFilter(const std::string &filter_expression);
                
                void captureLoop();
                void processingLoop();

                void registerPacketCallback(PacketCallback callback);
                void unregisterPacketCallback();

                bool enqueuePacket(PacketBuffer &&packet);
                bool dequeuePacket(PacketBuffer &packet);
                size_t getQueueSize() const;
                bool isQueueFull() const;

                IngressStats getStatistics() const;
                void resetStatistics();
                void updateStatistics();
                void printStatistics() const;

                void setConfig(const IngressConfig &config);
                IngressConfig getConfig() const;

                bool isRunning() const { return is_running_; }
                bool isCapturing() const { return is_capturing_; }
                std::string getInterfaceName() const { return config_.interface_name; }

                void setXDPFilter(std::shared_ptr<XDPFilter> xdp_filter);
                std::shared_ptr<XDPFilter> getXDPFilter() const;

            private:
                static void pcapCallbackStatic(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
                void pcapCallback(const struct pcap_pkthdr *header, const u_char *packet);
                
                void startWorkerThreads();
                void stopWorkerThreads();
                void workerThread(int thread_id);

                bool validateConfig() const;
                void calculateStatistics();

                IngressConfig config_;
                
                pcap_t *pcap_handle_;
                char pcap_errbuf_[PCAP_ERRBUF_SIZE];
                
                std::queue<PacketBuffer> packet_queue_;
                mutable std::mutex queue_mutex_;
                std::condition_variable queue_cv_;
                
                std::vector<std::thread> worker_threads_;
                std::thread capture_thread_;
                
                PacketCallback packet_callback_;
                std::mutex callback_mutex_;
                
                mutable IngressStats stats_;
                mutable std::mutex stats_mutex_;
                
                std::atomic<bool> is_running_;
                std::atomic<bool> is_capturing_;
                std::atomic<bool> stop_requested_;
                
                std::shared_ptr<XDPFilter> xdp_filter_;
                
                std::shared_ptr<Common::Logger> logger_;
                std::unique_ptr<Common::PacketParser> packet_parser_;
            };

        } // namespace Layer1
    }     // namespace Core
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_PACKET_INGRESS_HPP
