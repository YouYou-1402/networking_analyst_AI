// src/core/layer1/packet_ingress.hpp
#ifndef NETWORK_SECURITY_LAYER1_PACKET_INGRESS_HPP
#define NETWORK_SECURITY_LAYER1_PACKET_INGRESS_HPP

#include <pcap.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "../../common/logger.hpp"

namespace NetworkSecurity {
namespace Layer1 {

// ============ Structures ============

struct CaptureStats {
    uint64_t packets_received{0};
    uint64_t packets_dropped{0};
    uint64_t bytes_received{0};
    double capture_rate{0.0};
    double processing_rate{0.0};
    uint64_t queue_size{0};
    uint64_t queue_drops{0};
};

struct PacketData {
    std::vector<uint8_t> data;
    uint64_t timestamp;
    uint32_t original_length;
    
    PacketData() = default;
    PacketData(const uint8_t* pkt_data, size_t len, uint64_t ts, uint32_t orig_len)
        : data(pkt_data, pkt_data + len), 
          timestamp(ts),
          original_length(orig_len) {}
};

// ============ Callback Types ============

using PacketCallback = std::function<void(const uint8_t*, size_t, uint64_t)>;
using PacketCallbackV2 = std::function<void(const PacketData&)>;

// ============ Configuration ============

struct CaptureConfig {
    std::string interface{"any"};
    std::string filter{};
    int snaplen{65535};
    int buffer_size{64 * 1024 * 1024};  // 64MB
    int timeout_ms{1000};
    bool promiscuous_mode{true};
    
    // Queue configuration
    size_t queue_capacity{10000};
    bool enable_queue{false};  // Nếu true, dùng queue + worker threads
    int worker_threads{2};
    
    // Performance tuning
    bool enable_zero_copy{false};  // Experimental
    int batch_size{-1};  // -1 = unlimited
};

// ============ Main Class ============

class PacketIngress {
public:
    PacketIngress();
    explicit PacketIngress(const CaptureConfig& config);
    ~PacketIngress();

    // Disable copy
    PacketIngress(const PacketIngress&) = delete;
    PacketIngress& operator=(const PacketIngress&) = delete;

    // ============ Initialization ============
    bool initialize(const CaptureConfig& config);
    bool initialize(const std::string& interface, 
                   const std::string& filter = "",
                   int snaplen = 65535,
                   int buffer_size = 64*1024*1024);

    // ============ Control ============
    bool start();
    void stop();
    bool isRunning() const { return is_running_.load(); }

    // ============ Callbacks ============
    void registerCallback(PacketCallback callback);
    void registerCallbackV2(PacketCallbackV2 callback);

    // ============ Statistics ============
    CaptureStats getStats() const;
    void resetStats();
    
    // ============ Configuration ============
    void setPromiscuousMode(bool enable);
    void setTimeout(int timeout_ms);
    void setQueueCapacity(size_t capacity);
    
    // ============ Utility ============
    static std::vector<std::string> listInterfaces();
    std::string getLastError() const { return last_error_; }

private:
    // ============ Capture Thread ============
    void captureLoop();
    static void packetHandler(u_char* user, const struct pcap_pkthdr* header, 
                             const u_char* packet);
    
    // ============ Worker Threads (Queue Mode) ============
    void workerLoop(int worker_id);
    bool enqueuePacket(PacketData&& packet);
    
    // ============ Statistics Update ============
    void updateCaptureRate();
    void updateProcessingRate();
    
    // ============ Cleanup ============
    void cleanup();

private:
    // ============ PCAP Handle ============
    pcap_t* pcap_handle_;
    
    // ============ Configuration ============
    CaptureConfig config_;
    std::string last_error_;
    
    // ============ State ============
    std::atomic<bool> is_running_;
    std::atomic<bool> stop_requested_;
    
    // ============ Threads ============
    std::thread capture_thread_;
    std::vector<std::thread> worker_threads_;
    
    // ============ Callbacks ============
    PacketCallback callback_;
    PacketCallbackV2 callback_v2_;
    
    // ============ Packet Queue (Optional) ============
    std::queue<PacketData> packet_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::atomic<size_t> queue_size_;
    
    // ============ Statistics (Atomic) ============
    std::atomic<uint64_t> packets_received_;
    std::atomic<uint64_t> packets_dropped_;
    std::atomic<uint64_t> bytes_received_;
    std::atomic<uint64_t> packets_processed_;
    std::atomic<uint64_t> queue_drops_;
    
    std::atomic<double> capture_rate_;
    std::atomic<double> processing_rate_;
    
    // ============ Rate Calculation ============
    std::chrono::steady_clock::time_point last_stats_time_;
    uint64_t last_packet_count_;
    uint64_t last_processed_count_;
    
    // ============ Logger ============
    Common::Logger logger_;
};

} // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_LAYER1_PACKET_INGRESS_HPP
