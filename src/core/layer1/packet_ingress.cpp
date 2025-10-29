// src/core/layer1/packet_ingress.cpp
#include "packet_ingress.hpp"
#include <cstring>
#include <chrono>
#include <algorithm>

namespace NetworkSecurity {
namespace Layer1 {

// ============ Constructor/Destructor ============

PacketIngress::PacketIngress()
    : pcap_handle_(nullptr),
      is_running_(false),
      stop_requested_(false),
      queue_size_(0),
      packets_received_(0),
      packets_dropped_(0),
      bytes_received_(0),
      packets_processed_(0),
      queue_drops_(0),
      capture_rate_(0.0),
      processing_rate_(0.0),
      last_packet_count_(0),
      last_processed_count_(0),
      logger_("PacketIngress")
{
    config_.interface = "any";
    config_.snaplen = 65535;
    config_.buffer_size = 64 * 1024 * 1024;
    config_.timeout_ms = 1000;
    config_.promiscuous_mode = true;
    config_.queue_capacity = 10000;
    config_.enable_queue = false;
    config_.worker_threads = 2;
}

PacketIngress::PacketIngress(const CaptureConfig& config)
    : PacketIngress()
{
    config_ = config;
}

PacketIngress::~PacketIngress() {
    stop();
    cleanup();
}

// ============ Initialization ============

bool PacketIngress::initialize(const CaptureConfig& config) {
    if (is_running_) {
        last_error_ = "Cannot initialize while running";
        logger_.error(last_error_);
        return false;
    }

    config_ = config;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Mở interface
    pcap_handle_ = pcap_open_live(
        config_.interface.c_str(),
        config_.snaplen,
        config_.promiscuous_mode ? 1 : 0,
        config_.timeout_ms,
        errbuf
    );

    if (!pcap_handle_) {
        last_error_ = std::string("Failed to open interface: ") + errbuf;
        logger_.error(last_error_);
        return false;
    }

    // Set buffer size (phải gọi TRƯỚC khi activate)
    // Note: pcap_set_buffer_size chỉ work với pcap_create/pcap_activate
    // Với pcap_open_live, buffer size được set qua system
    
    // Set immediate mode (giảm latency)
#ifdef PCAP_D_IN
    if (pcap_set_immediate_mode(pcap_handle_, 1) != 0) {
        logger_.warn("Failed to set immediate mode");
    }
#endif

    // Compile và apply filter
    if (!config_.filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(pcap_handle_, &fp, config_.filter.c_str(), 
                        1, PCAP_NETMASK_UNKNOWN) == -1) {
            last_error_ = std::string("Failed to compile filter: ") + 
                         pcap_geterr(pcap_handle_);
            logger_.error(last_error_);
            cleanup();
            return false;
        }

        if (pcap_setfilter(pcap_handle_, &fp) == -1) {
            last_error_ = std::string("Failed to set filter: ") + 
                         pcap_geterr(pcap_handle_);
            logger_.error(last_error_);
            pcap_freecode(&fp);
            cleanup();
            return false;
        }
        
        pcap_freecode(&fp);
        logger_.info("Applied BPF filter: {}", config_.filter);
    }

    // Set non-blocking mode nếu cần
    // pcap_setnonblock(pcap_handle_, 1, errbuf);

    logger_.info("Initialized packet capture on interface: {} (snaplen={}, buffer={}MB, queue={})",
                config_.interface, config_.snaplen, 
                config_.buffer_size / (1024*1024),
                config_.enable_queue ? "enabled" : "disabled");
    
    return true;
}

bool PacketIngress::initialize(const std::string& interface, 
                               const std::string& filter,
                               int snaplen,
                               int buffer_size) {
    CaptureConfig config;
    config.interface = interface;
    config.filter = filter;
    config.snaplen = snaplen;
    config.buffer_size = buffer_size;
    
    return initialize(config);
}

// ============ Control ============

bool PacketIngress::start() {
    if (is_running_) {
        logger_.warn("Packet capture already running");
        return false;
    }

    if (!pcap_handle_) {
        last_error_ = "Not initialized";
        logger_.error(last_error_);
        return false;
    }

    // Reset state
    is_running_ = true;
    stop_requested_ = false;
    last_stats_time_ = std::chrono::steady_clock::now();
    last_packet_count_ = 0;
    last_processed_count_ = 0;

    // Start worker threads nếu enable queue
    if (config_.enable_queue) {
        for (int i = 0; i < config_.worker_threads; i++) {
            worker_threads_.emplace_back(&PacketIngress::workerLoop, this, i);
        }
        logger_.info("Started {} worker threads", config_.worker_threads);
    }

    // Start capture thread
    capture_thread_ = std::thread(&PacketIngress::captureLoop, this);
    
    logger_.info("Started packet capture");
    return true;
}

void PacketIngress::stop() {
    if (!is_running_) return;

    logger_.info("Stopping packet capture...");
    
    stop_requested_ = true;
    is_running_ = false;
    
    // Break pcap loop
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }

    // Wake up worker threads
    queue_cv_.notify_all();

    // Join capture thread
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }

    // Join worker threads
    for (auto& worker : worker_threads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    worker_threads_.clear();

    // Clear queue
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!packet_queue_.empty()) {
            packet_queue_.pop();
        }
        queue_size_ = 0;
    }

    logger_.info("Stopped packet capture (received={}, dropped={}, queue_drops={})",
                packets_received_.load(), packets_dropped_.load(), 
                queue_drops_.load());
}

// ============ Capture Loop ============

void PacketIngress::captureLoop() {
    logger_.info("Capture thread started (tid={})", std::this_thread::get_id());
    
    auto last_stats_time = std::chrono::steady_clock::now();
    uint64_t last_packet_count = 0;

    while (is_running_ && !stop_requested_) {
        // Batch process packets
        int result = pcap_dispatch(
            pcap_handle_, 
            config_.batch_size,  // -1 = unlimited, >0 = max packets per call
            packetHandler, 
            reinterpret_cast<u_char*>(this)
        );
        
        if (result == -1) {
            last_error_ = std::string("pcap_dispatch error: ") + 
                         pcap_geterr(pcap_handle_);
            logger_.error(last_error_);
            break;
        }
        else if (result == -2) {
            // pcap_breakloop() called
            logger_.debug("pcap_breakloop() detected");
            break;
        }

        // Update capture rate mỗi giây
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_stats_time).count();
        
        if (elapsed >= 1000) {  // 1 second
            updateCaptureRate();
            updateProcessingRate();
            last_stats_time = now;
            
            // Log stats (optional, có thể comment để giảm overhead)
            if (logger_.getLevel() <= Common::LogLevel::DEBUG) {
                auto stats = getStats();
                logger_.debug("Capture: {:.0f} pps, Processing: {:.0f} pps, Queue: {}", 
                            stats.capture_rate, stats.processing_rate, stats.queue_size);
            }
        }

        // Yield CPU nếu không có packets (tránh busy-wait)
        if (result == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }
    
    // Get final pcap stats
    struct pcap_stat ps;
    if (pcap_stats(pcap_handle_, &ps) == 0) {
        packets_dropped_ = ps.ps_drop;
        logger_.info("PCAP stats: received={}, dropped={}, ifdrop={}", 
                    ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    }

    logger_.info("Capture thread stopped");
}

void PacketIngress::packetHandler(u_char* user, 
                                  const struct pcap_pkthdr* header, 
                                  const u_char* packet) {
    auto* self = reinterpret_cast<PacketIngress*>(user);
    
    // Update atomic stats
    self->packets_received_.fetch_add(1, std::memory_order_relaxed);
    self->bytes_received_.fetch_add(header->len, std::memory_order_relaxed);

    // Timestamp (microseconds)
    uint64_t timestamp = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;

    // Queue mode: enqueue packet for worker threads
    if (self->config_.enable_queue) {
        PacketData pkt_data(packet, header->caplen, timestamp, header->len);
        
        if (!self->enqueuePacket(std::move(pkt_data))) {
            // Queue full - drop packet
            self->queue_drops_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // Direct mode: call callback immediately
    else {
        if (self->callback_) {
            self->callback_(packet, header->caplen, timestamp);
            self->packets_processed_.fetch_add(1, std::memory_order_relaxed);
        }
        
        if (self->callback_v2_) {
            PacketData pkt_data(packet, header->caplen, timestamp, header->len);
            self->callback_v2_(pkt_data);
        }
    }
}

// ============ Worker Threads (Queue Mode) ============

bool PacketIngress::enqueuePacket(PacketData&& packet) {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    
    // Check queue capacity
    if (packet_queue_.size() >= config_.queue_capacity) {
        return false;  // Queue full
    }
    
    packet_queue_.push(std::move(packet));
    queue_size_.store(packet_queue_.size(), std::memory_order_relaxed);
    
    lock.unlock();
    queue_cv_.notify_one();
    
    return true;
}

void PacketIngress::workerLoop(int worker_id) {
    logger_.info("Worker thread {} started", worker_id);
    
    while (is_running_ || !packet_queue_.empty()) {
        PacketData packet;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            // Wait for packets
            queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !packet_queue_.empty() || !is_running_;
            });
            
            if (packet_queue_.empty()) {
                if (!is_running_) break;
                continue;
            }
            
            // Get packet
            packet = std::move(packet_queue_.front());
            packet_queue_.pop();
            queue_size_.store(packet_queue_.size(), std::memory_order_relaxed);
        }
        
        // Process packet (outside lock)
        if (callback_) {
            callback_(packet.data.data(), packet.data.size(), packet.timestamp);
        }
        
        if (callback_v2_) {
            callback_v2_(packet);
        }
        
        packets_processed_.fetch_add(1, std::memory_order_relaxed);
    }
    
    logger_.info("Worker thread {} stopped", worker_id);
}

// ============ Callbacks ============

void PacketIngress::registerCallback(PacketCallback callback) {
    callback_ = callback;
}

void PacketIngress::registerCallbackV2(PacketCallbackV2 callback) {
    callback_v2_ = callback;
}

// ============ Statistics ============

CaptureStats PacketIngress::getStats() const {
    CaptureStats stats;
    stats.packets_received = packets_received_.load(std::memory_order_relaxed);
    stats.packets_dropped = packets_dropped_.load(std::memory_order_relaxed);
    stats.bytes_received = bytes_received_.load(std::memory_order_relaxed);
    stats.capture_rate = capture_rate_.load(std::memory_order_relaxed);
    stats.processing_rate = processing_rate_.load(std::memory_order_relaxed);
    stats.queue_size = queue_size_.load(std::memory_order_relaxed);
    stats.queue_drops = queue_drops_.load(std::memory_order_relaxed);
    return stats;
}

void PacketIngress::resetStats() {
    packets_received_ = 0;
    packets_dropped_ = 0;
    bytes_received_ = 0;
    packets_processed_ = 0;
    queue_drops_ = 0;
    capture_rate_ = 0.0;
    processing_rate_ = 0.0;
    last_packet_count_ = 0;
    last_processed_count_ = 0;
    last_stats_time_ = std::chrono::steady_clock::now();
}

void PacketIngress::updateCaptureRate() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_stats_time_).count() / 1000.0;
    
    if (elapsed > 0) {
        uint64_t current_count = packets_received_.load(std::memory_order_relaxed);
        double rate = (current_count - last_packet_count_) / elapsed;
        capture_rate_.store(rate, std::memory_order_relaxed);
        last_packet_count_ = current_count;
        last_stats_time_ = now;
    }
}

void PacketIngress::updateProcessingRate() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_stats_time_).count() / 1000.0;
    
    if (elapsed > 0) {
        uint64_t current_count = packets_processed_.load(std::memory_order_relaxed);
        double rate = (current_count - last_processed_count_) / elapsed;
        processing_rate_.store(rate, std::memory_order_relaxed);
        last_processed_count_ = current_count;
    }
}

// ============ Configuration ============

void PacketIngress::setPromiscuousMode(bool enable) {
    config_.promiscuous_mode = enable;
}

void PacketIngress::setTimeout(int timeout_ms) {
    config_.timeout_ms = timeout_ms;
}

void PacketIngress::setQueueCapacity(size_t capacity) {
    config_.queue_capacity = capacity;
}

// ============ Utility ============

std::vector<std::string> PacketIngress::listInterfaces() {
    std::vector<std::string> interfaces;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return interfaces;
    }
    
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        interfaces.push_back(dev->name);
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

// ============ Cleanup ============

void PacketIngress::cleanup() {
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

} // namespace Layer1
} // namespace NetworkSecurity
