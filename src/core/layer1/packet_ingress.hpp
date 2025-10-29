// src/core/layer1/packet_ingress.hpp
#ifndef NETWORK_SECURITY_PACKET_INGRESS_HPP
#define NETWORK_SECURITY_PACKET_INGRESS_HPP

#include "../../common/packet_parser.hpp"
#include "../../common/utils.hpp"
#include "../../common/logger.hpp"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <functional>
#include <queue>
#include <condition_variable>
#include <pcap.h>

namespace NetworkSecurity
{
    namespace Core
    {
        namespace Layer1
        {
            /**
             * @brief Cấu hình cho PacketIngress
             */
            struct PacketIngressConfig
            {
                std::string interface;              // Tên interface (eth0, wlan0, ...)
                std::string filter;                 // BPF filter
                int snaplen;                        // Snapshot length
                int timeout_ms;                     // Timeout in milliseconds
                bool promiscuous;                   // Promiscuous mode
                int buffer_size;                    // Buffer size
                int num_threads;                    // Number of processing threads
                bool use_xdp;                       // Use XDP/eBPF acceleration
                
                PacketIngressConfig()
                    : interface("any"),
                      filter(""),
                      snaplen(65535),
                      timeout_ms(1000),
                      promiscuous(true),
                      buffer_size(10000),
                      num_threads(4),
                      use_xdp(false)
                {}
            };

            /**
             * @brief Thống kê packet
             */
            struct PacketStatistics
            {
                std::atomic<uint64_t> total_packets{0};
                std::atomic<uint64_t> total_bytes{0};
                std::atomic<uint64_t> dropped_packets{0};
                std::atomic<uint64_t> filtered_packets{0};
                std::atomic<uint64_t> error_packets{0};
                
                // Protocol statistics
                std::atomic<uint64_t> tcp_packets{0};
                std::atomic<uint64_t> udp_packets{0};
                std::atomic<uint64_t> icmp_packets{0};
                std::atomic<uint64_t> other_packets{0};
                
                // Performance metrics
                std::atomic<uint64_t> packets_per_second{0};
                std::atomic<uint64_t> bytes_per_second{0};
                
                std::chrono::steady_clock::time_point start_time;
                std::chrono::steady_clock::time_point last_update;
                
                PacketStatistics()
                {
                    start_time = std::chrono::steady_clock::now();
                    last_update = start_time;
                }
                
                // Delete copy constructor and assignment operator
                PacketStatistics(const PacketStatistics&) = delete;
                PacketStatistics& operator=(const PacketStatistics&) = delete;
                
                // Default move constructor and assignment operator
                PacketStatistics(PacketStatistics&&) = default;
                PacketStatistics& operator=(PacketStatistics&&) = default;
                
                void reset()
                {
                    total_packets = 0;
                    total_bytes = 0;
                    dropped_packets = 0;
                    filtered_packets = 0;
                    error_packets = 0;
                    tcp_packets = 0;
                    udp_packets = 0;
                    icmp_packets = 0;
                    other_packets = 0;
                    packets_per_second = 0;
                    bytes_per_second = 0;
                    start_time = std::chrono::steady_clock::now();
                    last_update = start_time;
                }
                
                // Helper method to get snapshot of statistics
                struct Snapshot
                {
                    uint64_t total_packets;
                    uint64_t total_bytes;
                    uint64_t dropped_packets;
                    uint64_t filtered_packets;
                    uint64_t error_packets;
                    uint64_t tcp_packets;
                    uint64_t udp_packets;
                    uint64_t icmp_packets;
                    uint64_t other_packets;
                    uint64_t packets_per_second;
                    uint64_t bytes_per_second;
                    std::chrono::steady_clock::time_point start_time;
                    std::chrono::steady_clock::time_point last_update;
                };
                
                Snapshot getSnapshot() const
                {
                    Snapshot snap;
                    snap.total_packets = total_packets.load();
                    snap.total_bytes = total_bytes.load();
                    snap.dropped_packets = dropped_packets.load();
                    snap.filtered_packets = filtered_packets.load();
                    snap.error_packets = error_packets.load();
                    snap.tcp_packets = tcp_packets.load();
                    snap.udp_packets = udp_packets.load();
                    snap.icmp_packets = icmp_packets.load();
                    snap.other_packets = other_packets.load();
                    snap.packets_per_second = packets_per_second.load();
                    snap.bytes_per_second = bytes_per_second.load();
                    snap.start_time = start_time;
                    snap.last_update = last_update;
                    return snap;
                }
            };

            /**
             * @brief Callback function type for packet processing
             */
            using PacketCallback = std::function<void(const Common::ParsedPacket&, 
                                                     const uint8_t*, 
                                                     size_t)>;

            /**
             * @brief Lớp quản lý thu thập packet từ network interface
             */
            class PacketIngress
            {
            public:
                PacketIngress();
                ~PacketIngress();

                // Prevent copy
                PacketIngress(const PacketIngress&) = delete;
                PacketIngress& operator=(const PacketIngress&) = delete;

                // ==================== Initialization ====================
                
                /**
                 * @brief Khởi tạo với cấu hình
                 */
                bool initialize(const PacketIngressConfig& config);
                
                /**
                 * @brief Dọn dẹp tài nguyên
                 */
                void cleanup();

                // ==================== Capture Control ====================
                
                /**
                 * @brief Bắt đầu capture packets
                 */
                bool startCapture();
                
                /**
                 * @brief Dừng capture packets
                 */
                void stopCapture();
                
                /**
                 * @brief Kiểm tra trạng thái capture
                 */
                bool isCapturing() const { return is_capturing_.load(); }

                // ==================== Callback Registration ====================
                
                /**
                 * @brief Đăng ký callback xử lý packet
                 */
                void registerCallback(const std::string& name, PacketCallback callback);
                
                /**
                 * @brief Hủy đăng ký callback
                 */
                void unregisterCallback(const std::string& name);
                
                /**
                 * @brief Xóa tất cả callbacks
                 */
                void clearCallbacks();

                // ==================== Statistics ====================
                
                /**
                 * @brief Lấy snapshot thống kê
                 */
                PacketStatistics::Snapshot getStatistics() const;
                
                /**
                 * @brief Reset thống kê
                 */
                void resetStatistics();
                
                /**
                 * @brief In thống kê ra console
                 */
                void printStatistics() const;

                // ==================== Configuration ====================
                
                /**
                 * @brief Cập nhật BPF filter
                 */
                bool updateFilter(const std::string& filter);
                
                /**
                 * @brief Lấy danh sách interfaces có sẵn
                 */
                static std::vector<std::string> getAvailableInterfaces();
                
                /**
                 * @brief Kiểm tra interface có tồn tại không
                 */
                static bool isInterfaceAvailable(const std::string& interface);

            private:
                // ==================== Internal Methods ====================
                
                /**
                 * @brief Thread chính để capture packets
                 */
                void captureThread();
                
                /**
                 * @brief Thread xử lý packets từ queue
                 */
                void processingThread();
                
                /**
                 * @brief Xử lý một packet
                 */
                void processPacket(const uint8_t* packet_data, size_t packet_len);
                
                /**
                 * @brief Callback từ libpcap
                 */
                static void pcapCallback(u_char* user, 
                                        const struct pcap_pkthdr* header,
                                        const u_char* packet);
                
                /**
                 * @brief Cập nhật thống kê hiệu suất
                 */
                void updatePerformanceMetrics();
                
                /**
                 * @brief Thread cập nhật metrics định kỳ
                 */
                void metricsUpdateThread();

                // ==================== Member Variables ====================
                
                // Configuration
                PacketIngressConfig config_;
                
                // PCAP handle
                pcap_t* pcap_handle_;
                
                // Packet parser
                Common::PacketParser parser_;
                
                // Logger
                std::shared_ptr<Common::Logger> logger_;
                
                // Threading
                std::atomic<bool> is_running_;
                std::atomic<bool> is_capturing_;
                std::thread capture_thread_;
                std::vector<std::thread> processing_threads_;
                std::thread metrics_thread_;
                
                // Packet queue
                struct PacketData
                {
                    std::vector<uint8_t> data;
                    size_t length;
                    std::chrono::steady_clock::time_point timestamp;
                };
                std::queue<PacketData> packet_queue_;
                std::mutex queue_mutex_;
                std::condition_variable queue_cv_;
                
                // Callbacks
                std::unordered_map<std::string, PacketCallback> callbacks_;
                std::shared_mutex callbacks_mutex_;
                
                // Statistics
                PacketStatistics stats_;
                mutable std::mutex stats_mutex_;
                
                // Error handling
                std::string last_error_;
                std::mutex error_mutex_;
            };

        } // namespace Layer1
    } // namespace Core
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_PACKET_INGRESS_HPP
