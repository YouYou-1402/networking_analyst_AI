// src/core/layer1/packet_ingress.hpp
#ifndef PACKET_INGRESS_HPP
#define PACKET_INGRESS_HPP

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include <thread>
#include <pcap.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include "packet_parser.hpp"

namespace NetworkSecurity
{
    namespace Layer1
    {
        /**
         * @brief Cấu trúc cấu hình cho Packet Ingress
         */
        struct IngressConfig
        {
            std::string interface;      // Tên interface (eth0, wlan0, ...)
            int snaplen;                // Snapshot length (bytes to capture)
            int buffer_size;            // Kernel buffer size (MB)
            int timeout_ms;             // Read timeout (milliseconds)
            bool promiscuous;           // Promiscuous mode
            bool enable_timestamp;      // Hardware timestamping
            std::string bpf_filter;     // Berkeley Packet Filter (optional)

            // Default values
            IngressConfig()
                : interface("wlan0"),
                  snaplen(65535),
                  buffer_size(16),
                  timeout_ms(1000),
                  promiscuous(true),
                  enable_timestamp(true),
                  bpf_filter("") {}
        };

        /**
         * @brief Statistics của Packet Ingress
         */
        struct IngressStats
        {
            uint64_t packets_received;   // Tổng số gói nhận được
            uint64_t packets_dropped;    // Gói bị drop bởi kernel
            uint64_t bytes_received;     // Tổng bytes nhận được
            uint64_t errors;             // Số lỗi
            double capture_rate;         // Packets/second
            uint64_t start_time;         // Thời gian bắt đầu
            uint64_t last_packet_time;   // Thời gian gói cuối

            IngressStats()
                : packets_received(0), packets_dropped(0),
                  bytes_received(0), errors(0), capture_rate(0.0),
                  start_time(0), last_packet_time(0) {}
        };

        /**
         * @brief Callback function type cho packet processing
         * Sử dụng ParsedPacket từ packet_parser.hpp
         */
        using PacketCallback = std::function<void(const Common::ParsedPacket &)>;

        /**
         * @class PacketIngress
         * @brief Lớp chính để bắt gói tin từ network interface
         */
        class PacketIngress
        {
        public:
            /**
             * @brief Constructor
             * @param config Cấu hình ingress
             */
            explicit PacketIngress(const IngressConfig &config);

            /**
             * @brief Destructor
             */
            ~PacketIngress();

            // Disable copy
            PacketIngress(const PacketIngress &) = delete;
            PacketIngress &operator=(const PacketIngress &) = delete;

            /**
             * @brief Khởi tạo và mở interface
             * @return true nếu thành công
             */
            bool initialize();

            /**
             * @brief Bắt đầu capture packets
             * @param callback Function được gọi cho mỗi packet
             * @return true nếu thành công
             */
            bool start(PacketCallback callback);

            /**
             * @brief Dừng capture
             */
            void stop();

            /**
             * @brief Kiểm tra trạng thái running
             * @return true nếu đang chạy
             */
            bool isRunning() const { return running_.load(); }

            /**
             * @brief Lấy statistics
             * @return IngressStats
             */
            IngressStats getStats() const;

            /**
             * @brief Reset statistics
             */
            void resetStats();

            /**
             * @brief Lấy tên interface
             */
            std::string getInterface() const { return config_.interface; }

            /**
             * @brief Kiểm tra interface có tồn tại không
             * @param interface Tên interface
             * @return true nếu tồn tại
             */
            static bool isInterfaceValid(const std::string &interface);

            /**
             * @brief Liệt kê tất cả interfaces có sẵn
             * @return Vector các tên interface
             */
            static std::vector<std::string> listInterfaces();

            /**
             * @brief Kiểm tra quyền root/CAP_NET_RAW
             * @return true nếu có quyền
             */
            static bool checkPermissions();

        private:
            /**
             * @brief Thiết lập promiscuous mode
             * @return true nếu thành công
             */
            bool setPromiscuousMode();

            /**
             * @brief Thiết lập BPF filter
             * @return true nếu thành công
             */
            bool setBPFFilter();

            /**
             * @brief Thiết lập buffer size
             * @return true nếu thành công
             */
            bool setBufferSize();

            /**
             * @brief Thiết lập hardware timestamping
             * @return true nếu thành công
             */
            bool setHardwareTimestamp();

            /**
             * @brief Callback từ libpcap
             */
            static void pcapCallback(u_char *user, const struct pcap_pkthdr *header,
                                     const u_char *packet);

            /**
             * @brief Xử lý packet - parse và gọi user callback
             */
            void processPacket(const struct pcap_pkthdr *header, const u_char *packet);

            /**
             * @brief Cập nhật statistics
             */
            void updateStats();

            /**
             * @brief Thread function cho capture loop
             */
            void captureLoop();

        private:
            IngressConfig config_;              // Cấu hình
            pcap_t *pcap_handle_;              // PCAP handle
            std::atomic<bool> running_;        // Trạng thái running
            std::atomic<bool> initialized_;    // Trạng thái initialized
            PacketCallback callback_;          // User callback
            std::unique_ptr<std::thread> capture_thread_; // Capture thread

            // Parser
            std::unique_ptr<Common::PacketParser> parser_;

            // Statistics
            mutable std::atomic<uint64_t> packets_received_;
            mutable std::atomic<uint64_t> bytes_received_;
            mutable std::atomic<uint64_t> errors_;
            mutable std::atomic<uint64_t> start_time_;
            mutable std::atomic<uint64_t> last_packet_time_;
        };

        /**
         * @class IngressManager
         * @brief Quản lý nhiều interfaces
         */
        class IngressManager
        {
        public:
            IngressManager() = default;
            ~IngressManager();

            /**
             * @brief Thêm interface để monitor
             * @param config Cấu hình interface
             * @return true nếu thành công
             */
            bool addInterface(const IngressConfig &config);

            /**
             * @brief Bắt đầu capture trên tất cả interfaces
             * @param callback Packet callback
             * @return true nếu thành công
             */
            bool startAll(PacketCallback callback);

            /**
             * @brief Dừng tất cả captures
             */
            void stopAll();

            /**
             * @brief Lấy tổng statistics
             */
            IngressStats getTotalStats() const;

            /**
             * @brief Lấy số interfaces đang hoạt động
             */
            size_t getActiveCount() const;

            /**
             * @brief Lấy danh sách interfaces đang monitor
             */
            std::vector<std::string> getActiveInterfaces() const;

        private:
            std::vector<std::unique_ptr<PacketIngress>> ingressors_;
        };

    } // namespace Layer1
} // namespace NetworkSecurity

#endif // PACKET_INGRESS_HPP
