// src/core/layer1/packet_ingress.cpp

#include "packet_ingress.hpp"
#include "utils.hpp"
#include <spdlog/spdlog.h>
#include <chrono>
#include <cstring>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/capability.h>
#include <errno.h>
#include <stdexcept>

namespace NetworkSecurity
{
    namespace Layer1
    {
        // ==================== PacketIngress Implementation ====================

        PacketIngress::PacketIngress(const IngressConfig &config)
            : config_(config),
              pcap_handle_(nullptr),
              running_(false),
              initialized_(false),
              callback_(nullptr),
              packets_received_(0),
              bytes_received_(0),
              errors_(0),
              start_time_(0),
              last_packet_time_(0)
        {
            // Khởi tạo parser
            parser_ = std::make_unique<Common::PacketParser>();

            spdlog::info("PacketIngress created for interface: {}", config_.interface);
        }

        PacketIngress::~PacketIngress()
        {
            stop();

            if (pcap_handle_)
            {
                pcap_close(pcap_handle_);
                pcap_handle_ = nullptr;
            }

            spdlog::info("PacketIngress destroyed for interface: {}", config_.interface);
        }

        bool PacketIngress::initialize()
        {
            if (initialized_.load())
            {
                spdlog::warn("PacketIngress already initialized for {}", config_.interface);
                return true;
            }

            // 1. Kiểm tra quyền
            if (!checkPermissions())
            {
                spdlog::error("Insufficient permissions. Need root or CAP_NET_RAW capability");
                return false;
            }

            // 2. Kiểm tra interface có tồn tại
            if (!isInterfaceValid(config_.interface))
            {
                spdlog::error("Interface {} does not exist or is not available", config_.interface);
                return false;
            }

            // 3. Tạo PCAP handle (KHÔNG dùng pcap_open_live)
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_handle_ = pcap_create(config_.interface.c_str(), errbuf);
            
            if (!pcap_handle_)
            {
                spdlog::error("Failed to create pcap handle for {}: {}", config_.interface, errbuf);
                return false;
            }

            spdlog::info("Successfully created pcap handle for {}", config_.interface);

            // 4. Set SNAPLEN trước khi activate
            if (pcap_set_snaplen(pcap_handle_, config_.snaplen) != 0)
            {
                spdlog::warn("Failed to set snaplen: {}", pcap_geterr(pcap_handle_));
            }

            // 5. Set PROMISCUOUS MODE trước khi activate
            if (pcap_set_promisc(pcap_handle_, config_.promiscuous ? 1 : 0) != 0)
            {
                spdlog::warn("Failed to set promiscuous mode: {}", pcap_geterr(pcap_handle_));
            }

            // 6. Set TIMEOUT trước khi activate
            if (pcap_set_timeout(pcap_handle_, config_.timeout_ms) != 0)
            {
                spdlog::warn("Failed to set timeout: {}", pcap_geterr(pcap_handle_));
            }

            // 7. Set BUFFER SIZE trước khi activate (QUAN TRỌNG!)
            if (pcap_set_buffer_size(pcap_handle_, config_.buffer_size) != 0)
            {
                spdlog::warn("Failed to set buffer size: {}", pcap_geterr(pcap_handle_));
                spdlog::warn("Will use default buffer size");
            }
            else
            {
                spdlog::info("Buffer size set to {} bytes ({} MB)", 
                    config_.buffer_size, 
                    config_.buffer_size / (1024 * 1024));
            }

            // 8. Set IMMEDIATE MODE (giảm latency - optional)
            if (pcap_set_immediate_mode(pcap_handle_, 1) != 0)
            {
                spdlog::debug("Failed to set immediate mode: {}", pcap_geterr(pcap_handle_));
            }

            // 9. ACTIVATE sau khi đã set tất cả config
            spdlog::info("Activating pcap handle for {}...", config_.interface);
            int activate_result = pcap_activate(pcap_handle_);

            if (activate_result != 0)
            {
                if (activate_result == PCAP_WARNING)
                {
                    spdlog::warn("Activation warning: {}", pcap_geterr(pcap_handle_));
                }
                else if (activate_result == PCAP_WARNING_PROMISC_NOTSUP)
                {
                    spdlog::warn("Promiscuous mode not supported on {}", config_.interface);
                }
                else if (activate_result == PCAP_ERROR_PERM_DENIED)
                {
                    spdlog::error("Permission denied. Run with sudo!");
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                    return false;
                }
                else if (activate_result == PCAP_ERROR_RFMON_NOTSUP)
                {
                    spdlog::error("Monitor mode not supported on {}", config_.interface);
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                    return false;
                }
                else
                {
                    spdlog::error("Failed to activate {}: {}", config_.interface, pcap_geterr(pcap_handle_));
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                    return false;
                }
            }

            spdlog::info("Successfully opened interface: {}", config_.interface);

            // 10. Thiết lập BPF filter (SAU khi activate)
            if (!config_.bpf_filter.empty())
            {
                if (!setBPFFilter())
                {
                    spdlog::error("Failed to set BPF filter: {}", config_.bpf_filter);
                    pcap_close(pcap_handle_);
                    pcap_handle_ = nullptr;
                    return false;
                }
                spdlog::info("BPF filter applied: {}", config_.bpf_filter);
            }

            // 11. Thiết lập hardware timestamp (optional)
            if (config_.enable_timestamp)
            {
                if (!setHardwareTimestamp())
                {
                    spdlog::debug("Hardware timestamping not available, using software timestamp");
                }
            }

            // 12. Get datalink type
            int datalink = pcap_datalink(pcap_handle_);
            const char* datalink_name = pcap_datalink_val_to_name(datalink);
            const char* datalink_desc = pcap_datalink_val_to_description(datalink);
            
            spdlog::info("Datalink type: {} ({})", 
                datalink_name ? datalink_name : "unknown",
                datalink_desc ? datalink_desc : "unknown");

            initialized_.store(true);

            // 13. Log thông tin cấu hình
            spdlog::info("PacketIngress initialized successfully for {}", config_.interface);
            spdlog::info("  - Snaplen: {} bytes", config_.snaplen);
            spdlog::info("  - Buffer: {} MB", config_.buffer_size / (1024 * 1024));
            spdlog::info("  - Promiscuous: {}", config_.promiscuous ? "enabled" : "disabled");
            spdlog::info("  - Timeout: {} ms", config_.timeout_ms);

            return true;
        }

        bool PacketIngress::start(PacketCallback callback)
        {
            if (!initialized_.load())
            {
                spdlog::error("PacketIngress not initialized. Call initialize() first");
                return false;
            }

            if (running_.load())
            {
                spdlog::warn("PacketIngress already running for {}", config_.interface);
                return false;
            }

            if (!callback)
            {
                spdlog::error("Callback function is null");
                return false;
            }

            callback_ = callback;
            running_.store(true);

            // Reset statistics
            resetStats();

            // Ghi log bắt đầu
            start_time_.store(Common::Utils::getCurrentTimestampUs());
            auto start_time_str = Common::Utils::formatTimestamp(start_time_.load());
            spdlog::info("========================================");
            spdlog::info("Packet capture STARTED");
            spdlog::info("Interface: {}", config_.interface);
            spdlog::info("Start time: {}", start_time_str);
            spdlog::info("========================================");

            // Bắt đầu capture thread
            capture_thread_ = std::make_unique<std::thread>(&PacketIngress::captureLoop, this);

            return true;
        }

        void PacketIngress::stop()
        {
            if (!running_.load())
            {
                return;
            }

            spdlog::info("Stopping packet capture on {}...", config_.interface);

            running_.store(false);

            // Break pcap loop
            if (pcap_handle_)
            {
                pcap_breakloop(pcap_handle_);
            }

            // Wait for capture thread
            if (capture_thread_ && capture_thread_->joinable())
            {
                capture_thread_->join();
            }

            // Ghi log kết thúc
            uint64_t end_time = Common::Utils::getCurrentTimestampUs();
            auto end_time_str = Common::Utils::formatTimestamp(end_time);
            uint64_t duration_sec = (end_time - start_time_.load()) / 1000000;

            IngressStats stats = getStats();

            spdlog::info("========================================");
            spdlog::info("Packet capture STOPPED");
            spdlog::info("Interface: {}", config_.interface);
            spdlog::info("End time: {}", end_time_str);
            spdlog::info("Duration: {} seconds", duration_sec);
            spdlog::info("----------------------------------------");
            spdlog::info("Statistics:");
            spdlog::info("  - Packets received: {}", stats.packets_received);
            spdlog::info("  - Packets dropped: {}", stats.packets_dropped);
            spdlog::info("  - Bytes received: {} ({:.2f} MB)",
                         stats.bytes_received,
                         stats.bytes_received / (1024.0 * 1024.0));
            spdlog::info("  - Errors: {}", stats.errors);
            spdlog::info("  - Average rate: {:.2f} packets/sec", stats.capture_rate);
            spdlog::info("========================================");
        }

        void PacketIngress::captureLoop()
        {
            spdlog::debug("Capture loop started for {}", config_.interface);

            // Sử dụng pcap_loop với callback
            int result = pcap_loop(pcap_handle_, -1, pcapCallback, reinterpret_cast<u_char *>(this));

            if (result == -1)
            {
                char *err = pcap_geterr(pcap_handle_);
                spdlog::error("pcap_loop error: {}", err);
            }
            else if (result == -2)
            {
                spdlog::debug("pcap_loop stopped by breakloop");
            }

            spdlog::debug("Capture loop ended for {}", config_.interface);
        }

        void PacketIngress::pcapCallback(u_char *user, const struct pcap_pkthdr *header,
                                         const u_char *packet)
        {
            PacketIngress *self = reinterpret_cast<PacketIngress *>(user);
            self->processPacket(header, packet);
        }

        void PacketIngress::processPacket(const struct pcap_pkthdr *header, const u_char *packet)
        {
            if (!running_.load())
            {
                return;
            }

            // Cập nhật statistics
            packets_received_.fetch_add(1);
            bytes_received_.fetch_add(header->caplen);
            last_packet_time_.store(Common::Utils::getCurrentTimestampUs());

            // Parse packet sử dụng PacketParser
            Common::ParsedPacket parsed;
            if (!parser_->parsePacket(packet, header->caplen, parsed))
            {
                errors_.fetch_add(1);
                spdlog::debug("Failed to parse packet on {}", config_.interface);
                return;
            }

            // Điền thêm metadata
            parsed.interface_name = config_.interface;
            parsed.timestamp = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
            parsed.packet_size = header->len;
            parsed.captured_length = header->caplen;

            // Gọi user callback
            try
            {
                if (callback_)
                {
                    callback_(parsed);
                }
            }
            catch (const std::exception &e)
            {
                errors_.fetch_add(1);
                spdlog::error("Exception in packet callback: {}", e.what());
            }

            // Cập nhật stats định kỳ (mỗi 10000 packets)
            if (packets_received_.load() % 10000 == 0)
            {
                updateStats();
            }
        }

        void PacketIngress::updateStats()
        {
            IngressStats stats = getStats();

            spdlog::info("[{}] Packets: {} | Dropped: {} | Rate: {:.2f} pps | Bytes: {:.2f} MB",
                         config_.interface,
                         stats.packets_received,
                         stats.packets_dropped,
                         stats.capture_rate,
                         stats.bytes_received / (1024.0 * 1024.0));
        }

        IngressStats PacketIngress::getStats() const
        {
            IngressStats stats;

            stats.packets_received = packets_received_.load();
            stats.bytes_received = bytes_received_.load();
            stats.errors = errors_.load();
            stats.start_time = start_time_.load();
            stats.last_packet_time = last_packet_time_.load();

            // Lấy dropped packets từ pcap
            if (pcap_handle_)
            {
                struct pcap_stat pstats;
                if (pcap_stats(pcap_handle_, &pstats) == 0)
                {
                    stats.packets_dropped = pstats.ps_drop;
                }
            }

            // Tính capture rate
            uint64_t duration_us = stats.last_packet_time - stats.start_time;
            if (duration_us > 0)
            {
                stats.capture_rate = (stats.packets_received * 1000000.0) / duration_us;
            }

            return stats;
        }

        void PacketIngress::resetStats()
        {
            packets_received_.store(0);
            bytes_received_.store(0);
            errors_.store(0);
            start_time_.store(Common::Utils::getCurrentTimestampUs());
            last_packet_time_.store(start_time_.load());
        }

        // ==================== Configuration Methods ====================

        bool PacketIngress::setPromiscuousMode()
        {
            // Promiscuous mode đã được set trong pcap_open_live
            // Hàm này để verify hoặc set thêm qua ioctl nếu cần

            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0)
            {
                spdlog::error("Failed to create socket for promiscuous mode check");
                return false;
            }

            struct ifreq ifr;
            std::memset(&ifr, 0, sizeof(ifr));
            std::strncpy(ifr.ifr_name, config_.interface.c_str(), IFNAMSIZ - 1);

            if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
            {
                spdlog::error("Failed to get interface flags: {}", strerror(errno));
                close(sock);
                return false;
            }

            if (config_.promiscuous)
            {
                ifr.ifr_flags |= IFF_PROMISC;
            }
            else
            {
                ifr.ifr_flags &= ~IFF_PROMISC;
            }

            if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
            {
                spdlog::error("Failed to set promiscuous mode: {}", strerror(errno));
                close(sock);
                return false;
            }

            close(sock);
            spdlog::debug("Promiscuous mode {} for {}",
                          config_.promiscuous ? "enabled" : "disabled",
                          config_.interface);
            return true;
        }

        bool PacketIngress::setBPFFilter()
        {
            if (!pcap_handle_ || config_.bpf_filter.empty())
            {
                return false;
            }

            struct bpf_program fp;
            bpf_u_int32 net = 0;
            bpf_u_int32 mask = 0;

            // Get network number and mask
            char errbuf[PCAP_ERRBUF_SIZE];
            if (pcap_lookupnet(config_.interface.c_str(), &net, &mask, errbuf) == -1)
            {
                spdlog::warn("pcap_lookupnet failed: {}", errbuf);
                net = 0;
                mask = 0;
            }

            // Compile filter
            if (pcap_compile(pcap_handle_, &fp, config_.bpf_filter.c_str(), 1, mask) == -1)
            {
                spdlog::error("Failed to compile BPF filter: {}", pcap_geterr(pcap_handle_));
                return false;
            }

            // Set filter
            if (pcap_setfilter(pcap_handle_, &fp) == -1)
            {
                spdlog::error("Failed to set BPF filter: {}", pcap_geterr(pcap_handle_));
                pcap_freecode(&fp);
                return false;
            }

            pcap_freecode(&fp);
            return true;
        }

        // bool PacketIngress::setBufferSize()
        // {
        //     if (!pcap_handle_)
        //     {
        //         return false;
        //     }

        //     // Set buffer size (in bytes)
        //     int buffer_size_bytes = config_.buffer_size * 1024 * 1024;

        //     if (pcap_set_buffer_size(pcap_handle_, buffer_size_bytes) != 0)
        //     {
        //         spdlog::warn("Failed to set buffer size: {}", pcap_geterr(pcap_handle_));
        //         return false;
        //     }

        //     spdlog::debug("Buffer size set to {} MB", config_.buffer_size);
        //     return true;
        // }

        bool PacketIngress::setHardwareTimestamp()
        {
            // Hardware timestamping requires special kernel support
            // This is optional and may not be available on all systems

#ifdef PCAP_TSTAMP_ADAPTER
            if (!pcap_handle_)
            {
                return false;
            }

            if (pcap_set_tstamp_type(pcap_handle_, PCAP_TSTAMP_ADAPTER) != 0)
            {
                spdlog::debug("Hardware timestamping not available");
                return false;
            }

            spdlog::debug("Hardware timestamping enabled");
            return true;
#else
            return false;
#endif
        }

        // ==================== Static Utility Methods ====================

        bool PacketIngress::isInterfaceValid(const std::string &interface)
        {
            struct ifaddrs *ifaddr, *ifa;

            if (getifaddrs(&ifaddr) == -1)
            {
                spdlog::error("getifaddrs failed: {}", strerror(errno));
                return false;
            }

            bool found = false;
            for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_name && interface == ifa->ifa_name)
                {
                    found = true;
                    break;
                }
            }

            freeifaddrs(ifaddr);
            return found;
        }

        std::vector<std::string> PacketIngress::listInterfaces()
        {
            std::vector<std::string> interfaces;

            pcap_if_t *alldevs;
            char errbuf[PCAP_ERRBUF_SIZE];

            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                spdlog::error("pcap_findalldevs failed: {}", errbuf);
                return interfaces;
            }

            for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
            {
                interfaces.push_back(dev->name);
            }

            pcap_freealldevs(alldevs);

            return interfaces;
        }

        bool PacketIngress::checkPermissions()
        {
            // Kiểm tra xem có quyền root hoặc CAP_NET_RAW không
            if (geteuid() == 0)
            {
                return true; // Root user
            }

            // Kiểm tra capabilities (Linux)
#ifdef __linux__
            cap_t caps = cap_get_proc();
            if (caps)
            {
                cap_flag_value_t cap_value;
                if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_value) == 0)
                {
                    cap_free(caps);
                    return (cap_value == CAP_SET);
                }
                cap_free(caps);
            }
#endif

            return false;
        }

        // ==================== IngressManager Implementation ====================

        IngressManager::~IngressManager()
        {
            stopAll();
        }

        bool IngressManager::addInterface(const IngressConfig &config)
        {
            // Kiểm tra interface đã tồn tại chưa
            for (const auto &ingress : ingressors_)
            {
                if (ingress->getInterface() == config.interface)
                {
                    spdlog::warn("Interface {} already added", config.interface);
                    return false;
                }
            }

            // Tạo PacketIngress mới
            auto ingress = std::make_unique<PacketIngress>(config);

            if (!ingress->initialize())
            {
                spdlog::error("Failed to initialize interface {}", config.interface);
                return false;
            }

            ingressors_.push_back(std::move(ingress));

            spdlog::info("Interface {} added to IngressManager", config.interface);
            return true;
        }

        bool IngressManager::startAll(PacketCallback callback)
        {
            if (ingressors_.empty())
            {
                spdlog::error("No interfaces to start");
                return false;
            }

            spdlog::info("Starting capture on {} interface(s)...", ingressors_.size());

            bool all_success = true;
            for (auto &ingress : ingressors_)
            {
                if (!ingress->start(callback))
                {
                    spdlog::error("Failed to start capture on {}", ingress->getInterface());
                    all_success = false;
                }
            }

            return all_success;
        }

        void IngressManager::stopAll()
        {
            spdlog::info("Stopping all captures...");

            for (auto &ingress : ingressors_)
            {
                ingress->stop();
            }
        }

        IngressStats IngressManager::getTotalStats() const
        {
            IngressStats total;

            for (const auto &ingress : ingressors_)
            {
                IngressStats stats = ingress->getStats();
                total.packets_received += stats.packets_received;
                total.packets_dropped += stats.packets_dropped;
                total.bytes_received += stats.bytes_received;
                total.errors += stats.errors;

                // Start time = earliest
                if (total.start_time == 0 || stats.start_time < total.start_time)
                {
                    total.start_time = stats.start_time;
                }

                // Last packet time = latest
                if (stats.last_packet_time > total.last_packet_time)
                {
                    total.last_packet_time = stats.last_packet_time;
                }
            }

            // Tính capture rate
            uint64_t duration_us = total.last_packet_time - total.start_time;
            if (duration_us > 0)
            {
                total.capture_rate = (total.packets_received * 1000000.0) / duration_us;
            }

            return total;
        }

        size_t IngressManager::getActiveCount() const
        {
            size_t count = 0;
            for (const auto &ingress : ingressors_)
            {
                if (ingress->isRunning())
                {
                    count++;
                }
            }
            return count;
        }

        std::vector<std::string> IngressManager::getActiveInterfaces() const
        {
            std::vector<std::string> interfaces;
            for (const auto &ingress : ingressors_)
            {
                if (ingress->isRunning())
                {
                    interfaces.push_back(ingress->getInterface());
                }
            }
            return interfaces;
        }

    } // namespace Layer1
} // namespace NetworkSecurity
