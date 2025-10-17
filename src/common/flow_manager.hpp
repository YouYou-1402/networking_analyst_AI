// src/common/flow_manager.hpp
#ifndef FLOW_MANAGER_HPP
#define FLOW_MANAGER_HPP

#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <vector>
#include "packet_parser.hpp"

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Định danh flow 5-tuple
         */
        struct FlowKey
        {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            uint8_t protocol;

            bool operator==(const FlowKey &other) const;
            size_t hash() const;
        };

        /**
         * @brief Thông tin flow
         */
        struct FlowInfo
        {
            FlowKey key;
            uint64_t first_seen;
            uint64_t last_seen;
            uint64_t packet_count;
            uint64_t byte_count;
            uint64_t flow_duration;

            // Statistics
            std::vector<uint64_t> packet_intervals;
            std::vector<size_t> packet_sizes;

            // Flags
            bool is_bidirectional;
            bool is_suspicious;
            uint8_t threat_level;

            // Application layer info
            std::string application_protocol;
            std::vector<uint8_t> payload_sample;
        };

        /**
         * @brief Hash function cho FlowKey
         */
        struct FlowKeyHash
        {
            size_t operator()(const FlowKey &key) const
            {
                return key.hash();
            }
        };

        /**
         * @brief Quản lý flows trong hệ thống
         */
        class FlowManager
        {
        public:
            FlowManager();
            ~FlowManager();

            /**
             * @brief Xử lý packet và cập nhật flow
             */
            std::shared_ptr<FlowInfo> processPacket(const ParsedPacket &packet);

            /**
             * @brief Lấy thông tin flow
             */
            std::shared_ptr<FlowInfo> getFlow(const FlowKey &key);

            /**
             * @brief Xóa flows cũ
             */
            size_t cleanupExpiredFlows(uint64_t timeout_ms = 300000); // 5 phút

            /**
             * @brief Lấy tất cả flows hiện tại
             */
            std::vector<std::shared_ptr<FlowInfo>> getAllFlows();

            /**
             * @brief Lấy flows đáng nghi
             */
            std::vector<std::shared_ptr<FlowInfo>> getSuspiciousFlows();

            /**
             * @brief Thống kê
             */
            size_t getFlowCount() const;
            size_t getTotalPackets() const;
            size_t getTotalBytes() const;

            /**
             * @brief Cấu hình
             */
            void setMaxFlows(size_t max_flows);
            void setFlowTimeout(uint64_t timeout_ms);

        private:
            mutable std::mutex flows_mutex_;
            std::unordered_map<FlowKey, std::shared_ptr<FlowInfo>, FlowKeyHash> flows_;

            // Configuration
            size_t max_flows_;
            uint64_t flow_timeout_ms_;

            // Statistics
            uint64_t total_packets_;
            uint64_t total_bytes_;

            // Helper methods
            FlowKey createFlowKey(const ParsedPacket &packet);
            void updateFlowStats(std::shared_ptr<FlowInfo> flow, const ParsedPacket &packet);
            bool isFlowExpired(const std::shared_ptr<FlowInfo> &flow, uint64_t current_time);

            // flow dang nghi
            void identifyApplicationProtocol(std::shared_ptr<FlowInfo> flow);
            void detectSuspiciousActivity(std::shared_ptr<FlowInfo> flow);

        };

    } // namespace Common
} // namespace NetworkSecurity

#endif // FLOW_MANAGER_HPP
