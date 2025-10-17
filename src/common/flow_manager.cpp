// src/common/flow_manager.cpp
#include "flow_manager.hpp"
#include <algorithm>
#include <cstring>

namespace NetworkSecurity
{
    namespace Common
    {
        // ==================== FlowKey Implementation ====================
        
        bool FlowKey::operator==(const FlowKey &other) const
        {
            return src_ip == other.src_ip &&
                   dst_ip == other.dst_ip &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port &&
                   protocol == other.protocol;
        }

        size_t FlowKey::hash() const
        {
            size_t h1 = std::hash<uint32_t>{}(src_ip);
            size_t h2 = std::hash<uint32_t>{}(dst_ip);
            size_t h3 = std::hash<uint16_t>{}(src_port);
            size_t h4 = std::hash<uint16_t>{}(dst_port);
            size_t h5 = std::hash<uint8_t>{}(protocol);
            
            // Combine hashes
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
        }

        // ==================== FlowManager Implementation ====================
        
        FlowManager::FlowManager()
            : max_flows_(100000),
              flow_timeout_ms_(300000), // 5 minutes
              total_packets_(0),
              total_bytes_(0)
        {
        }

        FlowManager::~FlowManager()
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            flows_.clear();
        }

        std::shared_ptr<FlowInfo> FlowManager::processPacket(const ParsedPacket &packet)
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);

            // Create flow key
            FlowKey key = createFlowKey(packet);

            // Find or create flow
            auto it = flows_.find(key);
            std::shared_ptr<FlowInfo> flow;

            if (it != flows_.end())
            {
                // Existing flow
                flow = it->second;
            }
            else
            {
                // Check if we've reached max flows
                if (flows_.size() >= max_flows_)
                {
                    // Clean up expired flows first
                    cleanupExpiredFlows(flow_timeout_ms_);

                    // If still at max, remove oldest flow
                    if (flows_.size() >= max_flows_)
                    {
                        auto oldest = std::min_element(
                            flows_.begin(), flows_.end(),
                            [](const auto &a, const auto &b) {
                                return a.second->last_seen < b.second->last_seen;
                            });
                        
                        if (oldest != flows_.end())
                        {
                            flows_.erase(oldest);
                        }
                    }
                }

                // Create new flow
                flow = std::make_shared<FlowInfo>();
                flow->key = key;
                flow->first_seen = packet.timestamp;
                flow->last_seen = packet.timestamp;
                flow->packet_count = 0;
                flow->byte_count = 0;
                flow->flow_duration = 0;
                flow->is_bidirectional = false;
                flow->is_suspicious = false;
                flow->threat_level = 0;

                flows_[key] = flow;
            }

            // Update flow statistics
            updateFlowStats(flow, packet);

            // Update global statistics
            total_packets_++;
            total_bytes_ += packet.packet_size; // ✅ SỬA TẠI ĐÂY

            return flow;
        }

        std::shared_ptr<FlowInfo> FlowManager::getFlow(const FlowKey &key)
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            
            auto it = flows_.find(key);
            if (it != flows_.end())
            {
                return it->second;
            }
            
            return nullptr;
        }

        size_t FlowManager::cleanupExpiredFlows(uint64_t timeout_ms)
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            
            auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            size_t removed_count = 0;
            
            for (auto it = flows_.begin(); it != flows_.end();)
            {
                if (isFlowExpired(it->second, current_time))
                {
                    it = flows_.erase(it);
                    removed_count++;
                }
                else
                {
                    ++it;
                }
            }

            return removed_count;
        }

        std::vector<std::shared_ptr<FlowInfo>> FlowManager::getAllFlows()
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            
            std::vector<std::shared_ptr<FlowInfo>> result;
            result.reserve(flows_.size());
            
            for (const auto &pair : flows_)
            {
                result.push_back(pair.second);
            }
            
            return result;
        }

        std::vector<std::shared_ptr<FlowInfo>> FlowManager::getSuspiciousFlows()
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            
            std::vector<std::shared_ptr<FlowInfo>> result;
            
            for (const auto &pair : flows_)
            {
                if (pair.second->is_suspicious || pair.second->threat_level > 0)
                {
                    result.push_back(pair.second);
                }
            }
            
            // Sort by threat level (highest first)
            std::sort(result.begin(), result.end(),
                [](const auto &a, const auto &b) {
                    return a->threat_level > b->threat_level;
                });
            
            return result;
        }

        size_t FlowManager::getFlowCount() const
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            return flows_.size();
        }

        size_t FlowManager::getTotalPackets() const
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            return total_packets_;
        }

        size_t FlowManager::getTotalBytes() const
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            return total_bytes_;
        }

        void FlowManager::setMaxFlows(size_t max_flows)
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            max_flows_ = max_flows;
        }

        void FlowManager::setFlowTimeout(uint64_t timeout_ms)
        {
            std::lock_guard<std::mutex> lock(flows_mutex_);
            flow_timeout_ms_ = timeout_ms;
        }

        // ==================== Private Helper Methods ====================

        FlowKey FlowManager::createFlowKey(const ParsedPacket &packet)
        {
            FlowKey key;
            
            // Normalize flow direction (smaller IP/port first for bidirectional matching)
            bool forward = (packet.src_ip < packet.dst_ip) ||
                          (packet.src_ip == packet.dst_ip && packet.src_port < packet.dst_port);
            
            if (forward)
            {
                key.src_ip = packet.src_ip;
                key.dst_ip = packet.dst_ip;
                key.src_port = packet.src_port;
                key.dst_port = packet.dst_port;
            }
            else
            {
                key.src_ip = packet.dst_ip;
                key.dst_ip = packet.src_ip;
                key.src_port = packet.dst_port;
                key.dst_port = packet.src_port;
            }
            
            key.protocol = packet.ip_protocol; // ✅ SỬA: dùng ip_protocol
            
            return key;
        }

        void FlowManager::updateFlowStats(std::shared_ptr<FlowInfo> flow, 
                                          const ParsedPacket &packet)
        {
            // Update basic counters
            flow->packet_count++;
            flow->byte_count += packet.packet_size; // ✅ SỬA TẠI ĐÂY
            
            // Calculate packet interval
            if (flow->last_seen > 0)
            {
                uint64_t interval = packet.timestamp - flow->last_seen;
                flow->packet_intervals.push_back(interval);
                
                // Keep only last 100 intervals to avoid memory bloat
                if (flow->packet_intervals.size() > 100)
                {
                    flow->packet_intervals.erase(flow->packet_intervals.begin());
                }
            }
            
            flow->last_seen = packet.timestamp;
            flow->flow_duration = flow->last_seen - flow->first_seen;
            
            // Store packet size
            flow->packet_sizes.push_back(packet.packet_size); // ✅ SỬA TẠI ĐÂY
            if (flow->packet_sizes.size() > 100)
            {
                flow->packet_sizes.erase(flow->packet_sizes.begin());
            }
            
            // Check for bidirectional traffic
            if (!flow->is_bidirectional)
            {
                // Simple heuristic: if we see packets in both directions
                bool is_reverse = (packet.src_ip == flow->key.dst_ip && 
                                  packet.dst_ip == flow->key.src_ip);
                if (is_reverse)
                {
                    flow->is_bidirectional = true;
                }
            }
            
            // Store payload sample (first 64 bytes of first packet with payload)
            if (flow->payload_sample.empty() && packet.payload_length > 0)
            {
                size_t sample_size = std::min(static_cast<size_t>(64), 
                                             packet.payload_length);
                flow->payload_sample.assign(packet.payload, 
                                           packet.payload + sample_size);
                
                // Try to identify application protocol from payload
                identifyApplicationProtocol(flow);
            }
            
            // Detect suspicious patterns
            detectSuspiciousActivity(flow);
        }

        bool FlowManager::isFlowExpired(const std::shared_ptr<FlowInfo> &flow, 
                                       uint64_t current_time)
        {
            return (current_time - flow->last_seen) > flow_timeout_ms_;
        }

        void FlowManager::identifyApplicationProtocol(std::shared_ptr<FlowInfo> flow)
        {
            if (flow->payload_sample.empty())
            {
                return;
            }

            const auto &payload = flow->payload_sample;
            
            // HTTP detection
            if (payload.size() >= 4)
            {
                if (std::memcmp(payload.data(), "GET ", 4) == 0 ||
                    std::memcmp(payload.data(), "POST", 4) == 0 ||
                    std::memcmp(payload.data(), "HTTP", 4) == 0)
                {
                    flow->application_protocol = "HTTP";
                    return;
                }
            }
            
            // HTTPS/TLS detection
            if (payload.size() >= 3)
            {
                if (payload[0] == 0x16 && payload[1] == 0x03 && 
                    (payload[2] >= 0x00 && payload[2] <= 0x03))
                {
                    flow->application_protocol = "TLS/SSL";
                    return;
                }
            }
            
            // DNS detection
            if (flow->key.dst_port == 53 || flow->key.src_port == 53)
            {
                flow->application_protocol = "DNS";
                return;
            }
            
            // SSH detection
            if (payload.size() >= 4 && std::memcmp(payload.data(), "SSH-", 4) == 0)
            {
                flow->application_protocol = "SSH";
                return;
            }
            
            // FTP detection
            if (flow->key.dst_port == 21 || flow->key.src_port == 21)
            {
                flow->application_protocol = "FTP";
                return;
            }
            
            // SMTP detection
            if (flow->key.dst_port == 25 || flow->key.src_port == 25 ||
                flow->key.dst_port == 587 || flow->key.src_port == 587)
            {
                flow->application_protocol = "SMTP";
                return;
            }
            
            flow->application_protocol = "Unknown";
        }

        void FlowManager::detectSuspiciousActivity(std::shared_ptr<FlowInfo> flow)
        {
            flow->threat_level = 0;
            flow->is_suspicious = false;
            
            // Port scan detection (many packets, small size, not bidirectional)
            if (flow->packet_count > 10 && !flow->is_bidirectional)
            {
                double avg_size = static_cast<double>(flow->byte_count) / flow->packet_count;
                if (avg_size < 100)
                {
                    flow->is_suspicious = true;
                    flow->threat_level = std::max(flow->threat_level, static_cast<uint8_t>(3));
                }
            }
            
            // DDoS detection (high packet rate)
            if (flow->packet_count > 100 && flow->flow_duration > 0)
            {
                double pps = static_cast<double>(flow->packet_count * 1000) / flow->flow_duration;
                if (pps > 1000) // More than 1000 packets per second
                {
                    flow->is_suspicious = true;
                    flow->threat_level = std::max(flow->threat_level, static_cast<uint8_t>(5));
                }
            }
            
            // Unusual packet intervals (potential covert channel)
            if (flow->packet_intervals.size() > 10)
            {
                double sum = 0;
                for (auto interval : flow->packet_intervals)
                {
                    sum += interval;
                }
                double avg = sum / flow->packet_intervals.size();
                
                double variance = 0;
                for (auto interval : flow->packet_intervals)
                {
                    variance += (interval - avg) * (interval - avg);
                }
                variance /= flow->packet_intervals.size();
                
                // Very regular intervals might indicate automated/malicious traffic
                if (variance < 10 && avg > 0)
                {
                    flow->is_suspicious = true;
                    flow->threat_level = std::max(flow->threat_level, static_cast<uint8_t>(2));
                }
            }
            
            // Large data transfer to uncommon ports
            if (flow->byte_count > 10000000 && // > 10MB
                flow->key.dst_port > 1024 && 
                flow->key.dst_port != 8080 && 
                flow->key.dst_port != 8443)
            {
                flow->is_suspicious = true;
                flow->threat_level = std::max(flow->threat_level, static_cast<uint8_t>(4));
            }
        }

    } // namespace Common
} // namespace NetworkSecurity
