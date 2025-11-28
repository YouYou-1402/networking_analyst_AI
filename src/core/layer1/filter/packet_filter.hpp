// src/core/layer1/filter/packet_filter.hpp

#ifndef NETWORK_SECURITY_PACKET_FILTER_HPP
#define NETWORK_SECURITY_PACKET_FILTER_HPP

#include "filter_expression.hpp"
#include "filter_parser.hpp"
#include "common/packet_parser.hpp"
#include <string>
#include <memory>
#include <atomic>
#include <mutex>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Main packet filter class
             */
            class PacketFilter
            {
            public:
                PacketFilter();
                ~PacketFilter();

                /**
                 * @brief Set filter from string
                 */
                bool setFilter(const std::string& filterString);

                /**
                 * @brief Clear current filter
                 */
                void clearFilter();

                /**
                 * @brief Check if filter is active
                 */
                bool hasFilter() const;

                /**
                 * @brief Get current filter string
                 */
                std::string getFilterString() const;

                /**
                 * @brief Evaluate packet against filter
                 */
                bool matches(const Common::ParsedPacket& packet) const;

                /**
                 * @brief Get last error
                 */
                std::string getLastError() const;

                /**
                 * @brief Statistics
                 */
                struct Statistics
                {
                    uint64_t total_packets;
                    uint64_t matched_packets;
                    uint64_t rejected_packets;
                    double match_rate;
                    uint64_t avg_eval_time_ns;
                };

                Statistics getStatistics() const;
                void resetStatistics();

                /**
                 * @brief Validate filter without applying
                 */
                static bool validateFilter(const std::string& filterString, std::string& error);

                /**
                 * @brief Enable/disable statistics collection
                 */
                void setStatisticsEnabled(bool enabled);

                /**
                 * @brief Optimize filter expression
                 */
                void optimize();

            private:
                std::string filter_string_;
                std::shared_ptr<Expression> filter_expression_;
                Parser parser_;
                std::string last_error_;

                // Statistics
                mutable std::atomic<uint64_t> total_packets_;
                mutable std::atomic<uint64_t> matched_packets_;
                mutable std::atomic<uint64_t> rejected_packets_;
                mutable std::atomic<uint64_t> total_eval_time_ns_;
                mutable bool stats_enabled_;

                // Thread safety
                mutable std::mutex filter_mutex_;
            };

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_PACKET_FILTER_HPP
