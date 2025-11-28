// src/core/layer1/filter/packet_filter.cpp

#include "packet_filter.hpp"
#include <spdlog/spdlog.h>
#include <chrono>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // ==================== PacketFilter Implementation ====================

            PacketFilter::PacketFilter()
                : total_packets_(0),
                  matched_packets_(0),
                  rejected_packets_(0),
                  total_eval_time_ns_(0),
                  stats_enabled_(true)
            {
            }

            PacketFilter::~PacketFilter()
            {
            }

            bool PacketFilter::setFilter(const std::string& filterString)
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);

                if (filterString.empty())
                {
                    clearFilter();
                    return true;
                }

                // Parse filter
                Parser parser;
                auto expr = parser.parse(filterString);

                if (!expr)
                {
                    last_error_ = parser.getError();
                    spdlog::error("Failed to set filter: {}", last_error_);
                    return false;
                }

                // Set new filter
                filter_string_ = filterString;
                filter_expression_ = expr;
                last_error_.clear();

                spdlog::info("Filter set: {}", filterString);
                return true;
            }

            void PacketFilter::clearFilter()
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);
                
                filter_string_.clear();
                filter_expression_.reset();
                last_error_.clear();

                spdlog::info("Filter cleared");
            }

            bool PacketFilter::hasFilter() const
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);
                return filter_expression_ != nullptr;
            }

            std::string PacketFilter::getFilterString() const
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);
                return filter_string_;
            }

            bool PacketFilter::matches(const Common::ParsedPacket& packet) const
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);

                // Update statistics
                if (stats_enabled_)
                {
                    total_packets_++;
                }

                // No filter means match all
                if (!filter_expression_)
                {
                    if (stats_enabled_)
                    {
                        matched_packets_++;
                    }
                    return true;
                }

                // Evaluate filter
                auto start = std::chrono::high_resolution_clock::now();
                
                bool result = false;
                try
                {
                    result = filter_expression_->evaluate(packet);
                }
                catch (const std::exception& e)
                {
                    spdlog::error("Filter evaluation error: {}", e.what());
                    result = false;
                }

                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

                // Update statistics
                if (stats_enabled_)
                {
                    total_eval_time_ns_ += duration.count();
                    
                    if (result)
                    {
                        matched_packets_++;
                    }
                    else
                    {
                        rejected_packets_++;
                    }
                }

                return result;
            }

            std::string PacketFilter::getLastError() const
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);
                return last_error_;
            }

            PacketFilter::Statistics PacketFilter::getStatistics() const
            {
                Statistics stats;
                
                stats.total_packets = total_packets_.load();
                stats.matched_packets = matched_packets_.load();
                stats.rejected_packets = rejected_packets_.load();
                
                if (stats.total_packets > 0)
                {
                    stats.match_rate = static_cast<double>(stats.matched_packets) / 
                                      static_cast<double>(stats.total_packets);
                }
                else
                {
                    stats.match_rate = 0.0;
                }
                
                if (stats.total_packets > 0)
                {
                    stats.avg_eval_time_ns = total_eval_time_ns_.load() / stats.total_packets;
                }
                else
                {
                    stats.avg_eval_time_ns = 0;
                }
                
                return stats;
            }

            void PacketFilter::resetStatistics()
            {
                total_packets_ = 0;
                matched_packets_ = 0;
                rejected_packets_ = 0;
                total_eval_time_ns_ = 0;
                
                spdlog::info("Filter statistics reset");
            }

            bool PacketFilter::validateFilter(const std::string& filterString, std::string& error)
            {
                return Parser::validate(filterString, error);
            }

            void PacketFilter::setStatisticsEnabled(bool enabled)
            {
                stats_enabled_ = enabled;
            }

            void PacketFilter::optimize()
            {
                std::lock_guard<std::mutex> lock(filter_mutex_);
                
                if (!filter_expression_)
                {
                    return;
                }

                // TODO: Implement filter optimization
                // - Constant folding
                // - Dead code elimination
                // - Expression reordering (evaluate cheaper expressions first)
                // - Convert to bytecode for faster evaluation
                
                spdlog::info("Filter optimization not yet implemented");
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity
