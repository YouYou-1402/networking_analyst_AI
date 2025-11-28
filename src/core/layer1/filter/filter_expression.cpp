// src/core/layer1/filter/filter_expression.cpp

#include "filter_expression.hpp"
#include "filter_field_evaluator.hpp"
#include <sstream>
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // ==================== FieldExpression Implementation ====================

            FieldExpression::FieldExpression(FieldType field, Operator op, const std::string& value)
                : field_(field), op_(op), value_(value), value_parsed_(false),
                  value_type_(ValueType::NONE)
            {
            }

            bool FieldExpression::evaluate(const Common::ParsedPacket& packet) const
            {
                // Extract field value from packet
                FieldValue fieldValue;
                ValueType fieldType;
                
                if (!FieldEvaluator::extractFieldValue(packet, field_, fieldValue, fieldType))
                {
                    return false;
                }
                
                // Compare with expected value
                return FieldEvaluator::compareValues(fieldValue, fieldType, op_, value_);
            }

            std::string FieldExpression::toString() const
            {
                std::stringstream ss;
                ss << fieldTypeToString(field_) << " " 
                   << operatorToString(op_) << " " 
                   << value_;
                return ss.str();
            }

            void FieldExpression::parseValue() const
            {
                if (value_parsed_)
                {
                    return;
                }
                
                value_parsed_ = true;
                
                // Try to determine value type
                // Check if it's a number
                if (!value_.empty() && (isdigit(value_[0]) || value_[0] == '-'))
                {
                    try
                    {
                        parsed_value_.number = std::stoull(value_, nullptr, 0);
                        value_type_ = ValueType::NUMBER;
                        return;
                    }
                    catch (...)
                    {
                        // Not a number
                    }
                }
                
                // Check if it's a MAC address (xx:xx:xx:xx:xx:xx)
                if (value_.find(':') != std::string::npos && value_.length() == 17)
                {
                    int values[6];
                    if (sscanf(value_.c_str(), "%x:%x:%x:%x:%x:%x",
                              &values[0], &values[1], &values[2],
                              &values[3], &values[4], &values[5]) == 6)
                    {
                        for (int i = 0; i < 6; i++)
                        {
                            parsed_value_.mac[i] = static_cast<uint8_t>(values[i]);
                        }
                        value_type_ = ValueType::MAC_ADDRESS;
                        return;
                    }
                }
                
                // Check if it's an IPv4 address
                struct in_addr addr;
                if (inet_pton(AF_INET, value_.c_str(), &addr) == 1)
                {
                    parsed_value_.ipv4 = addr.s_addr;
                    value_type_ = ValueType::IP_ADDRESS;
                    return;
                }
                
                // Check if it's an IPv6 address
                struct in6_addr addr6;
                if (inet_pton(AF_INET6, value_.c_str(), &addr6) == 1)
                {
                    std::memcpy(parsed_value_.ipv6, &addr6, 16);
                    value_type_ = ValueType::IP_ADDRESS;
                    return;
                }
                
                // Check if it's a boolean
                std::string lower = value_;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower == "true" || lower == "1")
                {
                    parsed_value_.boolean = true;
                    value_type_ = ValueType::BOOLEAN;
                    return;
                }
                else if (lower == "false" || lower == "0")
                {
                    parsed_value_.boolean = false;
                    value_type_ = ValueType::BOOLEAN;
                    return;
                }
                
                // Default to string
                value_type_ = ValueType::STRING;
            }

            // ==================== ExistenceExpression Implementation ====================

            ExistenceExpression::ExistenceExpression(FieldType field)
                : field_(field)
            {
            }

            bool ExistenceExpression::evaluate(const Common::ParsedPacket& packet) const
            {
                return FieldEvaluator::fieldExists(packet, field_);
            }

            std::string ExistenceExpression::toString() const
            {
                return fieldTypeToString(field_);
            }

            // ==================== LogicalExpression Implementation ====================

            LogicalExpression::LogicalExpression(LogicalOp op,
                                               std::shared_ptr<Expression> left,
                                               std::shared_ptr<Expression> right)
                : op_(op), left_(left), right_(right)
            {
            }

            bool LogicalExpression::evaluate(const Common::ParsedPacket& packet) const
            {
                switch (op_)
                {
                    case LogicalOp::AND:
                        if (!left_ || !right_)
                        {
                            return false;
                        }
                        return left_->evaluate(packet) && right_->evaluate(packet);
                    
                    case LogicalOp::OR:
                        if (!left_ || !right_)
                        {
                            return false;
                        }
                        return left_->evaluate(packet) || right_->evaluate(packet);
                    
                    case LogicalOp::NOT:
                        if (!left_)
                        {
                            return false;
                        }
                        return !left_->evaluate(packet);
                    
                    default:
                        return false;
                }
            }

            std::string LogicalExpression::toString() const
            {
                std::stringstream ss;
                
                switch (op_)
                {
                    case LogicalOp::AND:
                        ss << "(" << (left_ ? left_->toString() : "null") 
                           << " and " 
                           << (right_ ? right_->toString() : "null") << ")";
                        break;
                    
                    case LogicalOp::OR:
                        ss << "(" << (left_ ? left_->toString() : "null") 
                           << " or " 
                           << (right_ ? right_->toString() : "null") << ")";
                        break;
                    
                    case LogicalOp::NOT:
                        ss << "not " << (left_ ? left_->toString() : "null");
                        break;
                    
                    default:
                        ss << "unknown";
                        break;
                }
                
                return ss.str();
            }

            // ==================== RangeExpression Implementation ====================

            RangeExpression::RangeExpression(FieldType field, const std::vector<std::string>& values)
                : field_(field), values_(values)
            {
            }

            bool RangeExpression::evaluate(const Common::ParsedPacket& packet) const
            {
                // Extract field value
                FieldValue fieldValue;
                ValueType fieldType;
                
                if (!FieldEvaluator::extractFieldValue(packet, field_, fieldValue, fieldType))
                {
                    return false;
                }
                
                // Check if field value matches any value in the range
                for (const auto& value : values_)
                {
                    if (FieldEvaluator::compareValues(fieldValue, fieldType, Operator::EQUALS, value))
                    {
                        return true;
                    }
                }
                
                return false;
            }

            std::string RangeExpression::toString() const
            {
                std::stringstream ss;
                ss << fieldTypeToString(field_) << " in {";
                for (size_t i = 0; i < values_.size(); i++)
                {
                    if (i > 0) ss << ", ";
                    ss << values_[i];
                }
                ss << "}";
                return ss.str();
            }

            // ==================== SliceExpression Implementation ====================

            SliceExpression::SliceExpression(size_t start, size_t length,
                                           Operator op, const std::string& value)
                : start_(start), length_(length), op_(op), value_(value)
            {
            }

            bool SliceExpression::evaluate(const Common::ParsedPacket& packet) const
            {
                // Check if slice is within packet bounds
                if (start_ >= packet.packet_size)
                {
                    return false;
                }
                
                size_t actual_length = std::min(length_, packet.packet_size - start_);
                
                // Extract slice data
                const uint8_t* slice_data = packet.raw_data + start_;
                
                // Convert value to bytes for comparison
                std::vector<uint8_t> expected_bytes;
                
                // Parse value as hex string or regular string
                if (value_.size() >= 2 && value_[0] == '0' && (value_[1] == 'x' || value_[1] == 'X'))
                {
                    // Hex string
                    std::string hex = value_.substr(2);
                    for (size_t i = 0; i < hex.length(); i += 2)
                    {
                        if (i + 1 < hex.length())
                        {
                            std::string byte_str = hex.substr(i, 2);
                            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                            expected_bytes.push_back(byte);
                        }
                    }
                }
                else
                {
                    // Regular string - convert to bytes
                    for (char c : value_)
                    {
                        expected_bytes.push_back(static_cast<uint8_t>(c));
                    }
                }
                
                // Compare based on operator
                switch (op_)
                {
                    case Operator::EQUALS:
                        if (expected_bytes.size() != actual_length)
                        {
                            return false;
                        }
                        return std::memcmp(slice_data, expected_bytes.data(), actual_length) == 0;
                    
                    case Operator::NOT_EQUALS:
                        if (expected_bytes.size() != actual_length)
                        {
                            return true;
                        }
                        return std::memcmp(slice_data, expected_bytes.data(), actual_length) != 0;
                    
                    case Operator::CONTAINS:
                    {
                        // Search for pattern in slice
                        if (expected_bytes.empty() || expected_bytes.size() > actual_length)
                        {
                            return false;
                        }
                        
                        for (size_t i = 0; i <= actual_length - expected_bytes.size(); i++)
                        {
                            if (std::memcmp(slice_data + i, expected_bytes.data(), 
                                          expected_bytes.size()) == 0)
                            {
                                return true;
                            }
                        }
                        return false;
                    }
                    
                    default:
                        return false;
                }
            }

            std::string SliceExpression::toString() const
            {
                std::stringstream ss;
                ss << "frame[" << start_ << ":" << length_ << "] " 
                   << operatorToString(op_) << " " << value_;
                return ss.str();
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity
