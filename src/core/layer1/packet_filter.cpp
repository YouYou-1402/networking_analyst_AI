// src/core/layer1/packet_filter.cpp

#include "packet_filter.hpp"
#include "utils.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <arpa/inet.h>
#include <string.h>
namespace NetworkSecurity
{
    namespace Layer1
    {
        // ==================== FieldExpression Implementation ====================
        
        FieldExpression::FieldExpression(FilterFieldType field, FilterOperator op, const std::string& value)
            : field_(field), op_(op), value_(value)
        {
        }

        bool FieldExpression::evaluate(const Common::ParsedPacket& packet) const
        {
            switch (field_)
            {
                // Ethernet fields
                case FilterFieldType::ETH_SRC:
                case FilterFieldType::ETH_DST:
                case FilterFieldType::ETH_ADDR:
                case FilterFieldType::ETH_TYPE:
                case FilterFieldType::VLAN_ID:
                    return evaluateEthernet(packet);
                
                // IPv4 fields
                case FilterFieldType::IP_SRC:
                case FilterFieldType::IP_DST:
                case FilterFieldType::IP_ADDR:
                case FilterFieldType::IP_PROTO:
                case FilterFieldType::IP_VERSION:
                case FilterFieldType::IP_ttl:
                case FilterFieldType::IP_LEN:
                case FilterFieldType::IP_ID:
                case FilterFieldType::IP_FLAGS:
                case FilterFieldType::IP_FRAG_OFFSET:
                    return evaluateIPv4(packet);
                
                // IPv6 fields
                case FilterFieldType::IPV6_SRC:
                case FilterFieldType::IPV6_DST:
                case FilterFieldType::IPV6_ADDR:
                case FilterFieldType::IPV6_NXTHDR:
                case FilterFieldType::IPV6_HLIM:
                case FilterFieldType::IPV6_FLOW:
                    return evaluateIPv6(packet);
                
                // TCP fields
                case FilterFieldType::TCP_SRCPORT:
                case FilterFieldType::TCP_DSTPORT:
                case FilterFieldType::TCP_PORT:
                case FilterFieldType::TCP_SEQ:
                case FilterFieldType::TCP_ACK:
                case FilterFieldType::TCP_FLAGS:
                case FilterFieldType::TCP_FLAGS_SYN:
                case FilterFieldType::TCP_FLAGS_ACK:
                case FilterFieldType::TCP_FLAGS_FIN:
                case FilterFieldType::TCP_FLAGS_RST:
                case FilterFieldType::TCP_FLAGS_PSH:
                case FilterFieldType::TCP_FLAGS_URG:
                case FilterFieldType::TCP_WINDOW:
                case FilterFieldType::TCP_LEN:
                    return evaluateTCP(packet);
                
                // UDP fields
                case FilterFieldType::UDP_SRCPORT:
                case FilterFieldType::UDP_DSTPORT:
                case FilterFieldType::UDP_PORT:
                case FilterFieldType::UDP_LENGTH:
                    return evaluateUDP(packet);
                
                // ICMP fields
                case FilterFieldType::ICMP_TYPE:
                case FilterFieldType::ICMP_CODE:
                case FilterFieldType::ICMPV6_TYPE:
                case FilterFieldType::ICMPV6_CODE:
                    return evaluateICMP(packet);
                
                // ARP fields
                case FilterFieldType::ARP_OPCODE:
                case FilterFieldType::ARP_SRC_HW:
                case FilterFieldType::ARP_DST_HW:
                case FilterFieldType::ARP_SRC_PROTO:
                case FilterFieldType::ARP_DST_PROTO:
                    return evaluateARP(packet);
                
                // General fields
                case FilterFieldType::FRAME_LEN:
                case FilterFieldType::FRAME_TIME:
                case FilterFieldType::DATA_LEN:
                    return evaluateGeneral(packet);
                
                // Protocol checks
                case FilterFieldType::PROTOCOL_TCP:
                case FilterFieldType::PROTOCOL_UDP:
                case FilterFieldType::PROTOCOL_ICMP:
                case FilterFieldType::PROTOCOL_ICMPV6:
                case FilterFieldType::PROTOCOL_ARP:
                case FilterFieldType::PROTOCOL_IP:
                case FilterFieldType::PROTOCOL_IPV6:
                    return evaluateProtocol(packet);
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateEthernet(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_ethernet)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::ETH_SRC:
                {
                    std::string src_mac = Common::PacketParser::macToString(packet.ethernet.src_mac);
                    return compareMAC(src_mac, value_, op_);
                }
                
                case FilterFieldType::ETH_DST:
                {
                    std::string dst_mac = Common::PacketParser::macToString(packet.ethernet.dst_mac);
                    return compareMAC(dst_mac, value_, op_);
                }
                
                case FilterFieldType::ETH_ADDR:
                {
                    std::string src_mac = Common::PacketParser::macToString(packet.ethernet.src_mac);
                    std::string dst_mac = Common::PacketParser::macToString(packet.ethernet.dst_mac);
                    return compareMAC(src_mac, value_, op_) || compareMAC(dst_mac, value_, op_);
                }
                
                case FilterFieldType::ETH_TYPE:
                {
                    uint16_t eth_type = ntohs(packet.ethernet.ether_type);
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(eth_type, expected, op_);
                }
                
                case FilterFieldType::VLAN_ID:
                {
                    if (!packet.ethernet.has_vlan)
                        return false;
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ethernet.vlan_id, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateIPv4(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_ipv4)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::IP_SRC:
                {
                    std::string src_ip = Common::PacketParser::ipv4ToString(packet.ipv4.src_ip);
                    return compareIP(src_ip, value_, op_);
                }
                
                case FilterFieldType::IP_DST:
                {
                    std::string dst_ip = Common::PacketParser::ipv4ToString(packet.ipv4.dst_ip);
                    return compareIP(dst_ip, value_, op_);
                }
                
                case FilterFieldType::IP_ADDR:
                {
                    std::string src_ip = Common::PacketParser::ipv4ToString(packet.ipv4.src_ip);
                    std::string dst_ip = Common::PacketParser::ipv4ToString(packet.ipv4.dst_ip);
                    return compareIP(src_ip, value_, op_) || compareIP(dst_ip, value_, op_);
                }
                
                case FilterFieldType::IP_PROTO:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv4.protocol, expected, op_);
                }
                
                case FilterFieldType::IP_ttl:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv4.ttl, expected, op_);
                }
                
                case FilterFieldType::IP_LEN:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv4.total_length, expected, op_);
                }
                
                case FilterFieldType::IP_ID:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv4.identification, expected, op_);
                }
                
                case FilterFieldType::IP_FLAGS:
                {
                    uint8_t flags = 0;
                    if (packet.ipv4.flags == 0x02) flags |= 0x02;
                    if (packet.ipv4.flags == 0x01) flags |= 0x01;
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(flags, expected, op_);
                }
                
                case FilterFieldType::IP_FRAG_OFFSET:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv4.fragment_offset, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateIPv6(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_ipv6)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::IPV6_SRC:
                {
                    std::string src_ip = Common::PacketParser::ipv6ToString(packet.ipv6.src_ip);
                    return compareIP(src_ip, value_, op_);
                }
                
                case FilterFieldType::IPV6_DST:
                {
                    std::string dst_ip = Common::PacketParser::ipv6ToString(packet.ipv6.dst_ip);
                    return compareIP(dst_ip, value_, op_);
                }
                
                case FilterFieldType::IPV6_ADDR:
                {
                    std::string src_ip = Common::PacketParser::ipv6ToString(packet.ipv6.src_ip);
                    std::string dst_ip = Common::PacketParser::ipv6ToString(packet.ipv6.dst_ip);
                    return compareIP(src_ip, value_, op_) || compareIP(dst_ip, value_, op_);
                }
                
                case FilterFieldType::IPV6_NXTHDR:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv6.next_header, expected, op_);
                }
                
                case FilterFieldType::IPV6_HLIM:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv6.hop_limit, expected, op_);
                }
                
                case FilterFieldType::IPV6_FLOW:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.ipv6.flow_label, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateTCP(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_tcp)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::TCP_SRCPORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.src_port, expected, op_);
                }
                
                case FilterFieldType::TCP_DSTPORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.dst_port, expected, op_);
                }
                
                case FilterFieldType::TCP_PORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.src_port, expected, op_) ||
                           compareNumeric(packet.tcp.dst_port, expected, op_);
                }
                
                case FilterFieldType::TCP_SEQ:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.seq_number, expected, op_);
                }
                
                case FilterFieldType::TCP_ACK:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.ack_number, expected, op_);
                }
                
                case FilterFieldType::TCP_FLAGS:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.flags, expected, op_);
                }
                
                case FilterFieldType::TCP_FLAGS_SYN:
                    return packet.tcp.flag_syn;
                
                case FilterFieldType::TCP_FLAGS_ACK:
                    return packet.tcp.flag_ack;
                
                case FilterFieldType::TCP_FLAGS_FIN:
                    return packet.tcp.flag_fin;
                
                case FilterFieldType::TCP_FLAGS_RST:
                    return packet.tcp.flag_rst;
                
                case FilterFieldType::TCP_FLAGS_PSH:
                    return packet.tcp.flag_psh;
                
                case FilterFieldType::TCP_FLAGS_URG:
                    return packet.tcp.flag_urg;
                
                case FilterFieldType::TCP_WINDOW:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.tcp.window_size, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateUDP(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_udp)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::UDP_SRCPORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.udp.src_port, expected, op_);
                }
                
                case FilterFieldType::UDP_DSTPORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.udp.dst_port, expected, op_);
                }
                
                case FilterFieldType::UDP_PORT:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.udp.src_port, expected, op_) ||
                           compareNumeric(packet.udp.dst_port, expected, op_);
                }
                
                case FilterFieldType::UDP_LENGTH:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.udp.length, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateICMP(const Common::ParsedPacket& packet) const
        {
            if (packet.has_icmp)
            {
                switch (field_)
                {
                    case FilterFieldType::ICMP_TYPE:
                    {
                        uint64_t expected = std::stoull(value_, nullptr, 0);
                        return compareNumeric(packet.icmp.type, expected, op_);
                    }
                    
                    case FilterFieldType::ICMP_CODE:
                    {
                        uint64_t expected = std::stoull(value_, nullptr, 0);
                        return compareNumeric(packet.icmp.code, expected, op_);
                    }
                    
                    default:
                        return false;
                }
            }
            else if (packet.has_icmpv6)
            {
                switch (field_)
                {
                    case FilterFieldType::ICMPV6_TYPE:
                    {
                        uint64_t expected = std::stoull(value_, nullptr, 0);
                        return compareNumeric(packet.icmpv6.type, expected, op_);
                    }
                    
                    case FilterFieldType::ICMPV6_CODE:
                    {
                        uint64_t expected = std::stoull(value_, nullptr, 0);
                        return compareNumeric(packet.icmpv6.code, expected, op_);
                    }
                    
                    default:
                        return false;
                }
            }
            
            return false;
        }

        bool FieldExpression::evaluateARP(const Common::ParsedPacket& packet) const
        {
            if (!packet.has_arp)
                return false;
            
            switch (field_)
            {
                case FilterFieldType::ARP_OPCODE:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.arp.opcode, expected, op_);
                }
                
                case FilterFieldType::ARP_SRC_HW:
                {
                    std::string src_mac = Common::PacketParser::macToString(packet.arp.sender_mac);
                    return compareMAC(src_mac, value_, op_);
                }
                
                case FilterFieldType::ARP_DST_HW:
                {
                    std::string dst_mac = Common::PacketParser::macToString(packet.arp.target_mac);
                    return compareMAC(dst_mac, value_, op_);
                }
                
                case FilterFieldType::ARP_SRC_PROTO:
                {
                    std::string src_ip = Common::PacketParser::ipv4ToString(packet.arp.sender_ip);
                    return compareIP(src_ip, value_, op_);
                }
                
                case FilterFieldType::ARP_DST_PROTO:
                {
                    std::string dst_ip = Common::PacketParser::ipv4ToString(packet.arp.target_ip);
                    return compareIP(dst_ip, value_, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateGeneral(const Common::ParsedPacket& packet) const
        {
            switch (field_)
            {
                case FilterFieldType::FRAME_LEN:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.packet_size, expected, op_);
                }
                
                case FilterFieldType::DATA_LEN:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.payload_length, expected, op_);
                }
                
                case FilterFieldType::FRAME_TIME:
                {
                    uint64_t expected = std::stoull(value_, nullptr, 0);
                    return compareNumeric(packet.timestamp, expected, op_);
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::evaluateProtocol(const Common::ParsedPacket& packet) const
        {
            switch (field_)
            {
                case FilterFieldType::PROTOCOL_TCP:
                    return packet.has_tcp;
                
                case FilterFieldType::PROTOCOL_UDP:
                    return packet.has_udp;
                
                case FilterFieldType::PROTOCOL_ICMP:
                    return packet.has_icmp;
                
                case FilterFieldType::PROTOCOL_ICMPV6:
                    return packet.has_icmpv6;
                
                case FilterFieldType::PROTOCOL_ARP:
                    return packet.has_arp;
                
                case FilterFieldType::PROTOCOL_IP:
                    return packet.has_ipv4;
                
                case FilterFieldType::PROTOCOL_IPV6:
                    return packet.has_ipv6;
                
                default:
                    return false;
            }
        }

        bool FieldExpression::compareValue(const std::string& actual, const std::string& expected, FilterOperator op) const
        {
            switch (op)
            {
                case FilterOperator::EQUALS:
                    return actual == expected;
                
                case FilterOperator::NOT_EQUALS:
                    return actual != expected;
                
                case FilterOperator::CONTAINS:
                    return actual.find(expected) != std::string::npos;
                
                case FilterOperator::MATCHES:
                {
                    try
                    {
                        std::regex pattern(expected);
                        return std::regex_match(actual, pattern);
                    }
                    catch (const std::regex_error&)
                    {
                        return false;
                    }
                }
                
                default:
                    return false;
            }
        }

        bool FieldExpression::compareNumeric(uint64_t actual, uint64_t expected, FilterOperator op) const
        {
            switch (op)
            {
                case FilterOperator::EQUALS:
                    return actual == expected;
                
                case FilterOperator::NOT_EQUALS:
                    return actual != expected;
                
                case FilterOperator::GREATER_THAN:
                    return actual > expected;
                
                case FilterOperator::LESS_THAN:
                    return actual < expected;
                
                case FilterOperator::GREATER_OR_EQUAL:
                    return actual >= expected;
                
                case FilterOperator::LESS_OR_EQUAL:
                    return actual <= expected;
                
                case FilterOperator::BITWISE_AND:
                    return (actual & expected) != 0;
                
                default:
                    return false;
            }
        }

        bool FieldExpression::compareIP(const std::string& actual, const std::string& expected, FilterOperator op) const
        {
            // Support CIDR notation
            if (expected.find('/') != std::string::npos)
            {
                // Parse CIDR
                size_t slash_pos = expected.find('/');
                std::string network_str = expected.substr(0, slash_pos);
                int prefix_len = std::stoi(expected.substr(slash_pos + 1));
                
                struct in_addr actual_addr, network_addr;
                inet_pton(AF_INET, actual.c_str(), &actual_addr);
                inet_pton(AF_INET, network_str.c_str(), &network_addr);
                
                uint32_t mask = (prefix_len == 0) ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));
                
                bool in_network = (actual_addr.s_addr & mask) == (network_addr.s_addr & mask);
                
                return (op == FilterOperator::EQUALS) ? in_network : !in_network;
            }
            
            return compareValue(actual, expected, op);
        }

        bool FieldExpression::compareMAC(const std::string& actual, const std::string& expected, FilterOperator op) const
        {
            std::string actual_lower = Common::Utils::toLowerCase(actual);
            std::string expected_lower = Common::Utils::toLowerCase(expected);
            
            return compareValue(actual_lower, expected_lower, op);
        }

        std::string FieldExpression::toString() const
        {
            std::stringstream ss;
            ss << "Field(" << static_cast<int>(field_) << ") ";
            
            switch (op_)
            {
                case FilterOperator::EQUALS: ss << "=="; break;
                case FilterOperator::NOT_EQUALS: ss << "!="; break;
                case FilterOperator::GREATER_THAN: ss << ">"; break;
                case FilterOperator::LESS_THAN: ss << "<"; break;
                case FilterOperator::GREATER_OR_EQUAL: ss << ">="; break;
                case FilterOperator::LESS_OR_EQUAL: ss << "<="; break;
                case FilterOperator::CONTAINS: ss << "contains"; break;
                case FilterOperator::MATCHES: ss << "matches"; break;
                case FilterOperator::BITWISE_AND: ss << "&"; break;
                default: ss << "?"; break;
            }
            
            ss << " " << value_;
            return ss.str();
        }

        // ==================== BinaryExpression Implementation ====================
        
        BinaryExpression::BinaryExpression(std::unique_ptr<FilterExpression> left,
                                         FilterOperator op,
                                         std::unique_ptr<FilterExpression> right)
            : left_(std::move(left)), op_(op), right_(std::move(right))
        {
        }

        bool BinaryExpression::evaluate(const Common::ParsedPacket& packet) const
        {
            switch (op_)
            {
                case FilterOperator::AND:
                    return left_->evaluate(packet) && right_->evaluate(packet);
                
                case FilterOperator::OR:
                    return left_->evaluate(packet) || right_->evaluate(packet);
                
                default:
                    return false;
            }
        }

        std::string BinaryExpression::toString() const
        {
            std::stringstream ss;
            ss << "(" << left_->toString();
            
            switch (op_)
            {
                case FilterOperator::AND: ss << " && "; break;
                case FilterOperator::OR: ss << " || "; break;
                default: ss << " ? "; break;
            }
            
            ss << right_->toString() << ")";
            return ss.str();
        }

        // ==================== UnaryExpression Implementation ====================
        
        UnaryExpression::UnaryExpression(FilterOperator op, std::unique_ptr<FilterExpression> expr)
            : op_(op), expr_(std::move(expr))
        {
        }

        bool UnaryExpression::evaluate(const Common::ParsedPacket& packet) const
        {
            if (op_ == FilterOperator::NOT)
            {
                return !expr_->evaluate(packet);
            }
            return false;
        }

        std::string UnaryExpression::toString() const
        {
            return "!(" + expr_->toString() + ")";
        }

        // ==================== FilterParser Implementation ====================
        
        FilterParser::FilterParser()
            : pos_(0)
        {
        }

        std::unique_ptr<FilterExpression> FilterParser::parse(const std::string& filter_string)
        {
            input_ = filter_string;
            pos_ = 0;
            last_error_.clear();
            
            try
            {
                return parseExpression();
            }
            catch (const std::exception& e)
            {
                last_error_ = e.what();
                return nullptr;
            }
        }

        bool FilterParser::validate(const std::string& filter_string, std::string& error_msg)
        {
            auto expr = parse(filter_string);
            if (!expr)
            {
                error_msg = last_error_;
                return false;
            }
            return true;
        }

        std::unique_ptr<FilterExpression> FilterParser::parseExpression()
        {
            return parseOrExpression();
        }

        std::unique_ptr<FilterExpression> FilterParser::parseOrExpression()
        {
            auto left = parseAndExpression();
            
            skipWhitespace();
            
            while (true)
            {
                size_t saved_pos = pos_;
                
                if (match('|') && match('|'))
                {
                    skipWhitespace();
                    auto right = parseAndExpression();
                    left = std::make_unique<BinaryExpression>(
                        std::move(left),
                        FilterOperator::OR,
                        std::move(right)
                    );
                }
                else if (input_.substr(pos_, 2) == "or" || input_.substr(pos_, 2) == "OR")
                {
                    pos_ += 2;
                    if (pos_ < input_.length() && !std::isspace(input_[pos_]) && std::isalnum(input_[pos_]))
                    {
                        pos_ = saved_pos;
                        break;
                    }
                    skipWhitespace();
                    auto right = parseAndExpression();
                    left = std::make_unique<BinaryExpression>(
                        std::move(left),
                        FilterOperator::OR,
                        std::move(right)
                    );
                }
                else
                {
                    pos_ = saved_pos;
                    break;
                }
            }
            
            return left;
        }

        std::unique_ptr<FilterExpression> FilterParser::parseAndExpression()
        {
            auto left = parseNotExpression();
            
            skipWhitespace();
            
            while (true)
            {
                size_t saved_pos = pos_;
                
                if (match('&') && match('&'))
                {
                    skipWhitespace();
                    auto right = parseNotExpression();
                    left = std::make_unique<BinaryExpression>(
                        std::move(left),
                        FilterOperator::AND,
                        std::move(right)
                    );
                }
                else if (input_.substr(pos_, 3) == "and" || input_.substr(pos_, 3) == "AND")
                {
                    pos_ += 3;
                    if (pos_ < input_.length() && !std::isspace(input_[pos_]) && std::isalnum(input_[pos_]))
                    {
                        pos_ = saved_pos;
                        break;
                    }
                    skipWhitespace();
                    auto right = parseNotExpression();
                    left = std::make_unique<BinaryExpression>(
                        std::move(left),
                        FilterOperator::AND,
                        std::move(right)
                    );
                }
                else
                {
                    pos_ = saved_pos;
                    break;
                }
            }
            
            return left;
        }

        std::unique_ptr<FilterExpression> FilterParser::parseNotExpression()
        {
            skipWhitespace();
            
            if (match('!'))
            {
                skipWhitespace();
                auto expr = parsePrimaryExpression();
                return std::make_unique<UnaryExpression>(FilterOperator::NOT, std::move(expr));
            }
            else if (input_.substr(pos_, 3) == "not" || input_.substr(pos_, 3) == "NOT")
            {
                pos_ += 3;
                skipWhitespace();
                auto expr = parsePrimaryExpression();
                return std::make_unique<UnaryExpression>(FilterOperator::NOT, std::move(expr));
            }
            
            return parsePrimaryExpression();
        }

        std::unique_ptr<FilterExpression> FilterParser::parsePrimaryExpression()
        {
            skipWhitespace();
            
            if (match('('))
            {
                auto expr = parseExpression();
                skipWhitespace();
                if (!match(')'))
                {
                    error("Expected ')'");
                }
                return expr;
            }
            
            return parseComparison();
        }

        std::unique_ptr<FilterExpression> FilterParser::parseComparison()
        {
            skipWhitespace();
            
            // Parse field name
            std::string field_str;
            while (pos_ < input_.length() && 
                   (std::isalnum(input_[pos_]) || input_[pos_] == '.' || input_[pos_] == '_'))
            {
                field_str += input_[pos_++];
            }
            
            if (field_str.empty())
            {
                error("Expected field name");
            }
            
            FilterFieldType field = parseFieldType(field_str);
            
            // Check if it's a boolean field (no operator needed)
            if (field == FilterFieldType::PROTOCOL_TCP ||
                field == FilterFieldType::PROTOCOL_UDP ||
                field == FilterFieldType::PROTOCOL_ICMP ||
                field == FilterFieldType::PROTOCOL_ICMPV6 ||
                field == FilterFieldType::PROTOCOL_ARP ||
                field == FilterFieldType::PROTOCOL_IP ||
                field == FilterFieldType::PROTOCOL_IPV6 ||
                field == FilterFieldType::TCP_FLAGS_SYN ||
                field == FilterFieldType::TCP_FLAGS_ACK ||
                field == FilterFieldType::TCP_FLAGS_FIN ||
                field == FilterFieldType::TCP_FLAGS_RST ||
                field == FilterFieldType::TCP_FLAGS_PSH ||
                field == FilterFieldType::TCP_FLAGS_URG)
            {
                return std::make_unique<FieldExpression>(field, FilterOperator::EQUALS, "1");
            }
            
            skipWhitespace();
            
            // Parse operator
            std::string op_str;
            size_t op_start = pos_;
            
            if (match('=') && match('='))
            {
                op_str = "==";
            }
            else if (match('!') && match('='))
            {
                op_str = "!=";
            }
            else if (match('>') && match('='))
            {
                op_str = ">=";
            }
            else if (match('<') && match('='))
            {
                op_str = "<=";
            }
            else if (match('>'))
            {
                op_str = ">";
            }
            else if (match('<'))
            {
                op_str = "<";
            }
            else if (match('&'))
            {
                op_str = "&";
            }
            else
            {
                // Try keyword operators
                while (pos_ < input_.length() && std::isalpha(input_[pos_]))
                {
                    op_str += input_[pos_++];
                }
            }
            
            if (op_str.empty())
            {
                error("Expected operator");
            }
            
            FilterOperator op = parseOperator(op_str);
            
            skipWhitespace();
            
            // Parse value
            std::string value = parseValue();
            
            return std::make_unique<FieldExpression>(field, op, value);
        }

        FilterFieldType FilterParser::parseFieldType(const std::string& field)
        {
            std::string lower_field = Common::Utils::toLowerCase(field);
            
            // Ethernet
            if (lower_field == "eth.src") return FilterFieldType::ETH_SRC;
            if (lower_field == "eth.dst") return FilterFieldType::ETH_DST;
            if (lower_field == "eth.addr") return FilterFieldType::ETH_ADDR;
            if (lower_field == "eth.type") return FilterFieldType::ETH_TYPE;
            if (lower_field == "vlan.id") return FilterFieldType::VLAN_ID;
            
            // IPv4
            if (lower_field == "ip.src") return FilterFieldType::IP_SRC;
            if (lower_field == "ip.dst") return FilterFieldType::IP_DST;
            if (lower_field == "ip.addr") return FilterFieldType::IP_ADDR;
            if (lower_field == "ip.proto") return FilterFieldType::IP_PROTO;
            if (lower_field == "ip.version") return FilterFieldType::IP_VERSION;
            if (lower_field == "ip.ttl") return FilterFieldType::IP_ttl;
            if (lower_field == "ip.len") return FilterFieldType::IP_LEN;
            if (lower_field == "ip.id") return FilterFieldType::IP_ID;
            if (lower_field == "ip.flags") return FilterFieldType::IP_FLAGS;
            if (lower_field == "ip.frag_offset") return FilterFieldType::IP_FRAG_OFFSET;
            
            // IPv6
            if (lower_field == "ipv6.src") return FilterFieldType::IPV6_SRC;
            if (lower_field == "ipv6.dst") return FilterFieldType::IPV6_DST;
            if (lower_field == "ipv6.addr") return FilterFieldType::IPV6_ADDR;
            if (lower_field == "ipv6.nxt") return FilterFieldType::IPV6_NXTHDR;
            if (lower_field == "ipv6.hlim") return FilterFieldType::IPV6_HLIM;
            if (lower_field == "ipv6.flow") return FilterFieldType::IPV6_FLOW;
            
            // TCP
            if (lower_field == "tcp.srcport") return FilterFieldType::TCP_SRCPORT;
            if (lower_field == "tcp.dstport") return FilterFieldType::TCP_DSTPORT;
            if (lower_field == "tcp.port") return FilterFieldType::TCP_PORT;
            if (lower_field == "tcp.seq") return FilterFieldType::TCP_SEQ;
            if (lower_field == "tcp.ack") return FilterFieldType::TCP_ACK;
            if (lower_field == "tcp.flags") return FilterFieldType::TCP_FLAGS;
            if (lower_field == "tcp.flags.syn") return FilterFieldType::TCP_FLAGS_SYN;
            if (lower_field == "tcp.flags.ack") return FilterFieldType::TCP_FLAGS_ACK;
            if (lower_field == "tcp.flags.fin") return FilterFieldType::TCP_FLAGS_FIN;
            if (lower_field == "tcp.flags.rst") return FilterFieldType::TCP_FLAGS_RST;
            if (lower_field == "tcp.flags.psh") return FilterFieldType::TCP_FLAGS_PSH;
            if (lower_field == "tcp.flags.urg") return FilterFieldType::TCP_FLAGS_URG;
            if (lower_field == "tcp.window_size") return FilterFieldType::TCP_WINDOW;
            if (lower_field == "tcp.len") return FilterFieldType::TCP_LEN;
            
            // UDP
            if (lower_field == "udp.srcport") return FilterFieldType::UDP_SRCPORT;
            if (lower_field == "udp.dstport") return FilterFieldType::UDP_DSTPORT;
            if (lower_field == "udp.port") return FilterFieldType::UDP_PORT;
            if (lower_field == "udp.length") return FilterFieldType::UDP_LENGTH;
            
            // ICMP
            if (lower_field == "icmp.type") return FilterFieldType::ICMP_TYPE;
            if (lower_field == "icmp.code") return FilterFieldType::ICMP_CODE;
            if (lower_field == "icmpv6.type") return FilterFieldType::ICMPV6_TYPE;
            if (lower_field == "icmpv6.code") return FilterFieldType::ICMPV6_CODE;
            
            // ARP
            if (lower_field == "arp.opcode") return FilterFieldType::ARP_OPCODE;
            if (lower_field == "arp.src.hw_mac") return FilterFieldType::ARP_SRC_HW;
            if (lower_field == "arp.dst.hw_mac") return FilterFieldType::ARP_DST_HW;
            if (lower_field == "arp.src.proto_ipv4") return FilterFieldType::ARP_SRC_PROTO;
            if (lower_field == "arp.dst.proto_ipv4") return FilterFieldType::ARP_DST_PROTO;
            
            // General
            if (lower_field == "frame.len") return FilterFieldType::FRAME_LEN;
            if (lower_field == "frame.time") return FilterFieldType::FRAME_TIME;
            if (lower_field == "data.len") return FilterFieldType::DATA_LEN;
            
            // Protocol checks
            if (lower_field == "tcp") return FilterFieldType::PROTOCOL_TCP;
            if (lower_field == "udp") return FilterFieldType::PROTOCOL_UDP;
            if (lower_field == "icmp") return FilterFieldType::PROTOCOL_ICMP;
            if (lower_field == "icmpv6") return FilterFieldType::PROTOCOL_ICMPV6;
            if (lower_field == "arp") return FilterFieldType::PROTOCOL_ARP;
            if (lower_field == "ip") return FilterFieldType::PROTOCOL_IP;
            if (lower_field == "ipv6") return FilterFieldType::PROTOCOL_IPV6;
            
            error("Unknown field: " + field);
            return FilterFieldType::UNKNOWN;
        }

        FilterOperator FilterParser::parseOperator(const std::string& op)
        {
            std::string lower_op = Common::Utils::toLowerCase(op);
            
            if (op == "==") return FilterOperator::EQUALS;
            if (op == "!=") return FilterOperator::NOT_EQUALS;
            if (op == ">") return FilterOperator::GREATER_THAN;
            if (op == "<") return FilterOperator::LESS_THAN;
            if (op == ">=") return FilterOperator::GREATER_OR_EQUAL;
            if (op == "<=") return FilterOperator::LESS_OR_EQUAL;
            if (op == "&") return FilterOperator::BITWISE_AND;
            if (lower_op == "contains") return FilterOperator::CONTAINS;
            if (lower_op == "matches") return FilterOperator::MATCHES;
            if (lower_op == "in") return FilterOperator::IN;
            
            error("Unknown operator: " + op);
            return FilterOperator::EQUALS;
        }

        std::string FilterParser::parseValue()
        {
            skipWhitespace();
            
            std::string value;
            
            // Quoted string
            if (match('"'))
            {
                while (pos_ < input_.length() && input_[pos_] != '"')
                {
                    if (input_[pos_] == '\\' && pos_ + 1 < input_.length())
                    {
                        pos_++;
                    }
                    value += input_[pos_++];
                }
                
                if (!match('"'))
                {
                    error("Expected closing quote");
                }
            }
            // Unquoted value
            else
            {
                while (pos_ < input_.length() && 
                       !std::isspace(input_[pos_]) &&
                       input_[pos_] != ')' &&
                       input_[pos_] != '&' &&
                       input_[pos_] != '|')
                {
                    value += input_[pos_++];
                }
            }
            
            return value;
        }

        void FilterParser::skipWhitespace()
        {
            while (pos_ < input_.length() && std::isspace(input_[pos_]))
            {
                pos_++;
            }
        }

        char FilterParser::peek()
        {
            if (pos_ < input_.length())
            {
                return input_[pos_];
            }
            return '\0';
        }

        char FilterParser::consume()
        {
            if (pos_ < input_.length())
            {
                return input_[pos_++];
            }
            return '\0';
        }

        bool FilterParser::match(char c)
        {
            if (pos_ < input_.length() && input_[pos_] == c)
            {
                pos_++;
                return true;
            }
            return false;
        }

        void FilterParser::error(const std::string& msg)
        {
            std::stringstream ss;
            ss << "Parse error at position " << pos_ << ": " << msg;
            throw std::runtime_error(ss.str());
        }

        // ==================== DisplayFilter Implementation ====================
        
        DisplayFilter::DisplayFilter()
            : match_count_(0), total_count_(0)
        {
        }

        DisplayFilter::~DisplayFilter()
        {
        }

        bool DisplayFilter::setFilter(const std::string& filter_string)
        {
            if (filter_string.empty())
            {
                clearFilter();
                return true;
            }
            
            expression_ = parser_.parse(filter_string);
            
            if (!expression_)
            {
                spdlog::error("Failed to parse filter: {}", parser_.getLastError());
                return false;
            }
            
            filter_string_ = filter_string;
            spdlog::info("Display filter set: {}", filter_string_);
            
            return true;
        }

        void DisplayFilter::clearFilter()
        {
            expression_.reset();
            filter_string_.clear();
            spdlog::info("Display filter cleared");
        }

        bool DisplayFilter::matches(const Common::ParsedPacket& packet) const
        {
            total_count_.fetch_add(1);
            
            if (!expression_)
            {
                match_count_.fetch_add(1);
                return true; // No filter = match all
            }
            
            bool result = expression_->evaluate(packet);
            
            if (result)
            {
                match_count_.fetch_add(1);
            }
            
            return result;
        }

        bool DisplayFilter::validate(const std::string& filter_string, std::string& error_msg)
        {
            return parser_.validate(filter_string, error_msg);
        }

        void DisplayFilter::resetStats()
        {
            match_count_.store(0);
            total_count_.store(0);
        }

        // ==================== CaptureFilter Implementation ====================
        
        CaptureFilter::CaptureFilter()
        {
        }

        CaptureFilter::~CaptureFilter()
        {
        }

        bool CaptureFilter::setFilter(const std::string& bpf_filter)
        {
            filter_string_ = bpf_filter;
            spdlog::info("Capture filter (BPF) set: {}", bpf_filter);
            return true;
        }

        std::string CaptureFilter::convertToBPF(const std::string& display_filter)
        {
            // Convert common Wireshark display filters to BPF
            std::string bpf;
            std::string lower = Common::Utils::toLowerCase(display_filter);
            
            // Simple conversions
            if (lower == "tcp") return "tcp";
            if (lower == "udp") return "udp";
            if (lower == "icmp") return "icmp";
            if (lower == "arp") return "arp";
            if (lower == "ip") return "ip";
            if (lower == "ipv6" || lower == "ip6") return "ip6";
            
            // Port filters
            std::regex port_regex(R"(tcp\.port\s*==\s*(\d+))");
            std::smatch match;
            if (std::regex_search(display_filter, match, port_regex))
            {
                return "tcp port " + match[1].str();
            }
            
            port_regex = std::regex(R"(udp\.port\s*==\s*(\d+))");
            if (std::regex_search(display_filter, match, port_regex))
            {
                return "udp port " + match[1].str();
            }
            
            // IP filters
            std::regex ip_regex(R"(ip\.src\s*==\s*([0-9.]+))");
            if (std::regex_search(display_filter, match, ip_regex))
            {
                return "src host " + match[1].str();
            }
            
            ip_regex = std::regex(R"(ip\.dst\s*==\s*([0-9.]+))");
            if (std::regex_search(display_filter, match, ip_regex))
            {
                return "dst host " + match[1].str();
            }
            
            ip_regex = std::regex(R"(ip\.addr\s*==\s*([0-9.]+))");
            if (std::regex_search(display_filter, match, ip_regex))
            {
                return "host " + match[1].str();
            }
            
            // TCP flags
            if (lower.find("tcp.flags.syn") != std::string::npos)
            {
                return "tcp[tcpflags] & tcp-syn != 0";
            }
            
            // If no conversion available, return empty
            spdlog::warn("Cannot convert display filter to BPF: {}", display_filter);
            return "";
        }

        bool CaptureFilter::validate(const std::string& bpf_filter, std::string& error_msg)
        {
            // Basic BPF syntax validation
            // In real implementation, use pcap_compile to validate
            if (bpf_filter.empty())
            {
                return true;
            }
            
            // TODO: Use pcap_compile for proper validation
            return true;
        }

        // ==================== FilterPresets Implementation ====================
        
        std::vector<FilterPresets::Preset> FilterPresets::presets_;
        bool FilterPresets::initialized_ = false;

        void FilterPresets::initializePresets()
        {
            if (initialized_) return;
            
            // Web Traffic
            presets_.push_back({"HTTP", "tcp.port == 80", "HTTP traffic", "Web"});
            presets_.push_back({"HTTPS", "tcp.port == 443", "HTTPS traffic", "Web"});
            presets_.push_back({"HTTP/HTTPS", "tcp.port == 80 || tcp.port == 443", "All web traffic", "Web"});
            presets_.push_back({"Web Browsing", "tcp.port == 80 || tcp.port == 443 || tcp.port == 8080", "Common web ports", "Web"});
            
            // DNS
            presets_.push_back({"DNS", "udp.port == 53 || tcp.port == 53", "DNS queries and responses", "DNS"});
            presets_.push_back({"DNS Queries", "udp.port == 53 && udp.srcport != 53", "DNS queries only", "DNS"});
            presets_.push_back({"DNS Responses", "udp.port == 53 && udp.srcport == 53", "DNS responses only", "DNS"});
            
            // Email
            presets_.push_back({"SMTP", "tcp.port == 25 || tcp.port == 587", "SMTP traffic", "Email"});
            presets_.push_back({"POP3", "tcp.port == 110 || tcp.port == 995", "POP3 traffic", "Email"});
            presets_.push_back({"IMAP", "tcp.port == 143 || tcp.port == 993", "IMAP traffic", "Email"});
            presets_.push_back({"All Email", "tcp.port == 25 || tcp.port == 110 || tcp.port == 143 || tcp.port == 587 || tcp.port == 993 || tcp.port == 995", "All email protocols", "Email"});
            
            // File Transfer
            presets_.push_back({"FTP", "tcp.port == 20 || tcp.port == 21", "FTP traffic", "File Transfer"});
            presets_.push_back({"SFTP", "tcp.port == 22", "SFTP/SSH traffic", "File Transfer"});
            presets_.push_back({"SMB", "tcp.port == 445 || tcp.port == 139", "SMB/CIFS traffic", "File Transfer"});
            
            // Remote Access
            presets_.push_back({"SSH", "tcp.port == 22", "SSH traffic", "Remote Access"});
            presets_.push_back({"Telnet", "tcp.port == 23", "Telnet traffic", "Remote Access"});
            presets_.push_back({"RDP", "tcp.port == 3389", "Remote Desktop Protocol", "Remote Access"});
            presets_.push_back({"VNC", "tcp.port >= 5900 && tcp.port <= 5910", "VNC traffic", "Remote Access"});
            
            // Database
            presets_.push_back({"MySQL", "tcp.port == 3306", "MySQL traffic", "Database"});
            presets_.push_back({"PostgreSQL", "tcp.port == 5432", "PostgreSQL traffic", "Database"});
            presets_.push_back({"MongoDB", "tcp.port == 27017", "MongoDB traffic", "Database"});
            presets_.push_back({"Redis", "tcp.port == 6379", "Redis traffic", "Database"});
            
            // Network Management
            presets_.push_back({"SNMP", "udp.port == 161 || udp.port == 162", "SNMP traffic", "Management"});
            presets_.push_back({"NTP", "udp.port == 123", "NTP traffic", "Management"});
            presets_.push_back({"DHCP", "udp.port == 67 || udp.port == 68", "DHCP traffic", "Management"});
            
            // ICMP
            presets_.push_back({"ICMP", "icmp", "All ICMP traffic", "ICMP"});
            presets_.push_back({"Ping", "icmp.type == 8 || icmp.type == 0", "ICMP Echo Request/Reply", "ICMP"});
            presets_.push_back({"ICMP Errors", "icmp.type == 3 || icmp.type == 11", "ICMP errors", "ICMP"});
            
            // TCP Analysis
            presets_.push_back({"TCP SYN", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "TCP SYN packets", "TCP Analysis"});
            presets_.push_back({"TCP SYN-ACK", "tcp.flags.syn == 1 && tcp.flags.ack == 1", "TCP SYN-ACK packets", "TCP Analysis"});
            presets_.push_back({"TCP RST", "tcp.flags.rst == 1", "TCP Reset packets", "TCP Analysis"});
            presets_.push_back({"TCP FIN", "tcp.flags.fin == 1", "TCP FIN packets", "TCP Analysis"});
            presets_.push_back({"TCP Retransmission", "tcp.flags.syn == 0 && tcp.seq > 0", "Possible retransmissions", "TCP Analysis"});
            
            // Security
            presets_.push_back({"SYN Flood", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "Potential SYN flood", "Security"});
            presets_.push_back({"Port Scan", "tcp.flags.syn == 1 || tcp.flags.rst == 1", "Potential port scan", "Security"});
            presets_.push_back({"Large Packets", "frame.len > 1500", "Packets larger than MTU", "Security"});
            presets_.push_back({"Fragmented IP", "ip.flags.mf == 1 || ip.frag_offset > 0", "Fragmented IP packets", "Security"});
            presets_.push_back({"Private IP Source", "ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16", "Private IP sources", "Security"});
            
            // Broadcast/Multicast
            presets_.push_back({"Broadcast", "eth.dst == ff:ff:ff:ff:ff:ff", "Ethernet broadcast", "Network"});
            presets_.push_back({"Multicast", "eth.dst[0] & 1", "Multicast packets", "Network"});
            presets_.push_back({"ARP", "arp", "ARP traffic", "Network"});
            
            // VLAN
            presets_.push_back({"VLAN Tagged", "vlan.id", "VLAN tagged packets", "VLAN"});
            
            // IPv6
            presets_.push_back({"IPv6", "ipv6", "IPv6 traffic", "IPv6"});
            presets_.push_back({"ICMPv6", "icmpv6", "ICMPv6 traffic", "IPv6"});
            
            // Specific Applications
            presets_.push_back({"BitTorrent", "tcp.port >= 6881 && tcp.port <= 6889", "BitTorrent traffic", "P2P"});
            presets_.push_back({"Skype", "tcp.port == 23399 || udp.port == 23399", "Skype traffic", "VoIP"});
            presets_.push_back({"SIP", "tcp.port == 5060 || udp.port == 5060", "SIP VoIP", "VoIP"});
            
            initialized_ = true;
        }

        std::vector<FilterPresets::Preset> FilterPresets::getPresets()
        {
            initializePresets();
            return presets_;
        }

        std::vector<FilterPresets::Preset> FilterPresets::getPresetsByCategory(const std::string& category)
        {
            initializePresets();
            
            std::vector<Preset> result;
            for (const auto& preset : presets_)
            {
                if (preset.category == category)
                {
                    result.push_back(preset);
                }
            }
            return result;
        }

        std::string FilterPresets::getPresetFilter(const std::string& name)
        {
            initializePresets();
            
            for (const auto& preset : presets_)
            {
                if (preset.name == name)
                {
                    return preset.filter;
                }
            }
            return "";
        }

        // ==================== FilterSuggestions Implementation ====================
        
        std::vector<std::string> FilterSuggestions::getFieldSuggestions(const std::string& partial)
        {
            std::vector<std::string> suggestions;
            std::string lower_partial = Common::Utils::toLowerCase(partial);
            
            std::vector<std::string> all_fields = {
                // Ethernet
                "eth.src", "eth.dst", "eth.addr", "eth.type",
                "vlan.id",
                
                // IP
                "ip", "ip.src", "ip.dst", "ip.addr", "ip.proto", "ip.version",
                "ip.ttl", "ip.len", "ip.id", "ip.flags", "ip.frag_offset",
                
                // IPv6
                "ipv6", "ipv6.src", "ipv6.dst", "ipv6.addr", "ipv6.nxt",
                "ipv6.hlim", "ipv6.flow",
                
                // TCP
                "tcp", "tcp.srcport", "tcp.dstport", "tcp.port",
                "tcp.seq", "tcp.ack", "tcp.flags", "tcp.flags.syn",
                "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.rst",
                "tcp.flags.psh", "tcp.flags.urg", "tcp.window_size", "tcp.len",
                
                // UDP
                "udp", "udp.srcport", "udp.dstport", "udp.port", "udp.length",
                
                // ICMP
                "icmp", "icmp.type", "icmp.code",
                "icmpv6", "icmpv6.type", "icmpv6.code",
                
                // ARP
                "arp", "arp.opcode", "arp.src.hw_mac", "arp.dst.hw_mac",
                "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
                
                // General
                "frame.len", "frame.time", "data.len"
            };
            
            for (const auto& field : all_fields)
            {
                if (Common::Utils::startsWith(field, lower_partial))
                {
                    suggestions.push_back(field);
                }
            }
            
            return suggestions;
        }

        std::vector<std::string> FilterSuggestions::getOperatorSuggestions(FilterFieldType field)
        {
            std::vector<std::string> operators;
            
            switch (field)
            {
                case FilterFieldType::ETH_SRC:
                case FilterFieldType::ETH_DST:
                case FilterFieldType::ETH_ADDR:
                case FilterFieldType::IP_SRC:
                case FilterFieldType::IP_DST:
                case FilterFieldType::IP_ADDR:
                case FilterFieldType::IPV6_SRC:
                case FilterFieldType::IPV6_DST:
                case FilterFieldType::IPV6_ADDR:
                    operators = {"==", "!="};
                    break;
                
                case FilterFieldType::TCP_SRCPORT:
                case FilterFieldType::TCP_DSTPORT:
                case FilterFieldType::TCP_PORT:
                case FilterFieldType::UDP_SRCPORT:
                case FilterFieldType::UDP_DSTPORT:
                case FilterFieldType::UDP_PORT:
                case FilterFieldType::IP_ttl:
                case FilterFieldType::IP_LEN:
                case FilterFieldType::FRAME_LEN:
                case FilterFieldType::DATA_LEN:
                    operators = {"==", "!=", ">", "<", ">=", "<="};
                    break;
                
                case FilterFieldType::TCP_FLAGS:
                case FilterFieldType::IP_FLAGS:
                    operators = {"==", "!=", "&"};
                    break;
                
                default:
                    operators = {"==", "!="};
                    break;
            }
            
            return operators;
        }

        std::vector<std::string> FilterSuggestions::getValueSuggestions(FilterFieldType field, 
                                                                        const std::string& partial)
        {
            std::vector<std::string> suggestions;
            
            switch (field)
            {
                case FilterFieldType::TCP_PORT:
                case FilterFieldType::TCP_SRCPORT:
                case FilterFieldType::TCP_DSTPORT:
                case FilterFieldType::UDP_PORT:
                case FilterFieldType::UDP_SRCPORT:
                case FilterFieldType::UDP_DSTPORT:
                {
                    // Common ports
                    std::vector<std::pair<std::string, std::string>> common_ports = {
                        {"20", "FTP Data"},
                        {"21", "FTP Control"},
                        {"22", "SSH"},
                        {"23", "Telnet"},
                        {"25", "SMTP"},
                        {"53", "DNS"},
                        {"80", "HTTP"},
                        {"110", "POP3"},
                        {"143", "IMAP"},
                        {"443", "HTTPS"},
                        {"3306", "MySQL"},
                        {"3389", "RDP"},
                        {"5432", "PostgreSQL"},
                        {"8080", "HTTP Alternate"}
                    };
                    
                    for (const auto& [port, desc] : common_ports)
                    {
                        if (partial.empty() || Common::Utils::startsWith(port, partial))
                        {
                            suggestions.push_back(port + " (" + desc + ")");
                        }
                    }
                    break;
                }
                
                case FilterFieldType::IP_PROTO:
                {
                    suggestions = {"1 (ICMP)", "6 (TCP)", "17 (UDP)", "41 (IPv6)", "58 (ICMPv6)"};
                    break;
                }
                
                case FilterFieldType::ICMP_TYPE:
                {
                    suggestions = {"0 (Echo Reply)", "3 (Dest Unreachable)", "8 (Echo Request)", "11 (Time Exceeded)"};
                    break;
                }
                
                case FilterFieldType::ARP_OPCODE:
                {
                    suggestions = {"1 (Request)", "2 (Reply)"};
                    break;
                }
                
                default:
                    break;
            }
            
            return suggestions;
        }

        std::string FilterSuggestions::autoComplete(const std::string& partial)
        {
            auto suggestions = getFieldSuggestions(partial);
            
            if (suggestions.empty())
            {
                return partial;
            }
            
            return suggestions[0];
        }

        // ==================== FilterHistory Implementation ====================
        
        FilterHistory::FilterHistory(size_t max_size)
            : max_size_(max_size)
        {
        }

        void FilterHistory::add(const std::string& filter)
        {
            if (filter.empty())
                return;
            
            // Remove duplicates
            auto it = std::find(history_.begin(), history_.end(), filter);
            if (it != history_.end())
            {
                history_.erase(it);
            }
            
            // Add to front
            history_.insert(history_.begin(), filter);
            
            // Limit size
            if (history_.size() > max_size_)
            {
                history_.resize(max_size_);
            }
        }

        std::vector<std::string> FilterHistory::getHistory() const
        {
            return history_;
        }

        std::vector<std::string> FilterHistory::search(const std::string& query) const
        {
            std::vector<std::string> results;
            std::string lower_query = Common::Utils::toLowerCase(query);
            
            for (const auto& filter : history_)
            {
                if (Common::Utils::toLowerCase(filter).find(lower_query) != std::string::npos)
                {
                    results.push_back(filter);
                }
            }
            
            return results;
        }

        void FilterHistory::clear()
        {
            history_.clear();
        }

        void FilterHistory::saveToFile(const std::string& filepath)
        {
            std::ofstream file(filepath);
            if (!file.is_open())
            {
                spdlog::error("Failed to save filter history to: {}", filepath);
                return;
            }
            
            for (const auto& filter : history_)
            {
                file << filter << "\n";
            }
            
            spdlog::info("Filter history saved to: {}", filepath);
        }

        void FilterHistory::loadFromFile(const std::string& filepath)
        {
            std::ifstream file(filepath);
            if (!file.is_open())
            {
                spdlog::warn("Failed to load filter history from: {}", filepath);
                return;
            }
            
            history_.clear();
            
            std::string line;
            while (std::getline(file, line))
            {
                if (!line.empty())
                {
                    history_.push_back(line);
                }
            }
            
            spdlog::info("Filter history loaded from: {} ({} entries)", filepath, history_.size());
        }

        // ==================== AdvancedFilterManager Implementation ====================
        
        AdvancedFilterManager::AdvancedFilterManager()
            : total_packets_(0), matched_packets_(0)
        {
            spdlog::info("AdvancedFilterManager created");
        }

        AdvancedFilterManager::~AdvancedFilterManager()
        {
            spdlog::info("AdvancedFilterManager destroyed");
        }

        bool AdvancedFilterManager::setDisplayFilter(const std::string& filter)
        {
            bool result = display_filter_.setFilter(filter);
            if (result)
            {
                history_.add(filter);
            }
            return result;
        }

        void AdvancedFilterManager::clearDisplayFilter()
        {
            display_filter_.clearFilter();
        }

        bool AdvancedFilterManager::matchesDisplayFilter(const Common::ParsedPacket& packet) const
        {
            return display_filter_.matches(packet);
        }

        bool AdvancedFilterManager::setCaptureFilter(const std::string& filter)
        {
            return capture_filter_.setFilter(filter);
        }

        std::string AdvancedFilterManager::getCaptureFilterBPF() const
        {
            return capture_filter_.getFilterString();
        }

        bool AdvancedFilterManager::matches(const Common::ParsedPacket& packet) const
        {
            total_packets_.fetch_add(1);
            
            bool result = display_filter_.matches(packet);
            
            if (result)
            {
                matched_packets_.fetch_add(1);
            }
            
            return result;
        }

        void AdvancedFilterManager::saveFilter(const std::string& name, const std::string& filter)
        {
            saved_filters_[name] = filter;
            spdlog::info("Filter saved: {} = {}", name, filter);
        }

        std::string AdvancedFilterManager::loadFilter(const std::string& name)
        {
            auto it = saved_filters_.find(name);
            if (it != saved_filters_.end())
            {
                return it->second;
            }
            return "";
        }

        std::vector<std::string> AdvancedFilterManager::getSavedFilters() const
        {
            std::vector<std::string> names;
            for (const auto& [name, filter] : saved_filters_)
            {
                names.push_back(name);
            }
            return names;
        }

        std::vector<FilterPresets::Preset> AdvancedFilterManager::getPresets() const
        {
            return FilterPresets::getPresets();
        }

        bool AdvancedFilterManager::applyPreset(const std::string& preset_name)
        {
            std::string filter = FilterPresets::getPresetFilter(preset_name);
            if (filter.empty())
            {
                spdlog::error("Preset not found: {}", preset_name);
                return false;
            }
            
            return setDisplayFilter(filter);
        }

        AdvancedFilterManager::FilterStats AdvancedFilterManager::getStats() const
        {
            FilterStats stats;
            stats.total_packets = total_packets_.load();
            stats.matched_packets = matched_packets_.load();
            stats.filtered_packets = stats.total_packets - stats.matched_packets;
            stats.match_rate = (stats.total_packets > 0) ? 
                (static_cast<double>(stats.matched_packets) / stats.total_packets * 100.0) : 0.0;
            stats.current_filter = display_filter_.getFilterString();
            return stats;
        }

        void AdvancedFilterManager::resetStats()
        {
            total_packets_.store(0);
            matched_packets_.store(0);
            display_filter_.resetStats();
        }

        bool AdvancedFilterManager::validateFilter(const std::string& filter, std::string& error_msg)
        {
            return display_filter_.validate(filter, error_msg);
        }

        // ==================== FilterBuilder Implementation ====================
        
        FilterBuilder::FilterBuilder()
        {
        }

        FilterBuilder& FilterBuilder::ethSrc(const std::string& mac)
        {
            parts_.push_back("eth.src == " + mac);
            return *this;
        }

        FilterBuilder& FilterBuilder::ethDst(const std::string& mac)
        {
            parts_.push_back("eth.dst == " + mac);
            return *this;
        }

        FilterBuilder& FilterBuilder::ethAddr(const std::string& mac)
        {
            parts_.push_back("eth.addr == " + mac);
            return *this;
        }

        FilterBuilder& FilterBuilder::ethType(uint16_t type)
        {
            parts_.push_back("eth.type == 0x" + std::to_string(type));
            return *this;
        }

        FilterBuilder& FilterBuilder::vlan(uint16_t vlan_id)
        {
            parts_.push_back("vlan.id == " + std::to_string(vlan_id));
            return *this;
        }

        FilterBuilder& FilterBuilder::ipSrc(const std::string& ip)
        {
            parts_.push_back("ip.src == " + ip);
            return *this;
        }

        FilterBuilder& FilterBuilder::ipDst(const std::string& ip)
        {
            parts_.push_back("ip.dst == " + ip);
            return *this;
        }

        FilterBuilder& FilterBuilder::ipAddr(const std::string& ip)
        {
            parts_.push_back("ip.addr == " + ip);
            return *this;
        }

        FilterBuilder& FilterBuilder::ipProto(uint8_t proto)
        {
            parts_.push_back("ip.proto == " + std::to_string(proto));
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpSrcPort(uint16_t port)
        {
            parts_.push_back("tcp.srcport == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpDstPort(uint16_t port)
        {
            parts_.push_back("tcp.dstport == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpPort(uint16_t port)
        {
            parts_.push_back("tcp.port == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpFlags(const std::string& flags)
        {
            parts_.push_back("tcp.flags == " + flags);
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpSyn()
        {
            parts_.push_back("tcp.flags.syn");
            return *this;
        }

        FilterBuilder& FilterBuilder::tcpAck()
        {
            parts_.push_back("tcp.flags.ack");
            return *this;
        }

        FilterBuilder& FilterBuilder::udpSrcPort(uint16_t port)
        {
            parts_.push_back("udp.srcport == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::udpDstPort(uint16_t port)
        {
            parts_.push_back("udp.dstport == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::udpPort(uint16_t port)
        {
            parts_.push_back("udp.port == " + std::to_string(port));
            return *this;
        }

        FilterBuilder& FilterBuilder::icmpType(uint8_t type)
        {
            parts_.push_back("icmp.type == " + std::to_string(type));
            return *this;
        }

        FilterBuilder& FilterBuilder::icmpCode(uint8_t code)
        {
            parts_.push_back("icmp.code == " + std::to_string(code));
            return *this;
        }

        FilterBuilder& FilterBuilder::and_()
        {
            parts_.push_back("&&");
            return *this;
        }

        FilterBuilder& FilterBuilder::or_()
        {
            parts_.push_back("||");
            return *this;
        }

        FilterBuilder& FilterBuilder::not_()
        {
            parts_.push_back("!");
            return *this;
        }

        FilterBuilder& FilterBuilder::beginGroup()
        {
            parts_.push_back("(");
            return *this;
        }

        FilterBuilder& FilterBuilder::endGroup()
        {
            parts_.push_back(")");
            return *this;
        }

        std::string FilterBuilder::build() const
        {
            std::stringstream ss;
            for (size_t i = 0; i < parts_.size(); ++i)
            {
                if (i > 0 && parts_[i] != "&&" && parts_[i] != "||" && 
                    parts_[i] != "!" && parts_[i] != "(" && parts_[i] != ")" &&
                    parts_[i-1] != "&&" && parts_[i-1] != "||" && 
                    parts_[i-1] != "!" && parts_[i-1] != "(")
                {
                    ss << " ";
                }
                ss << parts_[i];
                if (parts_[i] == "&&" || parts_[i] == "||" || parts_[i] == "!")
                {
                    ss << " ";
                }
            }
            return ss.str();
        }

    } // namespace Layer1
} // namespace NetworkSecurity
