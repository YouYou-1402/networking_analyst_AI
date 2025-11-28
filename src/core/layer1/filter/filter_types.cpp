// src/core/layer1/filter/filter_types.cpp

#include "filter_types.hpp"
#include <algorithm>
#include <unordered_map>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // ==================== Field Type Mapping ====================
            
            static const std::unordered_map<std::string, FieldType> FIELD_TYPE_MAP = {
                // Frame
                {"frame.number", FieldType::FRAME_NUMBER},
                {"frame.len", FieldType::FRAME_LEN},
                {"frame.cap_len", FieldType::FRAME_CAP_LEN},
                {"frame.time_relative", FieldType::FRAME_TIME_RELATIVE},
                {"frame.time_delta", FieldType::FRAME_TIME_DELTA},
                {"frame.protocols", FieldType::FRAME_PROTOCOLS},
                
                // Ethernet
                {"eth.dst", FieldType::ETH_DST},
                {"eth.src", FieldType::ETH_SRC},
                {"eth.addr", FieldType::ETH_ADDR},
                {"eth.type", FieldType::ETH_TYPE},
                {"eth.dst.oui", FieldType::ETH_DST_OUI},
                {"eth.src.oui", FieldType::ETH_SRC_OUI},
                
                // VLAN
                {"vlan", FieldType::VLAN},
                {"vlan.id", FieldType::VLAN_ID},
                {"vlan.priority", FieldType::VLAN_PRIORITY},
                
                // ARP
                {"arp", FieldType::ARP},
                {"arp.opcode", FieldType::ARP_OPCODE},
                {"arp.src.hw_mac", FieldType::ARP_SRC_HW},
                {"arp.dst.hw_mac", FieldType::ARP_DST_HW},
                {"arp.src.proto_ipv4", FieldType::ARP_SRC_PROTO},
                {"arp.dst.proto_ipv4", FieldType::ARP_DST_PROTO},
                {"arp.isgratuitous", FieldType::ARP_GRATUITOUS},
                {"arp.isprobe", FieldType::ARP_PROBE},
                {"arp.duplicate-address-detected", FieldType::ARP_DUPLICATE},
                
                // IPv4
                {"ip", FieldType::IP},
                {"ip.version", FieldType::IP_VERSION},
                {"ip.hdr_len", FieldType::IP_HDR_LEN},
                {"ip.dscp", FieldType::IP_DSCP},
                {"ip.ecn", FieldType::IP_ECN},
                {"ip.len", FieldType::IP_LEN},
                {"ip.id", FieldType::IP_ID},
                {"ip.flags", FieldType::IP_FLAGS},
                {"ip.flags.df", FieldType::IP_FLAGS_DF},
                {"ip.flags.mf", FieldType::IP_FLAGS_MF},
                {"ip.frag_offset", FieldType::IP_FRAG_OFFSET},
                {"ip.ttl", FieldType::IP_ttl},
                {"ip.proto", FieldType::IP_PROTO},
                {"ip.checksum", FieldType::IP_checksum},
                {"ip.src", FieldType::IP_SRC},
                {"ip.dst", FieldType::IP_DST},
                {"ip.addr", FieldType::IP_ADDR},
                {"ip.src_host", FieldType::IP_SRC_HOST},
                {"ip.dst_host", FieldType::IP_DST_HOST},
                
                // IPv6
                {"ipv6", FieldType::IPV6},
                {"ipv6.version", FieldType::IPV6_version},
                {"ipv6.tclass", FieldType::IPV6_tclass},
                {"ipv6.flow", FieldType::IPV6_FLOW},
                {"ipv6.plen", FieldType::IPV6_PLEN},
                {"ipv6.nxt", FieldType::IPV6_NXTHDR},
                {"ipv6.hlim", FieldType::IPV6_HLIM},
                {"ipv6.src", FieldType::IPV6_SRC},
                {"ipv6.dst", FieldType::IPV6_DST},
                {"ipv6.addr", FieldType::IPV6_ADDR},
                
                // TCP
                {"tcp", FieldType::TCP},
                {"tcp.srcport", FieldType::TCP_SRCPORT},
                {"tcp.dstport", FieldType::TCP_DSTPORT},
                {"tcp.port", FieldType::TCP_PORT},
                {"tcp.stream", FieldType::TCP_STREAM},
                {"tcp.seq", FieldType::TCP_SEQ},
                {"tcp.ack", FieldType::TCP_ACK},
                {"tcp.nxtseq", FieldType::TCP_NXTSEQ},
                {"tcp.len", FieldType::TCP_LEN},
                {"tcp.hdr_len", FieldType::TCP_HDR_LEN},
                {"tcp.flags", FieldType::TCP_FLAGS},
                {"tcp.flags.fin", FieldType::TCP_FLAGS_FIN},
                {"tcp.flags.syn", FieldType::TCP_FLAGS_SYN},
                {"tcp.flags.reset", FieldType::TCP_FLAGS_RST},
                {"tcp.flags.push", FieldType::TCP_FLAGS_PSH},
                {"tcp.flags.ack", FieldType::TCP_FLAGS_ACK},
                {"tcp.flags.urg", FieldType::TCP_FLAGS_URG},
                {"tcp.flags.ecn", FieldType::TCP_FLAGS_ECE},
                {"tcp.flags.cwr", FieldType::TCP_FLAGS_CWR},
                {"tcp.window_size_value", FieldType::TCP_WINDOW},
                {"tcp.window_size", FieldType::TCP_WINDOW_SIZE},
                {"tcp.checksum", FieldType::TCP_CHECKSUM},
                {"tcp.urgent_pointer", FieldType::TCP_URGENT},
                {"tcp.options", FieldType::TCP_OPTIONS},
                {"tcp.options.mss_val", FieldType::TCP_OPTION_MSS},
                {"tcp.options.wscale.shift", FieldType::TCP_OPTION_WSCALE},
                {"tcp.options.sack", FieldType::TCP_OPTION_SACK},
                {"tcp.options.timestamp", FieldType::TCP_OPTION_TIMESTAMP},
                
                // TCP Analysis
                {"tcp.analysis", FieldType::TCP_ANALYSIS},
                {"tcp.analysis.retransmission", FieldType::TCP_ANALYSIS_RETRANS},
                {"tcp.analysis.fast_retransmission", FieldType::TCP_ANALYSIS_FAST_RETRANS},
                {"tcp.analysis.duplicate_ack", FieldType::TCP_ANALYSIS_DUP_ACK},
                {"tcp.analysis.zero_window", FieldType::TCP_ANALYSIS_ZERO_WINDOW},
                {"tcp.analysis.keep_alive", FieldType::TCP_ANALYSIS_KEEP_ALIVE},
                {"tcp.analysis.out_of_order", FieldType::TCP_ANALYSIS_OUT_OF_ORDER},
                {"tcp.analysis.lost_segment", FieldType::TCP_ANALYSIS_LOST_SEGMENT},
                {"tcp.analysis.bytes_in_flight", FieldType::TCP_ANALYSIS_BYTES_IN_FLIGHT},
                
                // UDP
                {"udp", FieldType::UDP},
                {"udp.srcport", FieldType::UDP_SRCPORT},
                {"udp.dstport", FieldType::UDP_DSTPORT},
                {"udp.port", FieldType::UDP_PORT},
                {"udp.length", FieldType::UDP_LENGTH},
                {"udp.checksum", FieldType::UDP_CHECKSUM},
                {"udp.stream", FieldType::UDP_STREAM},
                
                // ICMP
                {"icmp", FieldType::ICMP},
                {"icmp.type", FieldType::ICMP_TYPE},
                {"icmp.code", FieldType::ICMP_CODE},
                {"icmp.checksum", FieldType::ICMP_CHECKSUM},
                {"icmp.ident", FieldType::ICMP_IDENT},
                {"icmp.seq", FieldType::ICMP_SEQ},
                {"icmp.resptime", FieldType::ICMP_RESPTIME},
                
                // ICMPv6
                {"icmpv6", FieldType::ICMPV6},
                {"icmpv6.type", FieldType::ICMPV6_TYPE},
                {"icmpv6.code", FieldType::ICMPV6_CODE},
                {"icmpv6.checksum", FieldType::ICMPV6_CHECKSUM},
                
                // Application protocols
                {"http", FieldType::HTTP},
                {"https", FieldType::HTTPS},
                {"dns", FieldType::DNS},
                {"ssh", FieldType::SSH},
                {"ftp", FieldType::FTP},
                {"smtp", FieldType::SMTP},
                {"pop", FieldType::POP},
                {"imap", FieldType::IMAP},
                {"telnet", FieldType::TELNET},
                {"dhcp", FieldType::DHCP},
                {"ntp", FieldType::NTP},
                {"snmp", FieldType::SNMP}
            };

            static const std::unordered_map<FieldType, std::string> FIELD_TYPE_REVERSE_MAP = {
                {FieldType::FRAME_NUMBER, "frame.number"},
                {FieldType::FRAME_LEN, "frame.len"},
                {FieldType::ETH_SRC, "eth.src"},
                {FieldType::ETH_DST, "eth.dst"},
                {FieldType::IP_SRC, "ip.src"},
                {FieldType::IP_DST, "ip.dst"},
                {FieldType::TCP_SRCPORT, "tcp.srcport"},
                {FieldType::TCP_DSTPORT, "tcp.dstport"},
                {FieldType::UDP_SRCPORT, "udp.srcport"},
                {FieldType::UDP_DSTPORT, "udp.dstport"},
                // Add more as needed
            };

            // ==================== Operator Mapping ====================
            
            static const std::unordered_map<std::string, Operator> OPERATOR_MAP = {
                {"==", Operator::EQUALS},
                {"eq", Operator::EQUALS},
                {"!=", Operator::NOT_EQUALS},
                {"ne", Operator::NOT_EQUALS},
                {">", Operator::GREATER_THAN},
                {"gt", Operator::GREATER_THAN},
                {"<", Operator::LESS_THAN},
                {"lt", Operator::LESS_THAN},
                {">=", Operator::GREATER_OR_EQUAL},
                {"ge", Operator::GREATER_OR_EQUAL},
                {"<=", Operator::LESS_OR_EQUAL},
                {"le", Operator::LESS_OR_EQUAL},
                {"contains", Operator::CONTAINS},
                {"matches", Operator::MATCHES},
                {"in", Operator::IN},
                {"&", Operator::BITWISE_AND}
            };

            static const std::unordered_map<Operator, std::string> OPERATOR_REVERSE_MAP = {
                {Operator::EQUALS, "=="},
                {Operator::NOT_EQUALS, "!="},
                {Operator::GREATER_THAN, ">"},
                {Operator::LESS_THAN, "<"},
                {Operator::GREATER_OR_EQUAL, ">="},
                {Operator::LESS_OR_EQUAL, "<="},
                {Operator::CONTAINS, "contains"},
                {Operator::MATCHES, "matches"},
                {Operator::IN, "in"},
                {Operator::BITWISE_AND, "&"}
            };

            // ==================== Logical Operator Mapping ====================
            
            static const std::unordered_map<std::string, LogicalOp> LOGICAL_OP_MAP = {
                {"and", LogicalOp::AND},
                {"&&", LogicalOp::AND},
                {"or", LogicalOp::OR},
                {"||", LogicalOp::OR},
                {"not", LogicalOp::NOT},
                {"!", LogicalOp::NOT}
            };

            static const std::unordered_map<LogicalOp, std::string> LOGICAL_OP_REVERSE_MAP = {
                {LogicalOp::AND, "and"},
                {LogicalOp::OR, "or"},
                {LogicalOp::NOT, "not"}
            };

            // ==================== Implementation ====================

            std::string fieldTypeToString(FieldType type)
            {
                auto it = FIELD_TYPE_REVERSE_MAP.find(type);
                if (it != FIELD_TYPE_REVERSE_MAP.end())
                {
                    return it->second;
                }
                return "unknown";
            }

            std::string operatorToString(Operator op)
            {
                auto it = OPERATOR_REVERSE_MAP.find(op);
                if (it != OPERATOR_REVERSE_MAP.end())
                {
                    return it->second;
                }
                return "unknown";
            }

            std::string logicalOpToString(LogicalOp op)
            {
                auto it = LOGICAL_OP_REVERSE_MAP.find(op);
                if (it != LOGICAL_OP_REVERSE_MAP.end())
                {
                    return it->second;
                }
                return "unknown";
            }

            FieldType parseFieldType(const std::string& str)
            {
                std::string lower = str;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                
                auto it = FIELD_TYPE_MAP.find(lower);
                if (it != FIELD_TYPE_MAP.end())
                {
                    return it->second;
                }
                return FieldType::UNKNOWN;
            }

            Operator parseOperator(const std::string& str)
            {
                std::string lower = str;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                
                auto it = OPERATOR_MAP.find(lower);
                if (it != OPERATOR_MAP.end())
                {
                    return it->second;
                }
                
                // Try exact match for symbols
                auto it2 = OPERATOR_MAP.find(str);
                if (it2 != OPERATOR_MAP.end())
                {
                    return it2->second;
                }
                
                return Operator::EQUALS; // Default
            }

            LogicalOp parseLogicalOp(const std::string& str)
            {
                std::string lower = str;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                
                auto it = LOGICAL_OP_MAP.find(lower);
                if (it != LOGICAL_OP_MAP.end())
                {
                    return it->second;
                }
                
                // Try exact match for symbols
                auto it2 = LOGICAL_OP_MAP.find(str);
                if (it2 != LOGICAL_OP_MAP.end())
                {
                    return it2->second;
                }
                
                return LogicalOp::AND; // Default
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity
