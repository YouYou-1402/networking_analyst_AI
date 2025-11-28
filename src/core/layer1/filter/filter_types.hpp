// src/core/layer1/filter/filter_types.hpp

#ifndef NETWORK_SECURITY_FILTER_TYPES_HPP
#define NETWORK_SECURITY_FILTER_TYPES_HPP

#include <string>
#include <cstdint>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Filter field types (Wireshark-compatible)
             */
            enum class FieldType
            {
                // ==================== Frame ====================
                FRAME_NUMBER,           // frame.number
                FRAME_LEN,             // frame.len
                FRAME_CAP_LEN,         // frame.cap_len
                FRAME_TIME_RELATIVE,   // frame.time_relative
                FRAME_TIME_DELTA,      // frame.time_delta
                FRAME_PROTOCOLS,       // frame.protocols
                
                // ==================== Ethernet ====================
                ETH_DST,               // eth.dst
                ETH_SRC,               // eth.src
                ETH_ADDR,              // eth.addr
                ETH_TYPE,              // eth.type
                ETH_DST_OUI,           // eth.dst.oui
                ETH_SRC_OUI,           // eth.src.oui
                
                // VLAN
                VLAN,                  // vlan
                VLAN_ID,               // vlan.id
                VLAN_PRIORITY,         // vlan.priority
                
                // ==================== ARP ====================
                ARP,                   // arp
                ARP_OPCODE,            // arp.opcode
                ARP_SRC_HW,            // arp.src.hw_mac
                ARP_DST_HW,            // arp.dst.hw_mac
                ARP_SRC_PROTO,         // arp.src.proto_ipv4
                ARP_DST_PROTO,         // arp.dst.proto_ipv4
                ARP_GRATUITOUS,        // arp.isgratuitous
                ARP_PROBE,             // arp.isprobe
                ARP_DUPLICATE,         // arp.duplicate-address-detected
                
                // ==================== IPv4 ====================
                IP,                    // ip
                IP_VERSION,            // ip.version
                IP_HDR_LEN,            // ip.hdr_len
                IP_DSCP,               // ip.dscp
                IP_ECN,                // ip.ecn
                IP_LEN,                // ip.len
                IP_ID,                 // ip.id
                IP_FLAGS,              // ip.flags
                IP_FLAGS_DF,           // ip.flags.df
                IP_FLAGS_MF,           // ip.flags.mf
                IP_FRAG_OFFSET,        // ip.frag_offset
                IP_ttl,                // ip.ttl
                IP_PROTO,              // ip.proto
                IP_checksum,           // ip.checksum
                IP_SRC,                // ip.src
                IP_DST,                // ip.dst
                IP_ADDR,               // ip.addr
                IP_SRC_HOST,           // ip.src_host
                IP_DST_HOST,           // ip.dst_host
                
                // ==================== IPv6 ====================
                IPV6,                  // ipv6
                IPV6_version,          // ipv6.version
                IPV6_tclass,           // ipv6.tclass
                IPV6_FLOW,             // ipv6.flow
                IPV6_PLEN,             // ipv6.plen
                IPV6_NXTHDR,           // ipv6.nxt
                IPV6_HLIM,             // ipv6.hlim
                IPV6_SRC,              // ipv6.src
                IPV6_DST,              // ipv6.dst
                IPV6_ADDR,             // ipv6.addr
                
                // ==================== TCP ====================
                TCP,                   // tcp
                TCP_SRCPORT,           // tcp.srcport
                TCP_DSTPORT,           // tcp.dstport
                TCP_PORT,              // tcp.port
                TCP_STREAM,            // tcp.stream
                TCP_SEQ,               // tcp.seq
                TCP_ACK,               // tcp.ack
                TCP_NXTSEQ,            // tcp.nxtseq
                TCP_LEN,               // tcp.len
                TCP_HDR_LEN,           // tcp.hdr_len
                TCP_FLAGS,             // tcp.flags
                TCP_FLAGS_FIN,         // tcp.flags.fin
                TCP_FLAGS_SYN,         // tcp.flags.syn
                TCP_FLAGS_RST,         // tcp.flags.reset
                TCP_FLAGS_PSH,         // tcp.flags.push
                TCP_FLAGS_ACK,         // tcp.flags.ack
                TCP_FLAGS_URG,         // tcp.flags.urg
                TCP_FLAGS_ECE,         // tcp.flags.ecn
                TCP_FLAGS_CWR,         // tcp.flags.cwr
                TCP_WINDOW,            // tcp.window_size_value
                TCP_WINDOW_SIZE,       // tcp.window_size
                TCP_CHECKSUM,          // tcp.checksum
                TCP_URGENT,            // tcp.urgent_pointer
                TCP_OPTIONS,           // tcp.options
                TCP_OPTION_MSS,        // tcp.options.mss_val
                TCP_OPTION_WSCALE,     // tcp.options.wscale.shift
                TCP_OPTION_SACK,       // tcp.options.sack
                TCP_OPTION_TIMESTAMP,  // tcp.options.timestamp
                
                // TCP Analysis
                TCP_ANALYSIS,          // tcp.analysis
                TCP_ANALYSIS_RETRANS,  // tcp.analysis.retransmission
                TCP_ANALYSIS_FAST_RETRANS, // tcp.analysis.fast_retransmission
                TCP_ANALYSIS_DUP_ACK,  // tcp.analysis.duplicate_ack
                TCP_ANALYSIS_ZERO_WINDOW, // tcp.analysis.zero_window
                TCP_ANALYSIS_KEEP_ALIVE, // tcp.analysis.keep_alive
                TCP_ANALYSIS_OUT_OF_ORDER, // tcp.analysis.out_of_order
                TCP_ANALYSIS_LOST_SEGMENT, // tcp.analysis.lost_segment
                TCP_ANALYSIS_BYTES_IN_FLIGHT, // tcp.analysis.bytes_in_flight
                
                // ==================== UDP ====================
                UDP,                   // udp
                UDP_SRCPORT,           // udp.srcport
                UDP_DSTPORT,           // udp.dstport
                UDP_PORT,              // udp.port
                UDP_LENGTH,            // udp.length
                UDP_CHECKSUM,          // udp.checksum
                UDP_STREAM,            // udp.stream
                
                // ==================== ICMP ====================
                ICMP,                  // icmp
                ICMP_TYPE,             // icmp.type
                ICMP_CODE,             // icmp.code
                ICMP_CHECKSUM,         // icmp.checksum
                ICMP_IDENT,            // icmp.ident
                ICMP_SEQ,              // icmp.seq
                ICMP_RESPTIME,         // icmp.resptime
                
                // ==================== ICMPv6 ====================
                ICMPV6,                // icmpv6
                ICMPV6_TYPE,           // icmpv6.type
                ICMPV6_CODE,           // icmpv6.code
                ICMPV6_CHECKSUM,       // icmpv6.checksum
                
                // ==================== Application ====================
                HTTP,                  // http
                HTTPS,                 // https
                DNS,                   // dns
                SSH,                   // ssh
                FTP,                   // ftp
                SMTP,                  // smtp
                POP,                   // pop
                IMAP,                  // imap
                TELNET,                // telnet
                DHCP,                  // dhcp
                NTP,                   // ntp
                SNMP,                  // snmp
                
                UNKNOWN
            };

            /**
             * @brief Comparison operators
             */
            enum class Operator
            {
                EQUALS,              // == or eq
                NOT_EQUALS,          // != or ne
                GREATER_THAN,        // > or gt
                LESS_THAN,           // < or lt
                GREATER_OR_EQUAL,    // >= or ge
                LESS_OR_EQUAL,       // <= or le
                CONTAINS,            // contains
                MATCHES,             // matches (regex)
                IN,                  // in
                BITWISE_AND          // &
            };

            /**
             * @brief Logical operators
             */
            enum class LogicalOp
            {
                AND,                 // and or &&
                OR,                  // or or ||
                NOT                  // not or !
            };

            /**
             * @brief Value types for comparison
             */
            enum class ValueType
            {
                NONE,
                NUMBER,
                STRING,
                IP_ADDRESS,
                MAC_ADDRESS,
                BOOLEAN
            };

            /**
             * @brief Field value union
             */
            union FieldValue
            {
                uint64_t number;
                bool boolean;
                uint32_t ipv4;
                uint8_t ipv6[16];
                uint8_t mac[6];
                
                FieldValue() : number(0) {}
            };

            /**
             * @brief Convert field type to string
             */
            std::string fieldTypeToString(FieldType type);

            /**
             * @brief Convert operator to string
             */
            std::string operatorToString(Operator op);

            /**
             * @brief Convert logical operator to string
             */
            std::string logicalOpToString(LogicalOp op);

            /**
             * @brief Parse field type from string
             */
            FieldType parseFieldType(const std::string& str);

            /**
             * @brief Parse operator from string
             */
            Operator parseOperator(const std::string& str);

            /**
             * @brief Parse logical operator from string
             */
            LogicalOp parseLogicalOp(const std::string& str);

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_FILTER_TYPES_HPP
