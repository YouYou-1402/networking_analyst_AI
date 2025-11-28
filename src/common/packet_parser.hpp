// src/common/packet_parser.hpp
#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <map>
#include <set>
#include <optional>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

namespace NetworkSecurity
{
    namespace Common
    {
        /**
         * @brief Enum cho các loại protocol
         */
        enum class ProtocolType
        {
            UNKNOWN = 0,
            ETHERNET,
            ARP,
            IPV4,
            IPV6,
            TCP,
            UDP,
            ICMP,
            ICMPV6,
            IGMP,
            ESP,
            AH,
            SCTP,
            GRE
        };

        // ==================== Frame Metadata (Wireshark frame.*) ====================
        /**
         * @brief Frame-level metadata như Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/f/frame.html
         */
        struct FrameMetadata
        {
            uint32_t frame_number;              // frame.number
            double frame_time_relative;         // frame.time_relative (seconds)
            double frame_time_delta;            // frame.time_delta (seconds)
            std::string frame_protocols;        // frame.protocols (e.g., "eth:ethertype:ip:tcp")
            
            uint32_t frame_len;                 // frame.len
            uint32_t frame_cap_len;             // frame.cap_len
            bool frame_marked;                  // frame.marked
            bool frame_ignored;                 // frame.ignored
            
            std::string frame_comment;          // frame.comment
            uint32_t frame_interface_id;        // frame.interface_id
            std::string frame_interface_name;   // frame.interface_name

            FrameMetadata()
            {
                frame_number = 0;
                frame_time_relative = 0.0;
                frame_time_delta = 0.0;
                frame_len = 0;
                frame_cap_len = 0;
                frame_marked = false;
                frame_ignored = false;
                frame_interface_id = 0;
            }
        };

        // ==================== Ethernet Header (Wireshark eth.*) ====================
        /**
         * @brief Cấu trúc cho Ethernet header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/e/eth.html
         */
        struct EthernetHeader
        {
            uint8_t dst_mac[6];                 // eth.dst
            uint8_t src_mac[6];                 // eth.src
            uint16_t ether_type;                // eth.type
            
            // MAC address analysis
            bool dst_lg_bit;                    // eth.dst.lg (Local/Global)
            bool dst_ig_bit;                    // eth.dst.ig (Individual/Group)
            bool src_lg_bit;                    // eth.src.lg
            bool src_ig_bit;                    // eth.src.ig
            uint32_t dst_oui;                   // eth.dst.oui (first 3 bytes)
            uint32_t src_oui;                   // eth.src.oui
            
            // VLAN 802.1Q
            bool has_vlan;                      // vlan
            uint16_t vlan_id;                   // vlan.id
            uint8_t vlan_priority;              // vlan.priority
            bool vlan_cfi;                      // vlan.cfi
            uint16_t vlan_etype;                // vlan.etype
            
            // QinQ (802.1ad) - Double VLAN tagging
            bool has_qinq;
            uint16_t outer_vlan_id;
            uint16_t inner_vlan_id;
            
            // Trailer and FCS
            bool has_trailer;
            uint8_t trailer[64];
            size_t trailer_length;
            
            bool has_fcs;                       // eth.fcs
            uint32_t fcs;                       // eth.fcs
            bool fcs_valid;                     // eth.fcs.status

            EthernetHeader()
            {
                std::memset(dst_mac, 0, 6);
                std::memset(src_mac, 0, 6);
                ether_type = 0;
                dst_lg_bit = false;
                dst_ig_bit = false;
                src_lg_bit = false;
                src_ig_bit = false;
                dst_oui = 0;
                src_oui = 0;
                has_vlan = false;
                vlan_id = 0;
                vlan_priority = 0;
                vlan_cfi = false;
                vlan_etype = 0;
                has_qinq = false;
                outer_vlan_id = 0;
                inner_vlan_id = 0;
                has_trailer = false;
                std::memset(trailer, 0, 64);
                trailer_length = 0;
                has_fcs = false;
                fcs = 0;
                fcs_valid = false;
            }
        };

        // ==================== ARP Header (Wireshark arp.*) ====================
        /**
         * @brief Cấu trúc cho ARP header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/a/arp.html
         */
        struct ARPHeader
        {
            uint16_t hardware_type;             // arp.hw.type
            uint16_t protocol_type;             // arp.proto.type
            uint8_t hardware_size;              // arp.hw.size
            uint8_t protocol_size;              // arp.proto.size
            uint16_t opcode;                    // arp.opcode
            uint8_t sender_mac[6];              // arp.src.hw_mac
            uint32_t sender_ip;                 // arp.src.proto_ipv4
            uint8_t target_mac[6];              // arp.dst.hw_mac
            uint32_t target_ip;                 // arp.dst.proto_ipv4
            
            // ARP analysis
            bool is_gratuitous;                 // arp.isgratuitous
            bool is_probe;                      // arp.isprobe
            bool is_announcement;               // arp.isannouncement
            
            // Duplicate detection
            bool is_duplicate_ip;               // arp.duplicate-address-detected
            uint32_t duplicate_frame;           // arp.duplicate-address-frame

            ARPHeader()
            {
                hardware_type = 0;
                protocol_type = 0;
                hardware_size = 0;
                protocol_size = 0;
                opcode = 0;
                std::memset(sender_mac, 0, 6);
                sender_ip = 0;
                std::memset(target_mac, 0, 6);
                target_ip = 0;
                is_gratuitous = false;
                is_probe = false;
                is_announcement = false;
                is_duplicate_ip = false;
                duplicate_frame = 0;
            }
        };

        // ==================== IPv4 Header (Wireshark ip.*) ====================
        /**
         * @brief IPv4 Option structure
         */
        struct IPv4Option
        {
            uint8_t type;                       // ip.opt.type
            uint8_t length;                     // ip.opt.len
            std::vector<uint8_t> data;
            
            // Common option types
            bool is_end_of_options;             // Type 0
            bool is_nop;                        // Type 1
            bool is_security;                   // Type 130
            bool is_loose_source_route;         // Type 131
            bool is_timestamp;                  // Type 68
            bool is_record_route;               // Type 7
            bool is_strict_source_route;        // Type 137

            IPv4Option()
            {
                type = 0;
                length = 0;
                is_end_of_options = false;
                is_nop = false;
                is_security = false;
                is_loose_source_route = false;
                is_timestamp = false;
                is_record_route = false;
                is_strict_source_route = false;
            }
        };

        /**
         * @brief Cấu trúc cho IPv4 header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/i/ip.html
         */
        struct IPv4Header
        {
            uint8_t version;                    // ip.version
            uint8_t ihl;                        // ip.hdr_len
            uint8_t tos;                        // ip.tos
            uint16_t total_length;              // ip.len
            uint16_t identification;            // ip.id
            uint16_t flags;                     // ip.flags
            uint16_t fragment_offset;           // ip.frag_offset
            uint8_t ttl;                        // ip.ttl
            uint8_t protocol;                   // ip.proto
            uint16_t checksum;                  // ip.checksum
            uint32_t src_ip;                    // ip.src
            uint32_t dst_ip;                    // ip.dst
            
            // DSCP and ECN (from ToS field)
            uint8_t dscp;                       // ip.dscp
            uint8_t ecn;                        // ip.ecn
            
            // Flags detailed
            bool flag_reserved;                 // ip.flags.rb
            bool flag_df;                       // ip.flags.df (Don't Fragment)
            bool flag_mf;                       // ip.flags.mf (More Fragments)
            
            // Fragmentation
            bool is_fragmented;                 // ip.frag_offset > 0 || mf
            bool more_fragments;
            bool dont_fragment;
            
            // Checksum validation
            bool checksum_valid;                // ip.checksum.status
            uint16_t checksum_calculated;       // ip.checksum_calculated
            
            // Options
            bool has_options;                   // ip.options
            std::vector<IPv4Option> options;
            
            // Reassembly information
            bool is_reassembled;                // ip.reassembled_in
            uint32_t reassembled_in_frame;
            uint32_t fragment_count;            // ip.fragment.count
            uint32_t reassembled_length;        // ip.reassembled.length

            IPv4Header()
            {
                version = 0;
                ihl = 0;
                tos = 0;
                total_length = 0;
                identification = 0;
                flags = 0;
                fragment_offset = 0;
                ttl = 0;
                protocol = 0;
                checksum = 0;
                src_ip = 0;
                dst_ip = 0;
                dscp = 0;
                ecn = 0;
                flag_reserved = false;
                flag_df = false;
                flag_mf = false;
                is_fragmented = false;
                more_fragments = false;
                dont_fragment = false;
                checksum_valid = false;
                checksum_calculated = 0;
                has_options = false;
                is_reassembled = false;
                reassembled_in_frame = 0;
                fragment_count = 0;
                reassembled_length = 0;
            }
        };

        // ==================== IPv6 Extension Headers ====================
        /**
         * @brief IPv6 Extension Headers structures
         * Reference: https://www.wireshark.org/docs/dfref/i/ipv6.html
         */
        struct IPv6HopByHopOptions
        {
            uint8_t next_header;                // ipv6.hop_opt.nxt
            uint8_t length;                     // ipv6.hop_opt.len
            std::vector<uint8_t> options;
        };

        struct IPv6RoutingHeader
        {
            uint8_t next_header;                // ipv6.routing.nxt
            uint8_t length;                     // ipv6.routing.len
            uint8_t type;                       // ipv6.routing.type
            uint8_t segments_left;              // ipv6.routing.segleft
            std::vector<uint8_t> addresses;
        };

        struct IPv6FragmentHeader
        {
            uint8_t next_header;                // ipv6.fragment.nxt
            uint8_t reserved;
            uint16_t offset;                    // ipv6.fragment.offset
            bool more_fragments;                // ipv6.fragment.more
            uint32_t identification;            // ipv6.fragment.id
        };

        struct IPv6DestinationOptions
        {
            uint8_t next_header;                // ipv6.dst_opt.nxt
            uint8_t length;                     // ipv6.dst_opt.len
            std::vector<uint8_t> options;
        };

        struct IPv6AuthenticationHeader
        {
            uint8_t next_header;                // ipv6.ah.nxt
            uint8_t length;                     // ipv6.ah.len
            uint16_t reserved;
            uint32_t spi;                       // ipv6.ah.spi
            uint32_t sequence;                  // ipv6.ah.sequence
        };

        /**
         * @brief Cấu trúc cho IPv6 header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/i/ipv6.html
         */
        struct IPv6Header
        {
            uint8_t version;                    // ipv6.version
            uint8_t traffic_class;              // ipv6.tclass
            uint32_t flow_label;                // ipv6.flow
            uint16_t payload_length;            // ipv6.plen
            uint8_t next_header;                // ipv6.nxt
            uint8_t hop_limit;                  // ipv6.hlim
            uint8_t src_ip[16];                 // ipv6.src
            uint8_t dst_ip[16];                 // ipv6.dst
            
            // DSCP and ECN (from traffic class)
            uint8_t dscp;                       // ipv6.dscp
            uint8_t ecn;                        // ipv6.ecn
            
            // Extension headers
            bool has_extension_headers;
            std::optional<IPv6HopByHopOptions> hop_by_hop;
            std::optional<IPv6RoutingHeader> routing;
            std::optional<IPv6FragmentHeader> fragment;
            std::optional<IPv6DestinationOptions> destination;
            std::optional<IPv6AuthenticationHeader> authentication;

            IPv6Header()
            {
                version = 0;
                traffic_class = 0;
                flow_label = 0;
                payload_length = 0;
                next_header = 0;
                hop_limit = 0;
                std::memset(src_ip, 0, 16);
                std::memset(dst_ip, 0, 16);
                dscp = 0;
                ecn = 0;
                has_extension_headers = false;
            }
        };

        // ==================== TCP Header (Wireshark tcp.*) ====================
        /**
         * @brief TCP Options structures
         * Reference: https://www.wireshark.org/docs/dfref/t/tcp.html
         */
        struct TCPOptionMSS
        {
            uint16_t value;                     // tcp.options.mss_val
        };

        struct TCPOptionWindowScale
        {
            uint8_t shift_count;                // tcp.options.wscale.shift
            uint32_t multiplier;                // tcp.options.wscale.multiplier
        };

        struct TCPOptionTimestamp
        {
            uint32_t tsval;                     // tcp.options.timestamp.tsval
            uint32_t tsecr;                     // tcp.options.timestamp.tsecr
        };

        struct TCPOptionSACK
        {
            bool permitted;                     // tcp.options.sack_perm
            struct SACKBlock
            {
                uint32_t left_edge;             // tcp.options.sack.le
                uint32_t right_edge;            // tcp.options.sack.re
            };
            std::vector<SACKBlock> blocks;
        };

        /**
         * @brief TCP Analysis information (như Wireshark SEQ/ACK analysis)
         */
        struct TCPAnalysis
        {
            // Stream tracking
            uint32_t stream_index;              // tcp.stream
            uint32_t conversation_completeness; // tcp.completeness
            
            // Sequence analysis
            uint32_t next_seq;                  // tcp.nxtseq
            uint32_t ack;                       // tcp.ack
            
            // Timing
            double time_relative;               // tcp.time_relative
            double time_delta;                  // tcp.time_delta
            
            // Retransmission detection
            bool is_retransmission;             // tcp.analysis.retransmission
            bool is_fast_retransmission;        // tcp.analysis.fast_retransmission
            bool is_spurious_retransmission;    // tcp.analysis.spurious_retransmission
            uint32_t retransmission_frame;      // tcp.analysis.retransmission_frame
            
            // Out-of-order detection
            bool is_out_of_order;               // tcp.analysis.out_of_order
            
            // Lost segment detection
            bool is_lost_segment;               // tcp.analysis.lost_segment
            uint32_t lost_segment_count;
            
            // ACK analysis
            bool is_dup_ack;                    // tcp.analysis.duplicate_ack
            uint32_t dup_ack_num;               // tcp.analysis.duplicate_ack_num
            uint32_t dup_ack_frame;             // tcp.analysis.duplicate_ack_frame
            
            // Zero window
            bool is_zero_window;                // tcp.analysis.zero_window
            bool is_zero_window_probe;          // tcp.analysis.zero_window_probe
            bool is_zero_window_probe_ack;      // tcp.analysis.zero_window_probe_ack
            
            // Keep-alive
            bool is_keep_alive;                 // tcp.analysis.keep_alive
            bool is_keep_alive_ack;             // tcp.analysis.keep_alive_ack
            
            // Window update
            bool is_window_update;              // tcp.analysis.window_update
            bool is_window_full;                // tcp.analysis.window_full
            
            // Bytes in flight
            uint32_t bytes_in_flight;           // tcp.analysis.bytes_in_flight
            uint32_t push_bytes_sent;           // tcp.analysis.push_bytes_sent
            
            // RTT (Round Trip Time)
            double rtt;                         // tcp.analysis.ack_rtt
            uint32_t ack_frame;                 // tcp.analysis.acks_frame

            TCPAnalysis()
            {
                stream_index = 0;
                conversation_completeness = 0;
                next_seq = 0;
                ack = 0;
                time_relative = 0.0;
                time_delta = 0.0;
                is_retransmission = false;
                is_fast_retransmission = false;
                is_spurious_retransmission = false;
                retransmission_frame = 0;
                is_out_of_order = false;
                is_lost_segment = false;
                lost_segment_count = 0;
                is_dup_ack = false;
                dup_ack_num = 0;
                dup_ack_frame = 0;
                is_zero_window = false;
                is_zero_window_probe = false;
                is_zero_window_probe_ack = false;
                is_keep_alive = false;
                is_keep_alive_ack = false;
                is_window_update = false;
                is_window_full = false;
                bytes_in_flight = 0;
                push_bytes_sent = 0;
                rtt = 0.0;
                ack_frame = 0;
            }
        };

        /**
         * @brief Cấu trúc cho TCP header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/t/tcp.html
         */
        struct TCPHeader
        {
            uint16_t src_port;                  // tcp.srcport
            uint16_t dst_port;                  // tcp.dstport
            uint32_t seq_number;                // tcp.seq
            uint32_t ack_number;                // tcp.ack
            uint8_t data_offset;                // tcp.hdr_len
            uint8_t reserved;
            uint8_t flags;                      // tcp.flags
            uint16_t window_size;               // tcp.window_size_value
            uint16_t checksum;                  // tcp.checksum
            uint16_t urgent_pointer;            // tcp.urgent_pointer
            
            // TCP Flags
            bool flag_fin;                      // tcp.flags.fin
            bool flag_syn;                      // tcp.flags.syn
            bool flag_rst;                      // tcp.flags.reset
            bool flag_psh;                      // tcp.flags.push
            bool flag_ack;                      // tcp.flags.ack
            bool flag_urg;                      // tcp.flags.urg
            bool flag_ece;                      // tcp.flags.ecn
            bool flag_cwr;                      // tcp.flags.cwr
            
            // Calculated fields
            uint32_t calculated_window_size;    // tcp.window_size (scaled)
            uint32_t payload_length;            // tcp.len
            uint32_t segment_data_length;       // tcp.segment_data
            
            // Checksum validation
            bool checksum_valid;                // tcp.checksum.status
            uint16_t checksum_calculated;       // tcp.checksum_calculated
            
            // TCP Options
            bool has_options;
            uint8_t options[40];
            size_t options_length;
            
            // Parsed options
            std::optional<TCPOptionMSS> opt_mss;
            std::optional<TCPOptionWindowScale> opt_window_scale;
            std::optional<TCPOptionTimestamp> opt_timestamp;
            std::optional<TCPOptionSACK> opt_sack;
            
            // TCP Analysis
            TCPAnalysis analysis;

            TCPHeader()
            {
                src_port = 0;
                dst_port = 0;
                seq_number = 0;
                ack_number = 0;
                data_offset = 0;
                reserved = 0;
                flags = 0;
                window_size = 0;
                checksum = 0;
                urgent_pointer = 0;
                flag_fin = false;
                flag_syn = false;
                flag_rst = false;
                flag_psh = false;
                flag_ack = false;
                flag_urg = false;
                flag_ece = false;
                flag_cwr = false;
                calculated_window_size = 0;
                payload_length = 0;
                segment_data_length = 0;
                checksum_valid = false;
                checksum_calculated = 0;
                has_options = false;
                std::memset(options, 0, 40);
                options_length = 0;
            }
        };

        // ==================== UDP Header (Wireshark udp.*) ====================
        /**
         * @brief Cấu trúc cho UDP header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/u/udp.html
         */
        struct UDPHeader
        {
            uint16_t src_port;                  // udp.srcport
            uint16_t dst_port;                  // udp.dstport
            uint16_t length;                    // udp.length
            uint16_t checksum;                  // udp.checksum
            
            // Calculated fields
            uint16_t payload_length;            // udp.length - 8
            
            // Checksum validation
            bool checksum_valid;                // udp.checksum.status
            uint16_t checksum_calculated;       // udp.checksum_calculated
            
            // Stream tracking
            uint32_t stream_index;              // udp.stream

            UDPHeader()
            {
                src_port = 0;
                dst_port = 0;
                length = 0;
                checksum = 0;
                payload_length = 0;
                checksum_valid = false;
                checksum_calculated = 0;
                stream_index = 0;
            }
        };

        // ==================== ICMP Header (Wireshark icmp.*) ====================
        /**
         * @brief Cấu trúc cho ICMP header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/i/icmp.html
         */
        struct ICMPHeader
        {
            uint8_t type;                       // icmp.type
            uint8_t code;                       // icmp.code
            uint16_t checksum;                  // icmp.checksum
            uint32_t rest_of_header;
            
            // Echo request/reply specific
            uint16_t identifier;                // icmp.ident
            uint16_t sequence;                  // icmp.seq
            
            // Other type-specific fields
            uint32_t unused;                    // icmp.unused
            uint32_t gateway;                   // icmp.gateway
            uint16_t mtu;                       // icmp.mtu
            
            // Timestamp fields
            uint32_t originate_timestamp;       // icmp.originate_timestamp
            uint32_t receive_timestamp;         // icmp.receive_timestamp
            uint32_t transmit_timestamp;        // icmp.transmit_timestamp
            
            // Address mask
            uint32_t address_mask;              // icmp.address_mask
            
            // Checksum validation
            bool checksum_valid;                // icmp.checksum.status
            uint16_t checksum_calculated;       // icmp.checksum_calculated
            
            // Response tracking
            bool is_response_to;                // icmp.resp_to
            uint32_t response_frame;            // icmp.resp_in
            double response_time;               // icmp.resptime
            
            // Data (for error messages)
            const uint8_t* data;                // icmp.data
            size_t data_length;

            ICMPHeader()
            {
                type = 0;
                code = 0;
                checksum = 0;
                rest_of_header = 0;
                identifier = 0;
                sequence = 0;
                unused = 0;
                gateway = 0;
                mtu = 0;
                originate_timestamp = 0;
                receive_timestamp = 0;
                transmit_timestamp = 0;
                address_mask = 0;
                checksum_valid = false;
                checksum_calculated = 0;
                is_response_to = false;
                response_frame = 0;
                response_time = 0.0;
                data = nullptr;
                data_length = 0;
            }
        };

        // ==================== ICMPv6 Header (Wireshark icmpv6.*) ====================
        /**
         * @brief Cấu trúc cho ICMPv6 header với đầy đủ trường Wireshark
         * Reference: https://www.wireshark.org/docs/dfref/i/icmpv6.html
         */
        struct ICMPv6Header
        {
            uint8_t type;                       // icmpv6.type
            uint8_t code;                       // icmpv6.code
            uint16_t checksum;                  // icmpv6.checksum
            uint32_t reserved;
            
            // Echo request/reply
            uint16_t identifier;                // icmpv6.echo.identifier
            uint16_t sequence;                  // icmpv6.echo.sequence_number
            
            // Checksum validation
            bool checksum_valid;                // icmpv6.checksum.status
            uint16_t checksum_calculated;       // icmpv6.checksum_calculated
            
            // Response tracking
            bool is_response_to;                // icmpv6.resp_to
            uint32_t response_frame;
            double response_time;               // icmpv6.resptime

            ICMPv6Header()
            {
                type = 0;
                code = 0;
                checksum = 0;
                reserved = 0;
                identifier = 0;
                sequence = 0;
                checksum_valid = false;
                checksum_calculated = 0;
                is_response_to = false;
                response_frame = 0;
                response_time = 0.0;
            }
        };

        // ==================== Application Protocol Detection ====================
        /**
         * @brief Application protocol detection
         */
        enum class AppProtocol
        {
            UNKNOWN = 0,
            HTTP,
            HTTPS,
            DNS,
            SSH,
            FTP,
            FTP_DATA,
            SMTP,
            POP3,
            IMAP,
            TELNET,
            DHCP,
            NTP,
            SNMP,
            SMB,
            RDP,
            MYSQL,
            POSTGRESQL,
            REDIS,
            MONGODB
        };

        // ==================== Parsed Packet Structure ====================
        /**
         * @brief Cấu trúc thông tin packet đã parse đầy đủ theo Wireshark
         */
        struct ParsedPacket
        {
            // ==================== Raw data =======================
            const uint8_t* raw_data;
            
            // ==================== Frame Metadata ====================
            FrameMetadata frame_metadata;
            
            // ==================== Basic Metadata ====================
            uint64_t timestamp;                 // Timestamp in microseconds
            size_t packet_size;                 // Total packet size
            size_t captured_length;             // Captured length
            std::string interface_name;         // Interface name
            ProtocolType protocol_type;         // Highest protocol type detected
            
            // ==================== Layer 2 - Ethernet ====================
            bool has_ethernet;
            EthernetHeader ethernet;
            
            // ==================== Layer 2.5 - ARP ====================
            bool has_arp;
            ARPHeader arp;
            
            // ==================== Layer 3 - Network ====================
            bool has_ipv4;
            IPv4Header ipv4;
            
            bool has_ipv6;
            IPv6Header ipv6;
            
            // ==================== Layer 4 - Transport ====================
            bool has_tcp;
            TCPHeader tcp;
            
            bool has_udp;
            UDPHeader udp;
            
            bool has_icmp;
            ICMPHeader icmp;
            
            bool has_icmpv6;
            ICMPv6Header icmpv6;
            
            // ==================== Payload ====================
            const uint8_t *payload;
            size_t payload_length;
            
            // ==================== Additional Info ====================
            uint8_t ip_protocol;                // IP protocol number
            bool is_fragmented;                 // Is packet fragmented
            bool is_truncated;                  // Is packet truncated
            bool is_encrypted;                  // Likely encrypted (HTTPS, SSH, etc.)
            
            // ==================== Application Layer ====================
            AppProtocol app_protocol;           // Detected application protocol
            
            // ==================== Quick Access Fields ====================
            // For backward compatibility and quick access
            uint8_t src_mac[6];
            uint8_t dst_mac[6];
            uint16_t eth_type;
            uint32_t src_ip;                    // IPv4 only
            uint32_t dst_ip;                    // IPv4 only
            uint16_t src_port;
            uint16_t dst_port;
            uint32_t seq_num;
            uint32_t ack_num;
            uint16_t tcp_flags;
            uint16_t window_size;
            uint8_t ip_ttl;
            uint8_t ip_version;
            
            // ==================== Constructor ====================
            ParsedPacket()
            {
                raw_data = nullptr;
                timestamp = 0;
                packet_size = 0;
                captured_length = 0;
                protocol_type = ProtocolType::UNKNOWN;
                
                has_ethernet = false;
                has_arp = false;
                has_ipv4 = false;
                has_ipv6 = false;
                has_tcp = false;
                has_udp = false;
                has_icmp = false;
                has_icmpv6 = false;
                
                payload = nullptr;
                payload_length = 0;
                
                ip_protocol = 0;
                is_fragmented = false;
                is_truncated = false;
                is_encrypted = false;
                
                app_protocol = AppProtocol::UNKNOWN;
                
                std::memset(src_mac, 0, 6);
                std::memset(dst_mac, 0, 6);
                eth_type = 0;
                src_ip = 0;
                dst_ip = 0;
                src_port = 0;
                dst_port = 0;
                seq_num = 0;
                ack_num = 0;
                tcp_flags = 0;
                window_size = 0;
                ip_ttl = 0;
                ip_version = 0;
            }
        };

        // ==================== Packet Info for Database ====================
        /**
         * @brief Struct đơn giản hóa để lưu database
         */
        struct PacketInfo
        {
            uint64_t timestamp;                 // Milliseconds since epoch
            std::string src_mac;
            std::string dst_mac;
            std::string src_ip;
            std::string dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            std::string protocol;               // "TCP", "UDP", "ICMP", etc.
            uint32_t length;
            std::string flags;                  // TCP flags (SYN, ACK, etc.)
            uint32_t payload_size;
            uint8_t ttl;
            std::string checksum;

            PacketInfo()
                : timestamp(0), src_port(0), dst_port(0),
                  length(0), payload_size(0), ttl(0) {}

            /**
             * @brief Tạo PacketInfo từ ParsedPacket
             */
            static PacketInfo fromParsedPacket(const ParsedPacket& parsed);
        };

        // ==================== TCP Stream Tracking ====================
        /**
         * @brief TCP Stream information for tracking connections
         */
        struct TCPStreamInfo
        {
            uint32_t stream_index;
            uint32_t next_seq;
            uint32_t expected_ack;
            uint64_t last_seen_time;
            uint64_t first_seen_time;
            std::set<uint32_t> seen_seq_numbers;
            std::map<uint32_t, uint64_t> seq_to_frame;  // seq -> frame number
            uint32_t dup_ack_count;
            uint32_t last_ack;
            uint8_t window_scale_factor;
            bool window_scale_set;
            uint32_t bytes_in_flight;
        };

        // ==================== Packet Parser Class ====================
        /**
         * @brief Parser cho các gói tin mạng với đầy đủ tính năng Wireshark
         */
        class PacketParser
        {
        public:
            PacketParser();
            ~PacketParser();

            /**
             * @brief Parse gói tin từ raw data
             */
            bool parsePacket(const uint8_t *data, size_t length, ParsedPacket &parsed);

            /**
             * @brief Parse Ethernet header
             */
            bool parseEthernet(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ARP header
             */
            bool parseARP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse IPv4 header
             */
            bool parseIPv4(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse IPv6 header
             */
            bool parseIPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse TCP header
             */
            bool parseTCP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse UDP header
             */
            bool parseUDP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ICMP header
             */
            bool parseICMP(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Parse ICMPv6 header
             */
            bool parseICMPv6(const uint8_t *data, size_t length, ParsedPacket &parsed, size_t &offset);

            /**
             * @brief Utility functions - Conversion
             */
            static std::string ipv4ToString(uint32_t ip);
            static std::string ipv6ToString(const uint8_t *ip);
            static std::string macToString(const uint8_t *mac);
            static std::string protocolToString(uint8_t protocol);
            static std::string tcpFlagsToString(uint8_t flags);
            static std::string icmpTypeToString(uint8_t type);
            static std::string icmpv6TypeToString(uint8_t type);
            static std::string arpOpcodeToString(uint16_t opcode);

            /**
             * @brief Get protocol type name
             */
            static std::string getProtocolTypeName(ProtocolType type);
            static std::string getAppProtocolName(AppProtocol proto);

            /**
             * @brief Get packet summary
             */
            static std::string getPacketSummary(const ParsedPacket &packet);

            /**
             * @brief Reset parser state (for new capture session)
             */
            void reset();

        private:
            // ==================== Validation Functions ====================
            bool validateEthernet(const struct ethhdr *eth_header, size_t length);
            bool validateIPv4(const struct iphdr *ip_header, size_t length);
            bool validateIPv6(const struct ip6_hdr *ip6_header, size_t length);
            bool validateTCP(const struct tcphdr *tcp_header, size_t length);
            bool validateUDP(const struct udphdr *udp_header, size_t length);
            bool validateICMP(const struct icmphdr *icmp_header, size_t length);

            // ==================== Helper Functions ====================
            void extractTCPFlags(const struct tcphdr *tcp_header, TCPHeader &tcp);
            void extractIPv4Flags(const struct iphdr *ip_header, IPv4Header &ipv4);
            void copyQuickAccessFields(ParsedPacket &parsed);
            void buildProtocolString(ParsedPacket &parsed);
            
            // ==================== Ethernet Analysis ====================
            void analyzeEthernetMAC(EthernetHeader &eth);
            
            // ==================== IPv4 Analysis ====================
            void parseIPv4Options(const uint8_t *data, size_t length, IPv4Header &ipv4);
            void extractDSCPandECN(uint8_t tos, uint8_t &dscp, uint8_t &ecn);
            
            // ==================== IPv6 Analysis ====================
            bool parseIPv6ExtensionHeaders(const uint8_t *data, size_t length, 
                                          ParsedPacket &parsed, size_t &offset);
            
            // ==================== TCP Analysis ====================
            void parseTCPOptions(const uint8_t *options_data, size_t options_len, TCPHeader &tcp);
            void analyzeTCPStream(ParsedPacket &parsed);
            std::string getTCPFlowKey(const ParsedPacket &parsed);
            void detectTCPRetransmission(ParsedPacket &parsed, TCPStreamInfo &stream);
            void detectTCPDuplicateACK(ParsedPacket &parsed, TCPStreamInfo &stream);
            void calculateTCPBytesInFlight(ParsedPacket &parsed, TCPStreamInfo &stream);
            
            // ==================== UDP Analysis ====================
            void analyzeUDPStream(ParsedPacket &parsed);
            std::string getUDPFlowKey(const ParsedPacket &parsed);
            
            // ==================== ARP Analysis ====================
            void analyzeARP(ParsedPacket &parsed);
            
            // ==================== ICMP Analysis ====================
            void analyzeICMPResponse(ParsedPacket &parsed);
            
            // ==================== Checksum Calculation ====================
            uint16_t calculateIPv4Checksum(const struct iphdr *ip_header);
            uint16_t calculateTCPChecksum(const ParsedPacket &parsed, 
                                         const uint8_t *tcp_data, size_t tcp_len);
            uint16_t calculateUDPChecksum(const ParsedPacket &parsed,
                                         const uint8_t *udp_data, size_t udp_len);
            uint16_t calculateICMPChecksum(const uint8_t *icmp_DATA, size_t icmp_len);
            
            // ==================== Application Protocol Detection ====================
            AppProtocol detectApplicationProtocol(const ParsedPacket &parsed);
            
            // ==================== State Management ====================
            uint32_t packet_counter_;
            uint64_t first_packet_time_;
            uint64_t last_packet_time_;
            
            // TCP stream tracking
            std::map<std::string, TCPStreamInfo> tcp_streams_;
            uint32_t next_tcp_stream_id_;
            
            // UDP stream tracking
            std::map<std::string, uint32_t> udp_streams_;
            uint32_t next_udp_stream_id_;
            
            // ARP cache for duplicate detection
            std::map<uint32_t, std::pair<uint64_t, uint32_t>> arp_cache_; // IP -> (MAC as uint64, frame)
            
            // ICMP echo tracking (for response time calculation)
            struct ICMPEchoInfo {
                uint64_t timestamp;
                uint32_t frame_number;
            };
            std::map<std::tuple<uint32_t, uint32_t, uint16_t, uint16_t>, ICMPEchoInfo> icmp_echo_requests_;
            // Key: (src_ip, dst_ip, id, seq)
        };

    } // namespace Common
} // namespace NetworkSecurity

#endif // PACKET_PARSER_HPP
