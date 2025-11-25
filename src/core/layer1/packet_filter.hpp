// src/core/layer1/packet_filter.hpp

#ifndef NETWORK_SECURITY_LAYER1_PACKET_FILTER_HPP
#define NETWORK_SECURITY_LAYER1_PACKET_FILTER_HPP

#include "../../common/packet_parser.hpp"
#include <fstream>      
#include <sstream>     
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_set>
#include <unordered_map>
#include <regex>
#include <atomic>

namespace NetworkSecurity
{
    namespace Layer1
    {
        // ==================== Filter Expression Parser ====================
        
        enum class FilterOperator
        {
            EQUALS,              // ==
            NOT_EQUALS,          // !=
            GREATER_THAN,        // >
            LESS_THAN,           // <
            GREATER_OR_EQUAL,    // >=
            LESS_OR_EQUAL,       // <=
            CONTAINS,            // contains
            MATCHES,             // matches (regex)
            IN,                  // in
            AND,                 // &&, and
            OR,                  // ||, or
            NOT,                 // !, not
            BITWISE_AND          // &
        };

        enum class FilterFieldType
        {
            // Ethernet
            ETH_SRC,
            ETH_DST,
            ETH_ADDR,
            ETH_TYPE,
            VLAN_ID,
            
            // IPv4
            IP_SRC,
            IP_DST,
            IP_ADDR,
            IP_PROTO,
            IP_VERSION,
            IP_ttl, 
            IP_LEN,
            IP_ID,
            IP_FLAGS,
            IP_FRAG_OFFSET,
            
            // IPv6
            IPV6_SRC,
            IPV6_DST,
            IPV6_ADDR,
            IPV6_NXTHDR,
            IPV6_HLIM,
            IPV6_FLOW,
            
            // TCP
            TCP_SRCPORT,
            TCP_DSTPORT,
            TCP_PORT,
            TCP_SEQ,
            TCP_ACK,
            TCP_FLAGS,
            TCP_FLAGS_SYN,
            TCP_FLAGS_ACK,
            TCP_FLAGS_FIN,
            TCP_FLAGS_RST,
            TCP_FLAGS_PSH,
            TCP_FLAGS_URG,
            TCP_WINDOW,
            TCP_LEN,
            TCP_STREAM,
            
            // UDP
            UDP_SRCPORT,
            UDP_DSTPORT,
            UDP_PORT,
            UDP_LENGTH,
            
            // ICMP
            ICMP_TYPE,
            ICMP_CODE,
            
            // ICMPv6
            ICMPV6_TYPE,
            ICMPV6_CODE,
            
            // ARP
            ARP_OPCODE,
            ARP_SRC_HW,
            ARP_DST_HW,
            ARP_SRC_PROTO,
            ARP_DST_PROTO,
            
            // General
            FRAME_LEN,
            FRAME_PROTOCOLS,
            FRAME_TIME,
            FRAME_TIME_DELTA,
            
            // Protocol checks
            PROTOCOL_TCP,
            PROTOCOL_UDP,
            PROTOCOL_ICMP,
            PROTOCOL_ICMPV6,
            PROTOCOL_ARP,
            PROTOCOL_IP,
            PROTOCOL_IPV6,
            
            // Data
            DATA,
            DATA_LEN,
            
            UNKNOWN
        };

        // ==================== Filter Expression Tree ====================
        
        class FilterExpression
        {
        public:
            virtual ~FilterExpression() = default;
            virtual bool evaluate(const Common::ParsedPacket& packet) const = 0;
            virtual std::string toString() const = 0;
        };

        // Leaf node - field comparison
        class FieldExpression : public FilterExpression
        {
        public:
            FieldExpression(FilterFieldType field, FilterOperator op, const std::string& value);
            
            bool evaluate(const Common::ParsedPacket& packet) const override;
            std::string toString() const override;
            
        private:
            FilterFieldType field_;
            FilterOperator op_;
            std::string value_;
            
            bool evaluateEthernet(const Common::ParsedPacket& packet) const;
            bool evaluateIPv4(const Common::ParsedPacket& packet) const;
            bool evaluateIPv6(const Common::ParsedPacket& packet) const;
            bool evaluateTCP(const Common::ParsedPacket& packet) const;
            bool evaluateUDP(const Common::ParsedPacket& packet) const;
            bool evaluateICMP(const Common::ParsedPacket& packet) const;
            bool evaluateARP(const Common::ParsedPacket& packet) const;
            bool evaluateGeneral(const Common::ParsedPacket& packet) const;
            bool evaluateProtocol(const Common::ParsedPacket& packet) const;
            
            bool compareValue(const std::string& actual, const std::string& expected, FilterOperator op) const;
            bool compareNumeric(uint64_t actual, uint64_t expected, FilterOperator op) const;
            bool compareIP(const std::string& actual, const std::string& expected, FilterOperator op) const;
            bool compareMAC(const std::string& actual, const std::string& expected, FilterOperator op) const;
        };

        // Binary operator node
        class BinaryExpression : public FilterExpression
        {
        public:
            BinaryExpression(std::unique_ptr<FilterExpression> left,
                           FilterOperator op,
                           std::unique_ptr<FilterExpression> right);
            
            bool evaluate(const Common::ParsedPacket& packet) const override;
            std::string toString() const override;
            
        private:
            std::unique_ptr<FilterExpression> left_;
            FilterOperator op_;
            std::unique_ptr<FilterExpression> right_;
        };

        // Unary operator node (NOT)
        class UnaryExpression : public FilterExpression
        {
        public:
            UnaryExpression(FilterOperator op, std::unique_ptr<FilterExpression> expr);
            
            bool evaluate(const Common::ParsedPacket& packet) const override;
            std::string toString() const override;
            
        private:
            FilterOperator op_;
            std::unique_ptr<FilterExpression> expr_;
        };

        // ==================== Filter Parser ====================
        
        class FilterParser
        {
        public:
            FilterParser();
            
            // Parse Wireshark-style filter expression
            std::unique_ptr<FilterExpression> parse(const std::string& filter_string);
            
            // Validate filter syntax
            bool validate(const std::string& filter_string, std::string& error_msg);
            
            // Get last error
            std::string getLastError() const { return last_error_; }
            
        private:
            std::string last_error_;
            size_t pos_;
            std::string input_;
            
            // Tokenizer
            struct Token
            {
                enum Type
                {
                    FIELD,
                    OPERATOR,
                    VALUE,
                    LPAREN,
                    RPAREN,
                    AND,
                    OR,
                    NOT,
                    END
                };
                
                Type type;
                std::string value;
            };
            
            std::vector<Token> tokenize(const std::string& input);
            Token nextToken();
            
            // Recursive descent parser
            std::unique_ptr<FilterExpression> parseExpression();
            std::unique_ptr<FilterExpression> parseOrExpression();
            std::unique_ptr<FilterExpression> parseAndExpression();
            std::unique_ptr<FilterExpression> parseNotExpression();
            std::unique_ptr<FilterExpression> parsePrimaryExpression();
            std::unique_ptr<FilterExpression> parseComparison();
            
            // Helper methods
            FilterFieldType parseFieldType(const std::string& field);
            FilterOperator parseOperator(const std::string& op);
            std::string parseValue();
            
            void skipWhitespace();
            char peek();
            char consume();
            bool match(char c);
            
            void error(const std::string& msg);
        };

        // ==================== Display Filter ====================
        
        class DisplayFilter
        {
        public:
            DisplayFilter();
            ~DisplayFilter();
            
            // Set filter from string (Wireshark syntax)
            bool setFilter(const std::string& filter_string);
            
            // Clear filter
            void clearFilter();
            
            // Check if packet matches filter
            bool matches(const Common::ParsedPacket& packet) const;
            
            // Get current filter string
            std::string getFilterString() const { return filter_string_; }
            
            // Validate filter
            bool validate(const std::string& filter_string, std::string& error_msg);
            
            // Statistics
            uint64_t getMatchCount() const { return match_count_.load(); }
            uint64_t getTotalCount() const { return total_count_.load(); }
            void resetStats();
            
        private:
            std::string filter_string_;
            std::unique_ptr<FilterExpression> expression_;
            FilterParser parser_;
            
            mutable std::atomic<uint64_t> match_count_;
            mutable std::atomic<uint64_t> total_count_;
        };

        // ==================== Capture Filter (BPF) ====================
        
        class CaptureFilter
        {
        public:
            CaptureFilter();
            ~CaptureFilter();
            
            // Set BPF filter
            bool setFilter(const std::string& bpf_filter);
            
            // Convert Wireshark display filter to BPF (limited support)
            static std::string convertToBPF(const std::string& display_filter);
            
            // Get current filter
            std::string getFilterString() const { return filter_string_; }
            
            // Validate BPF syntax
            bool validate(const std::string& bpf_filter, std::string& error_msg);
            
        private:
            std::string filter_string_;
        };

        // ==================== Filter Presets ====================
        
        class FilterPresets
        {
        public:
            struct Preset
            {
                std::string name;
                std::string filter;
                std::string description;
                std::string category;
            };
            
            static std::vector<Preset> getPresets();
            static std::vector<Preset> getPresetsByCategory(const std::string& category);
            static std::string getPresetFilter(const std::string& name);
            
        private:
            static void initializePresets();
            static std::vector<Preset> presets_;
            static bool initialized_;
        };

        // ==================== Filter Suggestions ====================
        
        class FilterSuggestions
        {
        public:
            // Get field suggestions based on partial input
            static std::vector<std::string> getFieldSuggestions(const std::string& partial);
            
            // Get operator suggestions for a field
            static std::vector<std::string> getOperatorSuggestions(FilterFieldType field);
            
            // Get value suggestions for a field
            static std::vector<std::string> getValueSuggestions(FilterFieldType field, 
                                                               const std::string& partial);
            
            // Auto-complete filter expression
            static std::string autoComplete(const std::string& partial);
        };

        // ==================== Filter History ====================
        
        class FilterHistory
        {
        public:
            FilterHistory(size_t max_size = 100);
            
            void add(const std::string& filter);
            std::vector<std::string> getHistory() const;
            std::vector<std::string> search(const std::string& query) const;
            void clear();
            
            void saveToFile(const std::string& filepath);
            void loadFromFile(const std::string& filepath);
            
        private:
            std::vector<std::string> history_;
            size_t max_size_;
        };

        // ==================== Advanced Filter Manager ====================
        
        class AdvancedFilterManager
        {
        public:
            AdvancedFilterManager();
            ~AdvancedFilterManager();
            
            // Display filter
            bool setDisplayFilter(const std::string& filter);
            void clearDisplayFilter();
            bool matchesDisplayFilter(const Common::ParsedPacket& packet) const;
            
            // Capture filter (BPF)
            bool setCaptureFilter(const std::string& filter);
            std::string getCaptureFilterBPF() const;
            
            // Combined filtering
            bool matches(const Common::ParsedPacket& packet) const;
            
            // Filter management
            void saveFilter(const std::string& name, const std::string& filter);
            std::string loadFilter(const std::string& name);
            std::vector<std::string> getSavedFilters() const;
            
            // Presets
            std::vector<FilterPresets::Preset> getPresets() const;
            bool applyPreset(const std::string& preset_name);
            
            // History
            FilterHistory& getHistory() { return history_; }
            
            // Statistics
            struct FilterStats
            {
                uint64_t total_packets;
                uint64_t matched_packets;
                uint64_t filtered_packets;
                double match_rate;
                std::string current_filter;
            };
            
            FilterStats getStats() const;
            void resetStats();
            
            // Validation
            bool validateFilter(const std::string& filter, std::string& error_msg);
            
        private:
            DisplayFilter display_filter_;
            CaptureFilter capture_filter_;
            FilterHistory history_;
            
            std::unordered_map<std::string, std::string> saved_filters_;
            
            mutable std::atomic<uint64_t> total_packets_;
            mutable std::atomic<uint64_t> matched_packets_;
        };

        // ==================== Filter Builder (Fluent API) ====================
        
        class FilterBuilder
        {
        public:
            FilterBuilder();
            
            // Ethernet
            FilterBuilder& ethSrc(const std::string& mac);
            FilterBuilder& ethDst(const std::string& mac);
            FilterBuilder& ethAddr(const std::string& mac);
            FilterBuilder& ethType(uint16_t type);
            FilterBuilder& vlan(uint16_t vlan_id);
            
            // IP
            FilterBuilder& ipSrc(const std::string& ip);
            FilterBuilder& ipDst(const std::string& ip);
            FilterBuilder& ipAddr(const std::string& ip);
            FilterBuilder& ipProto(uint8_t proto);
            
            // TCP
            FilterBuilder& tcpSrcPort(uint16_t port);
            FilterBuilder& tcpDstPort(uint16_t port);
            FilterBuilder& tcpPort(uint16_t port);
            FilterBuilder& tcpFlags(const std::string& flags);
            FilterBuilder& tcpSyn();
            FilterBuilder& tcpAck();
            
            // UDP
            FilterBuilder& udpSrcPort(uint16_t port);
            FilterBuilder& udpDstPort(uint16_t port);
            FilterBuilder& udpPort(uint16_t port);
            
            // ICMP
            FilterBuilder& icmpType(uint8_t type);
            FilterBuilder& icmpCode(uint8_t code);
            
            // Logical operators
            FilterBuilder& and_();
            FilterBuilder& or_();
            FilterBuilder& not_();
            
            // Grouping
            FilterBuilder& beginGroup();
            FilterBuilder& endGroup();
            
            // Build
            std::string build() const;
            
        private:
            std::vector<std::string> parts_;
        };

    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_LAYER1_PACKET_FILTER_HPP
