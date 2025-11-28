// src/core/layer1/filter/filter_field_evaluator.hpp

#ifndef NETWORK_SECURITY_FILTER_FIELD_EVALUATOR_HPP
#define NETWORK_SECURITY_FILTER_FIELD_EVALUATOR_HPP

#include "filter_types.hpp"
#include "common/packet_parser.hpp"
#include <string>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Field evaluator - evaluates field values from packets
             */
            class FieldEvaluator
            {
            public:
                /**
                 * @brief Extract field value from packet
                 */
                static bool extractFieldValue(const Common::ParsedPacket& packet,
                                             FieldType field,
                                             FieldValue& value,
                                             ValueType& type);

                /**
                 * @brief Compare field value with expected value
                 */
                static bool compareValues(const FieldValue& fieldValue,
                                        ValueType fieldType,
                                        Operator op,
                                        const std::string& expectedValue);

                /**
                 * @brief Check if field exists in packet
                 */
                static bool fieldExists(const Common::ParsedPacket& packet,
                                      FieldType field);

            private:
                // Frame evaluators
                static bool extractFrameField(const Common::ParsedPacket& packet,
                                             FieldType field,
                                             FieldValue& value,
                                             ValueType& type);

                // Ethernet evaluators
                static bool extractEthernetField(const Common::ParsedPacket& packet,
                                                FieldType field,
                                                FieldValue& value,
                                                ValueType& type);

                // ARP evaluators
                static bool extractARPField(const Common::ParsedPacket& packet,
                                           FieldType field,
                                           FieldValue& value,
                                           ValueType& type);

                // IPv4 evaluators
                static bool extractIPv4Field(const Common::ParsedPacket& packet,
                                            FieldType field,
                                            FieldValue& value,
                                            ValueType& type);

                // IPv6 evaluators
                static bool extractIPv6Field(const Common::ParsedPacket& packet,
                                            FieldType field,
                                            FieldValue& value,
                                            ValueType& type);

                // TCP evaluators
                static bool extractTCPField(const Common::ParsedPacket& packet,
                                           FieldType field,
                                           FieldValue& value,
                                           ValueType& type);

                // UDP evaluators
                static bool extractUDPField(const Common::ParsedPacket& packet,
                                           FieldType field,
                                           FieldValue& value,
                                           ValueType& type);

                // ICMP evaluators
                static bool extractICMPField(const Common::ParsedPacket& packet,
                                            FieldType field,
                                            FieldValue& value,
                                            ValueType& type);

                // Application protocol evaluators
                static bool extractAppProtocolField(const Common::ParsedPacket& packet,
                                                   FieldType field,
                                                   FieldValue& value,
                                                   ValueType& type);

                // Comparison helpers
                static bool compareNumber(uint64_t fieldValue, Operator op, uint64_t expectedValue);
                static bool compareString(const std::string& fieldValue, Operator op, const std::string& expectedValue);
                static bool compareIP(uint32_t fieldValue, Operator op, uint32_t expectedValue);
                static bool compareIPv6(const uint8_t* fieldValue, Operator op, const uint8_t* expectedValue);
                static bool compareMAC(const uint8_t* fieldValue, Operator op, const uint8_t* expectedValue);
            };

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_FILTER_FIELD_EVALUATOR_HPP
