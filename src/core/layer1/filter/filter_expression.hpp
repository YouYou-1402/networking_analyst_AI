// src/core/layer1/filter/filter_expression.hpp

#ifndef NETWORK_SECURITY_FILTER_EXPRESSION_HPP
#define NETWORK_SECURITY_FILTER_EXPRESSION_HPP

#include "filter_types.hpp"
#include "common/packet_parser.hpp"
#include <memory>
#include <string>
#include <vector>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Base class for all filter expressions
             */
            class Expression
            {
            public:
                virtual ~Expression() = default;
                
                /**
                 * @brief Evaluate expression against packet
                 */
                virtual bool evaluate(const Common::ParsedPacket& packet) const = 0;
                
                /**
                 * @brief Convert expression to string
                 */
                virtual std::string toString() const = 0;
                
                /**
                 * @brief Get expression type for optimization
                 */
                virtual std::string getType() const = 0;
            };

            /**
             * @brief Field comparison expression (e.g., tcp.port == 80)
             */
            class FieldExpression : public Expression
            {
            public:
                FieldExpression(FieldType field, Operator op, const std::string& value);
                
                bool evaluate(const Common::ParsedPacket& packet) const override;
                std::string toString() const override;
                std::string getType() const override { return "field"; }
                
                FieldType getField() const { return field_; }
                Operator getOperator() const { return op_; }
                const std::string& getValue() const { return value_; }

            private:
                FieldType field_;
                Operator op_;
                std::string value_;
                
                // Cached parsed values for performance
                mutable bool value_parsed_;
                mutable ValueType value_type_;
                mutable FieldValue parsed_value_;
                
                void parseValue() const;
            };

            /**
             * @brief Existence expression (e.g., tcp, http)
             */
            class ExistenceExpression : public Expression
            {
            public:
                explicit ExistenceExpression(FieldType field);
                
                bool evaluate(const Common::ParsedPacket& packet) const override;
                std::string toString() const override;
                std::string getType() const override { return "existence"; }
                
                FieldType getField() const { return field_; }

            private:
                FieldType field_;
            };

            /**
             * @brief Logical expression (AND, OR, NOT)
             */
            class LogicalExpression : public Expression
            {
            public:
                LogicalExpression(LogicalOp op,
                                std::shared_ptr<Expression> left,
                                std::shared_ptr<Expression> right = nullptr);
                
                bool evaluate(const Common::ParsedPacket& packet) const override;
                std::string toString() const override;
                std::string getType() const override { return "logical"; }
                
                LogicalOp getOperator() const { return op_; }
                std::shared_ptr<Expression> getLeft() const { return left_; }
                std::shared_ptr<Expression> getRight() const { return right_; }

            private:
                LogicalOp op_;
                std::shared_ptr<Expression> left_;
                std::shared_ptr<Expression> right_;
            };

            /**
             * @brief Range expression (e.g., tcp.port in {80, 443, 8080})
             */
            class RangeExpression : public Expression
            {
            public:
                RangeExpression(FieldType field, const std::vector<std::string>& values);
                
                bool evaluate(const Common::ParsedPacket& packet) const override;
                std::string toString() const override;
                std::string getType() const override { return "range"; }

            private:
                FieldType field_;
                std::vector<std::string> values_;
            };

            /**
             * @brief Slice expression (e.g., frame[10:20] == "data")
             */
            class SliceExpression : public Expression
            {
            public:
                SliceExpression(size_t start, size_t length, 
                              Operator op, const std::string& value);
                
                bool evaluate(const Common::ParsedPacket& packet) const override;
                std::string toString() const override;
                std::string getType() const override { return "slice"; }

            private:
                size_t start_;
                size_t length_;
                Operator op_;
                std::string value_;
            };

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_FILTER_EXPRESSION_HPP
