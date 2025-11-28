// src/core/layer1/filter/filter_parser.hpp

#ifndef NETWORK_SECURITY_FILTER_PARSER_HPP
#define NETWORK_SECURITY_FILTER_PARSER_HPP

#include "filter_expression.hpp"
#include <string>
#include <vector>
#include <memory>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Token for lexical analysis
             */
            struct Token
            {
                enum class Type
                {
                    FIELD,          // tcp.port, ip.src, etc.
                    OPERATOR,       // ==, !=, >, <, etc.
                    VALUE,          // 80, "192.168.1.1", etc.
                    LOGICAL_AND,    // and, &&
                    LOGICAL_OR,     // or, ||
                    LOGICAL_NOT,    // not, !
                    LPAREN,         // (
                    RPAREN,         // )
                    LBRACKET,       // [
                    RBRACKET,       // ]
                    LBRACE,         // {
                    RBRACE,         // }
                    COMMA,          // ,
                    COLON,          // :
                    END             // End of input
                };

                Type type;
                std::string value;
                size_t position;

                Token(Type t = Type::END, const std::string& v = "", size_t p = 0)
                    : type(t), value(v), position(p) {}
            };

            /**
             * @brief Lexer for filter expressions
             */
            class Lexer
            {
            public:
                explicit Lexer(const std::string& input);

                /**
                 * @brief Tokenize input string
                 */
                std::vector<Token> tokenize();

                /**
                 * @brief Get last error
                 */
                std::string getError() const { return error_; }

            private:
                std::string input_;
                size_t pos_;
                std::string error_;

                char peek();
                char advance();
                void skipWhitespace();
                bool isAtEnd();

                Token readField();
                Token readOperator();
                Token readValue();
                Token readString();
                Token readNumber();

                void setError(const std::string& message);
            };

            /**
             * @brief Parser for filter expressions (Wireshark-compatible)
             */
            class Parser
            {
            public:
                Parser();

                /**
                 * @brief Parse filter string into expression tree
                 */
                std::shared_ptr<Expression> parse(const std::string& filterString);

                /**
                 * @brief Get last error
                 */
                std::string getError() const { return error_; }

                /**
                 * @brief Validate filter syntax
                 */
                static bool validate(const std::string& filterString, std::string& error);

            private:
                std::vector<Token> tokens_;
                size_t pos_;
                std::string error_;

                Token current();
                Token peek();
                Token advance();
                bool match(Token::Type type);
                bool check(Token::Type type);
                bool isAtEnd();

                // Recursive descent parsing
                std::shared_ptr<Expression> parseExpression();
                std::shared_ptr<Expression> parseOrExpression();
                std::shared_ptr<Expression> parseAndExpression();
                std::shared_ptr<Expression> parseNotExpression();
                std::shared_ptr<Expression> parsePrimaryExpression();
                std::shared_ptr<Expression> parseFieldExpression();
                std::shared_ptr<Expression> parseExistenceExpression(FieldType field);
                std::shared_ptr<Expression> parseRangeExpression(FieldType field);
                std::shared_ptr<Expression> parseSliceExpression();
                std::shared_ptr<Expression> parseParenthesizedExpression();

                void setError(const std::string& message);
            };

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_FILTER_PARSER_HPP
