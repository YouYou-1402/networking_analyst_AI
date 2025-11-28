// src/core/layer1/filter/filter_parser.cpp

#include "filter_parser.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <cctype>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // ==================== Lexer Implementation ====================

            Lexer::Lexer(const std::string& input)
                : input_(input), pos_(0)
            {
            }

            std::vector<Token> Lexer::tokenize()
            {
                std::vector<Token> tokens;

                while (!isAtEnd())
                {
                    skipWhitespace();
                    if (isAtEnd())
                    {
                        break;
                    }

                    char c = peek();
                    size_t start_pos = pos_;

                    // Parentheses
                    if (c == '(')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::LPAREN, "(", start_pos));
                        continue;
                    }
                    else if (c == ')')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::RPAREN, ")", start_pos));
                        continue;
                    }
                    // Brackets
                    else if (c == '[')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::LBRACKET, "[", start_pos));
                        continue;
                    }
                    else if (c == ']')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::RBRACKET, "]", start_pos));
                        continue;
                    }
                    // Braces
                    else if (c == '{')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::LBRACE, "{", start_pos));
                        continue;
                    }
                    else if (c == '}')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::RBRACE, "}", start_pos));
                        continue;
                    }
                    // Comma
                    else if (c == ',')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::COMMA, ",", start_pos));
                        continue;
                    }
                    // Colon
                    else if (c == ':')
                    {
                        advance();
                        tokens.push_back(Token(Token::Type::COLON, ":", start_pos));
                        continue;
                    }
                    // Operators
                    else if (c == '=' || c == '!' || c == '>' || c == '<' || c == '&')
                    {
                        Token op_token = readOperator();
                        tokens.push_back(op_token);
                        continue;
                    }
                    // String literal
                    else if (c == '"' || c == '\'')
                    {
                        Token str_token = readString();
                        if (!error_.empty())
                        {
                            return {};
                        }
                        tokens.push_back(str_token);
                        continue;
                    }
                    // Number
                    else if (isdigit(c) || (c == '0' && pos_ + 1 < input_.length() && 
                            (input_[pos_ + 1] == 'x' || input_[pos_ + 1] == 'X')))
                    {
                        Token num_token = readNumber();
                        tokens.push_back(num_token);
                        continue;
                    }
                    // Field name or keyword
                    else if (isalpha(c) || c == '_')
                    {
                        Token field_token = readField();
                        tokens.push_back(field_token);
                        continue;
                    }
                    else
                    {
                        setError("Unexpected character: " + std::string(1, c));
                        return {};
                    }
                }

                tokens.push_back(Token(Token::Type::END, "", pos_));
                return tokens;
            }

            char Lexer::peek()
            {
                if (isAtEnd())
                {
                    return '\0';
                }
                return input_[pos_];
            }

            char Lexer::advance()
            {
                if (isAtEnd())
                {
                    return '\0';
                }
                return input_[pos_++];
            }

            void Lexer::skipWhitespace()
            {
                while (!isAtEnd() && std::isspace(peek()))
                {
                    advance();
                }
            }

            bool Lexer::isAtEnd()
            {
                return pos_ >= input_.length();
            }

            Token Lexer::readField()
            {
                size_t start = pos_;
                std::string value;

                // Read field name (alphanumeric, underscore, dot, dash)
                while (!isAtEnd())
                {
                    char c = peek();
                    if (isalnum(c) || c == '_' || c == '.' || c == '-')
                    {
                        value += advance();
                    }
                    else
                    {
                        break;
                    }
                }

                // Check if it's a logical operator keyword
                std::string lower = value;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                if (lower == "and" || lower == "&&")
                {
                    return Token(Token::Type::LOGICAL_AND, value, start);
                }
                else if (lower == "or" || lower == "||")
                {
                    return Token(Token::Type::LOGICAL_OR, value, start);
                }
                else if (lower == "not" || lower == "!")
                {
                    return Token(Token::Type::LOGICAL_NOT, value, start);
                }
                // Check if it's an operator keyword
                else if (lower == "eq" || lower == "ne" || lower == "gt" || 
                        lower == "lt" || lower == "ge" || lower == "le" ||
                        lower == "contains" || lower == "matches" || lower == "in")
                {
                    return Token(Token::Type::OPERATOR, value, start);
                }
                else
                {
                    return Token(Token::Type::FIELD, value, start);
                }
            }

            Token Lexer::readOperator()
            {
                size_t start = pos_;
                std::string value;

                char c = advance();
                value += c;

                // Check for two-character operators
                if (!isAtEnd())
                {
                    char next = peek();
                    if ((c == '=' && next == '=') ||
                        (c == '!' && next == '=') ||
                        (c == '>' && next == '=') ||
                        (c == '<' && next == '=') ||
                        (c == '&' && next == '&') ||
                        (c == '|' && next == '|'))
                    {
                        value += advance();
                    }
                }

                // Determine token type
                if (value == "&&")
                {
                    return Token(Token::Type::LOGICAL_AND, value, start);
                }
                else if (value == "||")
                {
                    return Token(Token::Type::LOGICAL_OR, value, start);
                }
                else if (value == "!")
                {
                    return Token(Token::Type::LOGICAL_NOT, value, start);
                }
                else
                {
                    return Token(Token::Type::OPERATOR, value, start);
                }
            }

            Token Lexer::readValue()
            {
                size_t start = pos_;
                std::string value;

                // Read until whitespace or special character
                while (!isAtEnd())
                {
                    char c = peek();
                    if (std::isspace(c) || c == ')' || c == ',' || c == '}')
                    {
                        break;
                    }
                    value += advance();
                }

                return Token(Token::Type::VALUE, value, start);
            }

            Token Lexer::readString()
            {
                size_t start = pos_;
                char quote = advance(); // Consume opening quote
                std::string value;

                while (!isAtEnd())
                {
                    char c = peek();
                    if (c == quote)
                    {
                        advance(); // Consume closing quote
                        return Token(Token::Type::VALUE, value, start);
                    }
                    else if (c == '\\')
                    {
                        advance(); // Consume backslash
                        if (!isAtEnd())
                        {
                            char escaped = advance();
                            switch (escaped)
                            {
                                case 'n': value += '\n'; break;
                                case 't': value += '\t'; break;
                                case 'r': value += '\r'; break;
                                case '\\': value += '\\'; break;
                                case '"': value += '"'; break;
                                case '\'': value += '\''; break;
                                default: value += escaped; break;
                            }
                        }
                    }
                    else
                    {
                        value += advance();
                    }
                }

                setError("Unterminated string literal");
                return Token(Token::Type::VALUE, "", start);
            }

            Token Lexer::readNumber()
            {
                size_t start = pos_;
                std::string value;

                // Check for hex number
                if (peek() == '0' && pos_ + 1 < input_.length() && 
                    (input_[pos_ + 1] == 'x' || input_[pos_ + 1] == 'X'))
                {
                    value += advance(); // '0'
                    value += advance(); // 'x'
                    
                    while (!isAtEnd() && std::isxdigit(peek()))
                    {
                        value += advance();
                    }
                }
                else
                {
                    // Decimal or octal number
                    while (!isAtEnd() && std::isdigit(peek()))
                    {
                        value += advance();
                    }
                }

                return Token(Token::Type::VALUE, value, start);
            }

            void Lexer::setError(const std::string& message)
            {
                error_ = "Lexer error at position " + std::to_string(pos_) + ": " + message;
                spdlog::error(error_);
            }

            // ==================== Parser Implementation ====================

            Parser::Parser()
                : pos_(0)
            {
            }

            std::shared_ptr<Expression> Parser::parse(const std::string& filterString)
            {
                if (filterString.empty())
                {
                    setError("Empty filter string");
                    return nullptr;
                }

                // Tokenize
                Lexer lexer(filterString);
                tokens_ = lexer.tokenize();
                
                if (!lexer.getError().empty())
                {
                    error_ = lexer.getError();
                    return nullptr;
                }

                if (tokens_.empty())
                {
                    setError("No tokens generated");
                    return nullptr;
                }

                // Parse expression tree
                pos_ = 0;
                try
                {
                    auto expr = parseExpression();
                    
                    // Check if all tokens consumed
                    if (!isAtEnd())
                    {
                        setError("Unexpected tokens after expression");
                        return nullptr;
                    }
                    
                    return expr;
                }
                catch (const std::exception& e)
                {
                    setError(std::string("Parse error: ") + e.what());
                    return nullptr;
                }
            }

            bool Parser::validate(const std::string& filterString, std::string& error)
            {
                Parser parser;
                auto expr = parser.parse(filterString);
                
                if (!expr)
                {
                    error = parser.getError();
                    return false;
                }
                
                return true;
            }

            Token Parser::current()
            {
                if (pos_ >= tokens_.size())
                {
                    return tokens_.back(); // Return END token
                }
                return tokens_[pos_];
            }

            Token Parser::peek()
            {
                if (pos_ + 1 >= tokens_.size())
                {
                    return tokens_.back();
                }
                return tokens_[pos_ + 1];
            }

            Token Parser::advance()
            {
                if (pos_ < tokens_.size())
                {
                    return tokens_[pos_++];
                }
                return tokens_.back();
            }

            bool Parser::match(Token::Type type)
            {
                if (check(type))
                {
                    advance();
                    return true;
                }
                return false;
            }

            bool Parser::check(Token::Type type)
            {
                if (isAtEnd())
                {
                    return false;
                }
                return current().type == type;
            }

            bool Parser::isAtEnd()
            {
                return current().type == Token::Type::END;
            }

            void Parser::setError(const std::string& message)
            {
                Token tok = current();
                error_ = "Parse error at position " + std::to_string(tok.position) + 
                        ": " + message + " (got '" + tok.value + "')";
                spdlog::error(error_);
            }

            // ==================== Expression Parsing ====================

            std::shared_ptr<Expression> Parser::parseExpression()
            {
                return parseOrExpression();
            }

            std::shared_ptr<Expression> Parser::parseOrExpression()
            {
                auto left = parseAndExpression();
                if (!left)
                {
                    return nullptr;
                }

                while (match(Token::Type::LOGICAL_OR))
                {
                    auto right = parseAndExpression();
                    if (!right)
                    {
                        setError("Expected expression after 'or'");
                        return nullptr;
                    }
                    
                    left = std::make_shared<LogicalExpression>(
                        LogicalOp::OR, left, right);
                }

                return left;
            }

            std::shared_ptr<Expression> Parser::parseAndExpression()
            {
                auto left = parseNotExpression();
                if (!left)
                {
                    return nullptr;
                }

                while (match(Token::Type::LOGICAL_AND))
                {
                    auto right = parseNotExpression();
                    if (!right)
                    {
                        setError("Expected expression after 'and'");
                        return nullptr;
                    }
                    
                    left = std::make_shared<LogicalExpression>(
                        LogicalOp::AND, left, right);
                }

                return left;
            }

            std::shared_ptr<Expression> Parser::parseNotExpression()
            {
                if (match(Token::Type::LOGICAL_NOT))
                {
                    auto expr = parseNotExpression(); // Allow chaining: not not expr
                    if (!expr)
                    {
                        setError("Expected expression after 'not'");
                        return nullptr;
                    }
                    
                    return std::make_shared<LogicalExpression>(
                        LogicalOp::NOT, expr);
                }

                return parsePrimaryExpression();
            }

            std::shared_ptr<Expression> Parser::parsePrimaryExpression()
            {
                // Parenthesized expression
                if (check(Token::Type::LPAREN))
                {
                    return parseParenthesizedExpression();
                }

                // Slice expression: frame[offset:length]
                if (check(Token::Type::FIELD))
                {
                    Token field_token = current();
                    if (field_token.value == "frame" && peek().type == Token::Type::LBRACKET)
                    {
                        return parseSliceExpression();
                    }
                }

                // Field expression
                if (check(Token::Type::FIELD))
                {
                    return parseFieldExpression();
                }

                setError("Expected field name or '('");
                return nullptr;
            }

            std::shared_ptr<Expression> Parser::parseFieldExpression()
            {
                Token field_token = advance();
                FieldType field = parseFieldType(field_token.value);

                if (field == FieldType::UNKNOWN)
                {
                    setError("Unknown field: " + field_token.value);
                    return nullptr;
                }

                // Check for operator
                if (check(Token::Type::OPERATOR))
                {
                    Token op_token = advance();
                    Operator op = parseOperator(op_token.value);

                    // Check for 'in' operator with set
                    if (op == Operator::IN)
                    {
                        return parseRangeExpression(field);
                    }

                    // Expect value
                    if (!check(Token::Type::VALUE))
                    {
                        setError("Expected value after operator");
                        return nullptr;
                    }

                    Token value_token = advance();
                    return std::make_shared<FieldExpression>(field, op, value_token.value);
                }
                else
                {
                    // Existence check (e.g., "tcp", "http")
                    return parseExistenceExpression(field);
                }
            }

            std::shared_ptr<Expression> Parser::parseExistenceExpression(FieldType field)
            {
                return std::make_shared<ExistenceExpression>(field);
            }

            std::shared_ptr<Expression> Parser::parseRangeExpression(FieldType field)
            {
                // Expect '{'
                if (!match(Token::Type::LBRACE))
                {
                    setError("Expected '{' after 'in'");
                    return nullptr;
                }

                std::vector<std::string> values;

                // Parse values
                while (!check(Token::Type::RBRACE))
                {
                    if (!check(Token::Type::VALUE))
                    {
                        setError("Expected value in range");
                        return nullptr;
                    }

                    Token value_token = advance();
                    values.push_back(value_token.value);

                    // Check for comma
                    if (check(Token::Type::COMMA))
                    {
                        advance();
                    }
                    else if (!check(Token::Type::RBRACE))
                    {
                        setError("Expected ',' or '}' in range");
                        return nullptr;
                    }
                }

                // Expect '}'
                if (!match(Token::Type::RBRACE))
                {
                    setError("Expected '}' at end of range");
                    return nullptr;
                }

                if (values.empty())
                {
                    setError("Empty range not allowed");
                    return nullptr;
                }

                return std::make_shared<RangeExpression>(field, values);
            }

            std::shared_ptr<Expression> Parser::parseSliceExpression()
            {
                // Consume "frame"
                advance();

                // Expect '['
                if (!match(Token::Type::LBRACKET))
                {
                    setError("Expected '[' after 'frame'");
                    return nullptr;
                }

                // Parse start offset
                if (!check(Token::Type::VALUE))
                {
                    setError("Expected offset value");
                    return nullptr;
                }

                Token start_token = advance();
                size_t start = 0;
                try
                {
                    start = std::stoull(start_token.value);
                }
                catch (...)
                {
                    setError("Invalid offset value");
                    return nullptr;
                }

                // Expect ':'
                if (!match(Token::Type::COLON))
                {
                    setError("Expected ':' in slice");
                    return nullptr;
                }

                // Parse length
                if (!check(Token::Type::VALUE))
                {
                    setError("Expected length value");
                    return nullptr;
                }

                Token length_token = advance();
                size_t length = 0;
                try
                {
                    length = std::stoull(length_token.value);
                }
                catch (...)
                {
                    setError("Invalid length value");
                    return nullptr;
                }

                // Expect ']'
                if (!match(Token::Type::RBRACKET))
                {
                    setError("Expected ']' at end of slice");
                    return nullptr;
                }

                // Expect operator
                if (!check(Token::Type::OPERATOR))
                {
                    setError("Expected operator after slice");
                    return nullptr;
                }

                Token op_token = advance();
                Operator op = parseOperator(op_token.value);

                // Expect value
                if (!check(Token::Type::VALUE))
                {
                    setError("Expected value after operator");
                    return nullptr;
                }

                Token value_token = advance();

                return std::make_shared<SliceExpression>(start, length, op, value_token.value);
            }

            std::shared_ptr<Expression> Parser::parseParenthesizedExpression()
            {
                // Consume '('
                advance();

                auto expr = parseExpression();
                if (!expr)
                {
                    return nullptr;
                }

                // Expect ')'
                if (!match(Token::Type::RPAREN))
                {
                    setError("Expected ')' after expression");
                    return nullptr;
                }

                return expr;
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity
