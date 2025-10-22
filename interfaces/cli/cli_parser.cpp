// src/interfaces/cli/cli_parser.cpp
#include "cli_parser.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <climits>

namespace NetworkSecurity
{
    namespace Interface
    {
        namespace CLI
        {
            // ==================== Constructor/Destructor ====================
            
            CLIParser::CLIParser()
            {
            }

            CLIParser::~CLIParser()
            {
            }

            // ==================== Command Registration ====================
            
            void CLIParser::registerCommand(const std::string &name,
                                          const std::string &description,
                                          const std::string &usage,
                                          CommandHandler handler)
            {
                CommandInfo info;
                info.name = name;
                info.description = description;
                info.usage = usage;
                info.handler = handler;
                
                commands_[name] = info;
            }

            void CLIParser::registerCommand(const CommandInfo &cmd_info)
            {
                commands_[cmd_info.name] = cmd_info;
            }

            bool CLIParser::unregisterCommand(const std::string &name)
            {
                return commands_.erase(name) > 0;
            }

            // ==================== Command Parsing ====================
            
            Command CLIParser::parseCommand(const std::string &input)
            {
                Command cmd;
                
                std::vector<std::string> tokens = tokenize(input);
                
                if (tokens.empty())
                {
                    return cmd;
                }
                
                cmd.name = tokens[0];
                
                for (size_t i = 1; i < tokens.size(); ++i)
                {
                    const std::string &token = tokens[i];
                    
                    if (token.size() >= 2 && token[0] == '-')
                    {
                        // Option
                        std::string key = token;
                        std::string value;
                        
                        // Check if next token is value
                        if (i + 1 < tokens.size() && tokens[i + 1][0] != '-')
                        {
                            value = tokens[++i];
                        }
                        else
                        {
                            value = "true";
                        }
                        
                        cmd.options[key] = value;
                    }
                    else
                    {
                        // Argument
                        cmd.args.push_back(token);
                    }
                }
                
                return cmd;
            }

            Command CLIParser::parseCommandLine(int argc, char *argv[])
            {
                Command cmd;
                
                if (argc < 2)
                {
                    return cmd;
                }
                
                cmd.name = argv[1];
                
                for (int i = 2; i < argc; ++i)
                {
                    std::string token = argv[i];
                    
                    if (token.size() >= 2 && token[0] == '-')
                    {
                        std::string key = token;
                        std::string value;
                        
                        if (i + 1 < argc && argv[i + 1][0] != '-')
                        {
                            value = argv[++i];
                        }
                        else
                        {
                            value = "true";
                        }
                        
                        cmd.options[key] = value;
                    }
                    else
                    {
                        cmd.args.push_back(token);
                    }
                }
                
                return cmd;
            }

            std::vector<std::string> CLIParser::tokenize(const std::string &input)
            {
                std::vector<std::string> tokens;
                std::string current;
                bool in_quotes = false;
                char quote_char = '\0';
                
                for (size_t i = 0; i < input.size(); ++i)
                {
                    char c = input[i];
                    
                    if (c == '"' || c == '\'')
                    {
                        if (!in_quotes)
                        {
                            in_quotes = true;
                            quote_char = c;
                        }
                        else if (c == quote_char)
                        {
                            in_quotes = false;
                            quote_char = '\0';
                        }
                        else
                        {
                            current += c;
                        }
                    }
                    else if (std::isspace(c) && !in_quotes)
                    {
                        if (!current.empty())
                        {
                            tokens.push_back(current);
                            current.clear();
                        }
                    }
                    else
                    {
                        current += c;
                    }
                }
                
                if (!current.empty())
                {
                    tokens.push_back(current);
                }
                
                return tokens;
            }

            // ==================== Command Execution ====================
            
            bool CLIParser::executeCommand(const Command &cmd)
            {
                if (cmd.name.empty())
                {
                    return false;
                }
                
                auto it = commands_.find(cmd.name);
                if (it == commands_.end())
                {
                    std::cerr << "Unknown command: " << cmd.name << std::endl;
                    
                    // Suggest similar command
                    std::string closest = getClosestCommand(cmd.name);
                    if (!closest.empty())
                    {
                        std::cerr << "Did you mean: " << closest << "?" << std::endl;
                    }
                    
                    return false;
                }
                
                try
                {
                    return it->second.handler(cmd);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error executing command: " << e.what() << std::endl;
                    return false;
                }
            }

            bool CLIParser::executeCommand(const std::string &input)
            {
                Command cmd = parseCommand(input);
                return executeCommand(cmd);
            }

            // ==================== Command Info ====================
            
            bool CLIParser::hasCommand(const std::string &name) const
            {
                return commands_.find(name) != commands_.end();
            }

            CommandInfo CLIParser::getCommandInfo(const std::string &name) const
            {
                auto it = commands_.find(name);
                if (it != commands_.end())
                {
                    return it->second;
                }
                return CommandInfo();
            }

            std::vector<CommandInfo> CLIParser::getAllCommands() const
            {
                std::vector<CommandInfo> result;
                for (const auto &pair : commands_)
                {
                    result.push_back(pair.second);
                }
                return result;
            }

            // ==================== Help ====================
            
            void CLIParser::printHelp() const
            {
                std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║     Network Security AI - Command Line Interface          ║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                std::cout << "\nAvailable Commands:\n" << std::endl;
                
                for (const auto &pair : commands_)
                {
                    const CommandInfo &info = pair.second;
                    std::cout << "  " << info.name;
                    
                    // Padding
                    int padding = 20 - info.name.length();
                    for (int i = 0; i < padding; ++i)
                    {
                        std::cout << " ";
                    }
                    
                    std::cout << info.description << std::endl;
                }
                
                std::cout << "\nUse 'help <command>' for detailed information about a command." << std::endl;
                std::cout << std::endl;
            }

            void CLIParser::printCommandHelp(const std::string &name) const
            {
                auto it = commands_.find(name);
                if (it == commands_.end())
                {
                    std::cerr << "Unknown command: " << name << std::endl;
                    return;
                }
                
                const CommandInfo &info = it->second;
                
                std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║  Command: " << info.name;
                
                int padding = 51 - info.name.length();
                for (int i = 0; i < padding; ++i)
                {
                    std::cout << " ";
                }
                std::cout << "║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                
                std::cout << "\nDescription:" << std::endl;
                std::cout << "  " << info.description << std::endl;
                
                std::cout << "\nUsage:" << std::endl;
                std::cout << "  " << info.usage << std::endl;
                
                if (!info.examples.empty())
                {
                    std::cout << "\nExamples:" << std::endl;
                    for (const auto &example : info.examples)
                    {
                        std::cout << "  " << example << std::endl;
                    }
                }
                
                std::cout << std::endl;
            }

            void CLIParser::printVersion() const
            {
                std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║     Network Security AI - Version 1.0.0                   ║" << std::endl;
                std::cout << "║     Deep Learning-based Network Security System           ║" << std::endl;
                std::cout << "║     Copyright (c) 2024                                    ║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                std::cout << std::endl;
            }

            // ==================== Auto-completion ====================
            
            std::vector<std::string> CLIParser::getCompletions(const std::string &prefix) const
            {
                std::vector<std::string> completions;
                
                for (const auto &pair : commands_)
                {
                    if (pair.first.find(prefix) == 0)
                    {
                        completions.push_back(pair.first);
                    }
                }
                
                return completions;
            }

            std::string CLIParser::getClosestCommand(const std::string &name) const
            {
                std::string closest;
                int min_distance = INT_MAX;
                
                for (const auto &pair : commands_)
                {
                    int distance = levenshteinDistance(name, pair.first);
                    if (distance < min_distance && distance <= 3)
                    {
                        min_distance = distance;
                        closest = pair.first;
                    }
                }
                
                return closest;
            }

            // ==================== Helper Functions ====================
            
            std::string CLIParser::trimString(const std::string &str) const
            {
                size_t start = str.find_first_not_of(" \t\n\r");
                if (start == std::string::npos)
                {
                    return "";
                }
                
                size_t end = str.find_last_not_of(" \t\n\r");
                return str.substr(start, end - start + 1);
            }

            bool CLIParser::isQuoted(const std::string &str) const
            {
                return str.size() >= 2 && 
                       ((str.front() == '"' && str.back() == '"') ||
                        (str.front() == '\'' && str.back() == '\''));
            }

            std::string CLIParser::removeQuotes(const std::string &str) const
            {
                if (isQuoted(str))
                {
                    return str.substr(1, str.size() - 2);
                }
                return str;
            }

            int CLIParser::levenshteinDistance(const std::string &s1, const std::string &s2) const
            {
                const size_t len1 = s1.size();
                const size_t len2 = s2.size();
                std::vector<std::vector<int>> d(len1 + 1, std::vector<int>(len2 + 1));
                
                for (size_t i = 0; i <= len1; ++i)
                {
                    d[i][0] = i;
                }
                
                for (size_t j = 0; j <= len2; ++j)
                {
                    d[0][j] = j;
                }
                
                for (size_t i = 1; i <= len1; ++i)
                {
                    for (size_t j = 1; j <= len2; ++j)
                    {
                        int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
                        d[i][j] = std::min({
                            d[i - 1][j] + 1,
                            d[i][j - 1] + 1,
                            d[i - 1][j - 1] + cost
                        });
                    }
                }
                
                return d[len1][len2];
            }

        } // namespace CLI
    }     // namespace Interface
} // namespace NetworkSecurity
