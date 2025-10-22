// src/interfaces/cli/cli_parser.hpp
#ifndef NETWORK_SECURITY_CLI_PARSER_HPP
#define NETWORK_SECURITY_CLI_PARSER_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>

namespace NetworkSecurity
{
    namespace Interface
    {
        namespace CLI
        {
            // ==================== Command Structure ====================
            struct Command
            {
                std::string name;
                std::vector<std::string> args;
                std::map<std::string, std::string> options;
                
                Command() = default;
                Command(const std::string &cmd_name) : name(cmd_name) {}
            };

            // ==================== Command Handler ====================
            using CommandHandler = std::function<bool(const Command &cmd)>;

            // ==================== Command Info ====================
            struct CommandInfo
            {
                std::string name;
                std::string description;
                std::string usage;
                std::vector<std::string> examples;
                CommandHandler handler;
                
                CommandInfo() = default;
                CommandInfo(const std::string &n, const std::string &desc, 
                           const std::string &u, CommandHandler h)
                    : name(n), description(desc), usage(u), handler(h)
                {
                }
            };

            // ==================== CLI Parser Class ====================
            class CLIParser
            {
            public:
                CLIParser();
                ~CLIParser();

                // ==================== Command Registration ====================
                void registerCommand(const std::string &name, 
                                   const std::string &description,
                                   const std::string &usage,
                                   CommandHandler handler);
                
                void registerCommand(const CommandInfo &cmd_info);
                
                bool unregisterCommand(const std::string &name);

                // ==================== Command Parsing ====================
                Command parseCommand(const std::string &input);
                Command parseCommandLine(int argc, char *argv[]);
                
                std::vector<std::string> tokenize(const std::string &input);
                
                // ==================== Command Execution ====================
                bool executeCommand(const Command &cmd);
                bool executeCommand(const std::string &input);
                
                // ==================== Command Info ====================
                bool hasCommand(const std::string &name) const;
                CommandInfo getCommandInfo(const std::string &name) const;
                std::vector<CommandInfo> getAllCommands() const;
                
                // ==================== Help ====================
                void printHelp() const;
                void printCommandHelp(const std::string &name) const;
                void printVersion() const;

                // ==================== Auto-completion ====================
                std::vector<std::string> getCompletions(const std::string &prefix) const;
                std::string getClosestCommand(const std::string &name) const;

            private:
                std::map<std::string, CommandInfo> commands_;
                
                std::string trimString(const std::string &str) const;
                bool isQuoted(const std::string &str) const;
                std::string removeQuotes(const std::string &str) const;
                int levenshteinDistance(const std::string &s1, const std::string &s2) const;
            };

        } // namespace CLI
    }     // namespace Interface
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_CLI_PARSER_HPP
