// src/interfaces/cli/cli_commands.hpp
#ifndef NETWORK_SECURITY_CLI_COMMANDS_HPP
#define NETWORK_SECURITY_CLI_COMMANDS_HPP

#include "cli_parser.hpp"
#include "../../src/core/layer1/packet_ingress.hpp"
#include "../../src/core/layer1/xdp_filter.hpp"
#include "../../src/common/network_utils.hpp" 
#include "../../src/common/utils.hpp" 
#include <memory>

namespace NetworkSecurity
{
    namespace Interface
    {
        namespace CLI
        {
            // ==================== Command Manager ====================
            class CommandManager
            {
            public:
                CommandManager();
                ~CommandManager();

                void initialize();
                void registerAllCommands();
                
                CLIParser& getParser() { return parser_; }
                
                // ==================== Packet Ingress Management ====================
                std::shared_ptr<Core::Layer1::PacketIngress> getPacketIngress() { return packet_ingress_; }
                std::shared_ptr<Core::Layer1::XDPFilter> getXDPFilter() { return xdp_filter_; }

            private:
                // ==================== Command Handlers ====================
                bool handleHelp(const Command &cmd);
                bool handleVersion(const Command &cmd);
                bool handleExit(const Command &cmd);
                bool handleClear(const Command &cmd);
                
                // Packet Ingress Commands
                bool handleStart(const Command &cmd);
                bool handleStop(const Command &cmd);
                bool handleStatus(const Command &cmd);
                bool handleStats(const Command &cmd);
                bool handleReset(const Command &cmd);
                bool handleConfig(const Command &cmd);
                bool handleFilter(const Command &cmd);
                
                // XDP Commands
                bool handleXDPLoad(const Command &cmd);
                bool handleXDPUnload(const Command &cmd);
                bool handleXDPStats(const Command &cmd);
                bool handleBlacklist(const Command &cmd);
                
                // Monitoring Commands
                bool handleMonitor(const Command &cmd);
                bool handleCapture(const Command &cmd);
                bool handleAnalyze(const Command &cmd);
                
                // Helper functions
                void printPacketIngressStatus();
                void printXDPStatus();
                void startMonitoring();
                void stopMonitoring();

                CLIParser parser_;
                
                std::shared_ptr<Core::Layer1::PacketIngress> packet_ingress_;
                std::shared_ptr<Core::Layer1::XDPFilter> xdp_filter_;
                
                bool is_monitoring_;
                std::thread monitor_thread_;
                std::atomic<bool> stop_monitoring_;
            };

        } // namespace CLI
    }     // namespace Interface
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_CLI_COMMANDS_HPP
