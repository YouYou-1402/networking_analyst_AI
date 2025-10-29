// interfaces/cli/cli_commands.cpp
#include "cli_commands.hpp"
#include "../../src/common/logger.hpp"
#include "../../src/common/network_utils.hpp" 
#include "../../src/common/utils.hpp" 
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace NetworkSecurity
{
    namespace Interface
    {
        namespace CLI
        {
            // ==================== Constructor/Destructor ====================
            
            CommandManager::CommandManager()
                : is_monitoring_(false), stop_monitoring_(false)
            {
            }

            CommandManager::~CommandManager()
            {
                stopMonitoring();
                
                if (packet_ingress_ && packet_ingress_->isRunning())
                {
                    packet_ingress_->stop();
                }
            }

            // ==================== Initialization ====================
            
            void CommandManager::initialize()
            {
                registerAllCommands();
                
                // Create packet ingress instance
                packet_ingress_ = std::make_shared<Core::Layer1::PacketIngress>();
            }

            void CommandManager::registerAllCommands()
            {
                // Help command
                parser_.registerCommand("help", 
                    "Show help information",
                    "help [command]",
                    [this](const Command &cmd) { return handleHelp(cmd); });
                
                // Version command
                parser_.registerCommand("version",
                    "Show version information",
                    "version",
                    [this](const Command &cmd) { return handleVersion(cmd); });
                
                // Exit command
                parser_.registerCommand("exit",
                    "Exit the program",
                    "exit",
                    [this](const Command &cmd) { return handleExit(cmd); });
                
                parser_.registerCommand("quit",
                    "Exit the program",
                    "quit",
                    [this](const Command &cmd) { return handleExit(cmd); });
                
                // Clear command
                parser_.registerCommand("clear",
                    "Clear the screen",
                    "clear",
                    [this](const Command &cmd) { return handleClear(cmd); });
                
                // Packet Ingress Commands
                parser_.registerCommand("start",
                    "Start packet capture",
                    "start -i <interface> [-f <filter>] [-t <threads>] [-q <queue_size>] [-x]",
                    [this](const Command &cmd) { return handleStart(cmd); });
                
                parser_.registerCommand("stop",
                    "Stop packet capture",
                    "stop",
                    [this](const Command &cmd) { return handleStop(cmd); });
                
                parser_.registerCommand("status",
                    "Show capture status",
                    "status",
                    [this](const Command &cmd) { return handleStatus(cmd); });
                
                parser_.registerCommand("stats",
                    "Show capture statistics",
                    "stats [-r]",
                    [this](const Command &cmd) { return handleStats(cmd); });
                
                parser_.registerCommand("reset",
                    "Reset statistics",
                    "reset",
                    [this](const Command &cmd) { return handleReset(cmd); });
                
                parser_.registerCommand("config",
                    "Show or modify configuration",
                    "config [key] [value]",
                    [this](const Command &cmd) { return handleConfig(cmd); });
                
                parser_.registerCommand("filter",
                    "Set BPF filter",
                    "filter <expression>",
                    [this](const Command &cmd) { return handleFilter(cmd); });
                
                // XDP Commands
                parser_.registerCommand("xdp-load",
                    "Load XDP filter",
                    "xdp-load -i <interface>",
                    [this](const Command &cmd) { return handleXDPLoad(cmd); });
                
                parser_.registerCommand("xdp-unload",
                    "Unload XDP filter",
                    "xdp-unload",
                    [this](const Command &cmd) { return handleXDPUnload(cmd); });
                
                parser_.registerCommand("xdp-stats",
                    "Show XDP statistics",
                    "xdp-stats",
                    [this](const Command &cmd) { return handleXDPStats(cmd); });
                
                parser_.registerCommand("blacklist",
                    "Manage IP blacklist",
                    "blacklist <add|remove|list> [ip]",
                    [this](const Command &cmd) { return handleBlacklist(cmd); });
                
                // Monitoring Commands
                parser_.registerCommand("monitor",
                    "Start real-time monitoring",
                    "monitor [-i <interval>]",
                    [this](const Command &cmd) { return handleMonitor(cmd); });
                
                parser_.registerCommand("capture",
                    "Capture packets to file",
                    "capture -o <output_file> [-c <count>] [-t <timeout>]",
                    [this](const Command &cmd) { return handleCapture(cmd); });
                
                parser_.registerCommand("analyze",
                    "Analyze captured packets",
                    "analyze <file>",
                    [this](const Command &cmd) { return handleAnalyze(cmd); });
            }

            // ==================== Command Handlers ====================
            
            bool CommandManager::handleHelp(const Command &cmd)
            {
                if (cmd.args.empty())
                {
                    parser_.printHelp();
                }
                else
                {
                    parser_.printCommandHelp(cmd.args[0]);
                }
                return true;
            }

            bool CommandManager::handleVersion(const Command &cmd)
            {
                parser_.printVersion();
                return true;
            }

            bool CommandManager::handleExit(const Command &cmd)
            {
                std::cout << "\n👋 Goodbye!\n" << std::endl;
                return false; // Signal to exit
            }

            bool CommandManager::handleClear(const Command &cmd)
            {
                #ifdef _WIN32
                    system("cls");
                #else
                    system("clear");
                #endif
                return true;
            }

            bool CommandManager::handleStart(const Command &cmd)
            {
                if (packet_ingress_->isRunning())
                {
                    std::cout << "⚠️  Packet capture is already running" << std::endl;
                    return true;
                }
                
                // Parse options
                Core::Layer1::IngressConfig config;
                
                auto it = cmd.options.find("-i");
                if (it != cmd.options.end())
                {
                    config.interface_name = it->second;
                }
                else
                {
                    std::cerr << "❌ Interface not specified. Use -i <interface>" << std::endl;
                    return true;
                }
                
                it = cmd.options.find("-f");
                if (it != cmd.options.end())
                {
                    config.capture_filter = it->second;
                }
                
                it = cmd.options.find("-t");
                if (it != cmd.options.end())
                {
                    config.worker_threads = std::stoi(it->second);
                }
                
                it = cmd.options.find("-q");
                if (it != cmd.options.end())
                {
                    config.packet_queue_size = std::stoul(it->second);
                }
                
                bool enable_xdp = cmd.options.find("-x") != cmd.options.end();
                
                // Initialize
                std::cout << "🔧 Initializing packet ingress..." << std::endl;
                if (!packet_ingress_->initialize(config))
                {
                    std::cerr << "❌ Failed to initialize packet ingress" << std::endl;
                    return true;
                }
                
                // Setup XDP if requested
                if (enable_xdp)
                {
                    std::cout << "🔧 Loading XDP filter..." << std::endl;
                    xdp_filter_ = std::make_shared<Core::Layer1::XDPFilter>();
                    
                    Core::Layer1::XDPFilterConfig xdp_config;
                    xdp_config.interface_name = config.interface_name;
                    
                    if (xdp_filter_->initialize(xdp_config))
                    {
                        packet_ingress_->setXDPFilter(xdp_filter_);
                        std::cout << "✅ XDP filter loaded" << std::endl;
                    }
                    else
                    {
                        std::cerr << "⚠️  Failed to load XDP filter" << std::endl;
                    }
                }
                
                // Register callback
                packet_ingress_->registerPacketCallback([](const Core::Layer1::PacketBuffer &packet) {
                    // Packet processing callback
                    static uint64_t count = 0;
                    count++;
                });
                
                // Start capture
                std::cout << "🎯 Starting packet capture..." << std::endl;
                if (packet_ingress_->start())
                {
                    std::cout << "✅ Packet capture started on " << config.interface_name << std::endl;
                    if (!config.capture_filter.empty())
                    {
                        std::cout << "   Filter: " << config.capture_filter << std::endl;
                    }
                }
                else
                {
                    std::cerr << "❌ Failed to start packet capture" << std::endl;
                }
                
                return true;
            }

            bool CommandManager::handleStop(const Command &cmd)
            {
                if (!packet_ingress_->isRunning())
                {
                    std::cout << "⚠️  Packet capture is not running" << std::endl;
                    return true;
                }
                
                std::cout << "🛑 Stopping packet capture..." << std::endl;
                packet_ingress_->stop();
                std::cout << "✅ Packet capture stopped" << std::endl;
                
                // Print final stats
                packet_ingress_->updateStatistics();
                packet_ingress_->printStatistics();
                
                return true;
            }

            bool CommandManager::handleStatus(const Command &cmd)
            {
                printPacketIngressStatus();
                
                if (xdp_filter_)
                {
                    std::cout << std::endl;
                    printXDPStatus();
                }
                
                return true;
            }

            bool CommandManager::handleStats(const Command &cmd)
            {
                bool reset = cmd.options.find("-r") != cmd.options.end();
                
                if (reset)
                {
                    packet_ingress_->resetStatistics();
                    std::cout << "✅ Statistics reset" << std::endl;
                }
                
                packet_ingress_->updateStatistics();
                packet_ingress_->printStatistics();
                
                return true;
            }

            bool CommandManager::handleReset(const Command &cmd)
            {
                packet_ingress_->resetStatistics();
                
                if (xdp_filter_)
                {
                    xdp_filter_->resetStatistics();
                }
                
                std::cout << "✅ All statistics reset" << std::endl;
                return true;
            }

            bool CommandManager::handleConfig(const Command &cmd)
            {
                auto config = packet_ingress_->getConfig();
                
                std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║              Packet Ingress Configuration                 ║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                std::cout << "\nInterface:        " << config.interface_name << std::endl;
                std::cout << "Capture Filter:   " << (config.capture_filter.empty() ? "(none)" : config.capture_filter) << std::endl;
                std::cout << "Snaplen:          " << config.snaplen << std::endl;
                std::cout << "Timeout:          " << config.timeout_ms << " ms" << std::endl;
                std::cout << "Buffer Size:      " << config.buffer_size << " bytes" << std::endl;
                std::cout << "Promiscuous:      " << (config.promiscuous_mode ? "Yes" : "No") << std::endl;
                std::cout << "Worker Threads:   " << config.worker_threads << std::endl;
                std::cout << "Queue Size:       " << config.packet_queue_size << std::endl;
                std::cout << "XDP Filter:       " << (config.enable_xdp_filter ? "Enabled" : "Disabled") << std::endl;
                std::cout << std::endl;
                
                return true;
            }

            bool CommandManager::handleFilter(const Command &cmd)
            {
                if (cmd.args.empty())
                {
                    std::cerr << "❌ Filter expression required" << std::endl;
                    return true;
                }
                
                std::string filter = cmd.args[0];
                
                if (packet_ingress_->setFilter(filter))
                {
                    std::cout << "✅ Filter set: " << filter << std::endl;
                }
                else
                {
                    std::cerr << "❌ Failed to set filter" << std::endl;
                }
                
                return true;
            }

            bool CommandManager::handleXDPLoad(const Command &cmd)
            {
                auto it = cmd.options.find("-i");
                if (it == cmd.options.end())
                {
                    std::cerr << "❌ Interface not specified. Use -i <interface>" << std::endl;
                    return true;
                }
                
                std::string interface = it->second;
                
                std::cout << "🔧 Loading XDP filter on " << interface << "..." << std::endl;
                
                xdp_filter_ = std::make_shared<Core::Layer1::XDPFilter>();
                
                Core::Layer1::XDPFilterConfig config;
                config.interface_name = interface;
                
                if (xdp_filter_->initialize(config))
                {
                    std::cout << "✅ XDP filter loaded successfully" << std::endl;
                    
                    if (packet_ingress_)
                    {
                        packet_ingress_->setXDPFilter(xdp_filter_);
                    }
                }
                else
                {
                    std::cerr << "❌ Failed to load XDP filter" << std::endl;
                    xdp_filter_ = nullptr;
                }
                
                return true;
            }

            bool CommandManager::handleXDPUnload(const Command &cmd)
            {
                if (!xdp_filter_)
                {
                    std::cout << "⚠️  XDP filter is not loaded" << std::endl;
                    return true;
                }
                
                std::cout << "🛑 Unloading XDP filter..." << std::endl;
                xdp_filter_->shutdown();
                xdp_filter_ = nullptr;
                std::cout << "✅ XDP filter unloaded" << std::endl;
                
                return true;
            }

            bool CommandManager::handleXDPStats(const Command &cmd)
            {
                if (!xdp_filter_)
                {
                    std::cout << "⚠️  XDP filter is not loaded" << std::endl;
                    return true;
                }
                
                xdp_filter_->updateStatistics();
                xdp_filter_->printStatistics();
                
                return true;
            }

            bool CommandManager::handleBlacklist(const Command &cmd)
            {
                if (!xdp_filter_)
                {
                    std::cout << "⚠️  XDP filter is not loaded" << std::endl;
                    return true;
                }
                
                if (cmd.args.empty())
                {
                    std::cerr << "❌ Action required: add, remove, or list" << std::endl;
                    return true;
                }
                
                std::string action = cmd.args[0];
                
                if (action == "add")
                {
                    if (cmd.args.size() < 2)
                    {
                        std::cerr << "❌ IP address required" << std::endl;
                        return true;
                    }
                    
                    std::string ip = cmd.args[1];
                    uint32_t ip_int = Common::NetworkUtils::ipStringToInt(ip);
                    
                    if (xdp_filter_->addIPToBlacklist(ip_int, "CLI add", true))
                    {
                        std::cout << "✅ Added " << ip << " to blacklist" << std::endl;
                    }
                    else
                    {
                        std::cerr << "❌ Failed to add IP to blacklist" << std::endl;
                    }
                }
                else if (action == "remove")
                {
                    if (cmd.args.size() < 2)
                    {
                        std::cerr << "❌ IP address required" << std::endl;
                        return true;
                    }
                    
                    std::string ip = cmd.args[1];
                    uint32_t ip_int = Common::NetworkUtils::ipStringToInt(ip);
                    
                    if (xdp_filter_->removeIPFromBlacklist(ip_int))
                    {
                        std::cout << "✅ Removed " << ip << " from blacklist" << std::endl;
                    }
                    else
                    {
                        std::cerr << "❌ Failed to remove IP from blacklist" << std::endl;
                    }
                }
                else if (action == "list")
                {
                    std::cout << "📋 IP Blacklist: (feature not fully implemented)" << std::endl;
                }
                else
                {
                    std::cerr << "❌ Unknown action: " << action << std::endl;
                }
                
                return true;
            }

            bool CommandManager::handleMonitor(const Command &cmd)
            {
                if (is_monitoring_)
                {
                    std::cout << "⚠️  Monitoring is already running. Press Ctrl+C to stop." << std::endl;
                    return true;
                }
                
                int interval = 1;
                auto it = cmd.options.find("-i");
                if (it != cmd.options.end())
                {
                    interval = std::stoi(it->second);
                }
                
                std::cout << "📊 Starting real-time monitoring (interval: " << interval << "s)" << std::endl;
                std::cout << "Press Ctrl+C to stop..." << std::endl;
                
                startMonitoring();
                
                return true;
            }

            bool CommandManager::handleCapture(const Command &cmd)
            {
                std::cout << "📹 Capture feature not yet implemented" << std::endl;
                return true;
            }

            bool CommandManager::handleAnalyze(const Command &cmd)
            {
                std::cout << "🔍 Analyze feature not yet implemented" << std::endl;
                return true;
            }

            // ==================== Helper Functions ====================
            
            void CommandManager::printPacketIngressStatus()
            {
                std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║            Packet Ingress Status                          ║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                
                std::cout << "\nStatus:           " << (packet_ingress_->isRunning() ? "🟢 Running" : "🔴 Stopped") << std::endl;
                std::cout << "Capturing:        " << (packet_ingress_->isCapturing() ? "Yes" : "No") << std::endl;
                std::cout << "Interface:        " << packet_ingress_->getInterfaceName() << std::endl;
                std::cout << "Queue Size:       " << packet_ingress_->getQueueSize() << std::endl;
                std::cout << std::endl;
            }

            void CommandManager::printXDPStatus()
            {
                std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
                std::cout << "║                XDP Filter Status                          ║" << std::endl;
                std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                
                std::cout << "\nStatus:           " << (xdp_filter_->isRunning() ? "🟢 Running" : "🔴 Stopped") << std::endl;
                std::cout << "Attached:         " << (xdp_filter_->isAttached() ? "Yes" : "No") << std::endl;
                std::cout << "Interface:        " << xdp_filter_->getInterfaceName() << std::endl;
                std::cout << "Interface Index:  " << xdp_filter_->getInterfaceIndex() << std::endl;
                std::cout << std::endl;
            }

            void CommandManager::startMonitoring()
            {
                is_monitoring_ = true;
                stop_monitoring_ = false;
                
                monitor_thread_ = std::thread([this]() {
                    while (!stop_monitoring_)
                    {
                        #ifdef _WIN32
                            system("cls");
                        #else
                            system("clear");
                        #endif
                        
                        std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
                        std::cout << "║          Real-time Packet Capture Monitor                 ║" << std::endl;
                        std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
                        
                        packet_ingress_->updateStatistics();
                        auto stats = packet_ingress_->getStatistics();
                        
                        std::cout << "\n📊 Statistics:" << std::endl;
                        std::cout << "  Total Packets:    " << stats.total_packets_received << std::endl;
                        std::cout << "  Total Bytes:      " << stats.total_bytes_received << std::endl;
                        std::cout << "  Packets/sec:      " << std::fixed << std::setprecision(2) << stats.packets_per_second << std::endl;
                        std::cout << "  Bytes/sec:        " << std::fixed << std::setprecision(2) << stats.bytes_per_second << std::endl;
                        std::cout << "  Queue Size:       " << packet_ingress_->getQueueSize() << std::endl;
                        std::cout << "  Dropped:          " << stats.packets_dropped << std::endl;
                        std::cout << "  Queue Full Drops: " << stats.queue_full_drops << std::endl;
                        
                        std::cout << "\nPress Ctrl+C to stop monitoring..." << std::endl;
                        
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }
                    
                    is_monitoring_ = false;
                });
            }

            void CommandManager::stopMonitoring()
            {
                if (is_monitoring_)
                {
                    stop_monitoring_ = true;
                    if (monitor_thread_.joinable())
                    {
                        monitor_thread_.join();
                    }
                }
            }

        } // namespace CLI
    }     // namespace Interface
} // namespace NetworkSecurity
