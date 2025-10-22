// src/interfaces/cli/cli_main.cpp
#include "cli_commands.hpp"
#include <iostream>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>

using namespace NetworkSecurity::Interface::CLI;

// Global command manager for signal handler
std::unique_ptr<CommandManager> g_cmd_manager;
bool g_running = true;

void signalHandler(int signum)
{
    std::cout << "\n🛑 Interrupt signal received..." << std::endl;
    g_running = false;
    
    if (g_cmd_manager)
    {
        auto ingress = g_cmd_manager->getPacketIngress();
        if (ingress && ingress->isRunning())
        {
            ingress->stop();
        }
    }
}

void printBanner()
{
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗  ║
║    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝  ║
║    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝   ║
║    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗   ║
║    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗  ║
║    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ║
║                                                                      ║
║              SECURITY AI - Deep Learning Network Security           ║
║                        Version 1.0.0                                 ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;
    
    std::cout << "Type 'help' for available commands, 'exit' to quit.\n" << std::endl;
}

int main(int argc, char *argv[])
{
    // Register signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Print banner
    printBanner();
    
    // Create command manager
    g_cmd_manager = std::make_unique<CommandManager>();
    g_cmd_manager->initialize();
    
    // Check if command provided as argument
    if (argc > 1)
    {
        Command cmd = g_cmd_manager->getParser().parseCommandLine(argc, argv);
        g_cmd_manager->getParser().executeCommand(cmd);
        return 0;
    }
    
    // Interactive mode
    while (g_running)
    {
        // Read command with readline (supports history and auto-completion)
        char *line = readline("nsai> ");
        
        if (!line)
        {
            break;
        }
        
        std::string input(line);
        free(line);
        
        // Skip empty lines
        if (input.empty())
        {
            continue;
        }
        
        // Add to history
        add_history(input.c_str());
        
        // Execute command
        if (!g_cmd_manager->getParser().executeCommand(input))
        {
            // Exit command returns false
            break;
        }
    }
    
    // Cleanup
    std::cout << "\n🧹 Cleaning up..." << std::endl;
    
    auto ingress = g_cmd_manager->getPacketIngress();
    if (ingress && ingress->isRunning())
    {
        ingress->stop();
    }
    
    g_cmd_manager.reset();
    
    std::cout << "✅ Goodbye!\n" << std::endl;
    
    return 0;
}
