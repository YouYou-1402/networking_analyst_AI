// tests/gui/main.cpp
#include "main_window.hpp"
#include <QApplication>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

int main(int argc, char *argv[])
{
    // Initialize logger
    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            "logs/gui.log", 1024 * 1024 * 10, 3);
        file_sink->set_level(spdlog::level::debug);
        
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("gui", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::debug);
        
        spdlog::set_default_logger(logger);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
        
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
    
    spdlog::info("Starting Network Security AI GUI...");
    spdlog::info("Qt Version: {}", QT_VERSION_STR);
    
    QApplication app(argc, argv);
    
    // Set application info
    app.setApplicationName("Network Security AI");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("NCKH");
    app.setOrganizationDomain("nckh.edu.vn");
    
    // Set style
    app.setStyle("Fusion");
    
    MainWindow window;
    window.show();
    
    spdlog::info("GUI initialized successfully");
    
    int ret = app.exec();
    
    spdlog::info("Application exiting with code: {}", ret);
    
    return ret;
}
