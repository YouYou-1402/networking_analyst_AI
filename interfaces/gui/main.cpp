// src/gui/main.cpp

#include "main_window.hpp"
#include <QApplication>
#include <QStyleFactory>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QFile>
#include <QDir>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <iostream>
#include <unistd.h>
#include <sys/capability.h>

// Check if running with proper permissions
bool checkPermissions()
{
    // Check if root
    if (geteuid() == 0) {
        return true;
    }

    // Check for CAP_NET_RAW capability
    cap_t caps = cap_get_proc();
    if (caps) {
        cap_flag_value_t cap_val;
        if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &cap_val) == 0) {
            cap_free(caps);
            if (cap_val == CAP_SET) {
                return true;
            }
        }
        cap_free(caps);
    }

    return false;
}

// Setup logging
void setupLogging(const QString& logLevel)
{
    try {
        // Create logs directory
        QDir().mkpath("logs");

        // Console sink
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");

        // File sink (rotating)
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            "logs/network_analyzer.log", 
            1024 * 1024 * 10,  // 10MB
            3                   // 3 files
        );
        file_sink->set_level(spdlog::level::debug);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        // Combined logger
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("main", sinks.begin(), sinks.end());
        
        // Set log level
        if (logLevel == "trace") {
            logger->set_level(spdlog::level::trace);
        } else if (logLevel == "debug") {
            logger->set_level(spdlog::level::debug);
        } else if (logLevel == "info") {
            logger->set_level(spdlog::level::info);
        } else if (logLevel == "warn") {
            logger->set_level(spdlog::level::warn);
        } else if (logLevel == "error") {
            logger->set_level(spdlog::level::err);
        } else {
            logger->set_level(spdlog::level::info);
        }

        logger->flush_on(spdlog::level::err);
        spdlog::set_default_logger(logger);

        spdlog::info("========================================");
        spdlog::info("  Network Security Analyzer v1.0.0");
        spdlog::info("========================================");
        spdlog::info("Logging initialized");
        spdlog::info("Log level: {}", logLevel.toStdString());
    }
    catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
}

// Apply stylesheet
void applyStylesheet(QApplication& app, const QString& theme)
{
    if (theme == "dark") {
        QFile file(":/styles/dark.qss");
        if (file.open(QFile::ReadOnly | QFile::Text)) {
            QString stylesheet = QLatin1String(file.readAll());
            app.setStyleSheet(stylesheet);
            file.close();
            spdlog::info("Applied dark theme");
        } else {
            spdlog::warn("Failed to load dark theme stylesheet");
        }
    } else if (theme == "light") {
        QFile file(":/styles/light.qss");
        if (file.open(QFile::ReadOnly | QFile::Text)) {
            QString stylesheet = QLatin1String(file.readAll());
            app.setStyleSheet(stylesheet);
            file.close();
            spdlog::info("Applied light theme");
        } else {
            spdlog::warn("Failed to load light theme stylesheet");
        }
    } else {
        // Use system theme
        spdlog::info("Using system theme");
    }
}

int main(int argc, char *argv[])
{
    // Create application
    QApplication app(argc, argv);
    
    // Set application info
    QApplication::setApplicationName("Network Security Analyzer");
    QApplication::setApplicationVersion("1.0.0");
    QApplication::setOrganizationName("NetworkSecurity");
    QApplication::setOrganizationDomain("networksecurity.local");

    // Command line parser
    QCommandLineParser parser;
    parser.setApplicationDescription("Network Security Analyzer - Packet capture and analysis tool");
    parser.addHelpOption();
    parser.addVersionOption();

    // Add options
    QCommandLineOption logLevelOption(
        QStringList() << "l" << "log-level",
        "Set log level (trace, debug, info, warn, error)",
        "level",
        "info"
    );
    parser.addOption(logLevelOption);

    QCommandLineOption themeOption(
        QStringList() << "t" << "theme",
        "Set theme (dark, light, system)",
        "theme",
        "system"
    );
    parser.addOption(themeOption);

    QCommandLineOption interfaceOption(
        QStringList() << "i" << "interface",
        "Start capture on interface",
        "interface"
    );
    parser.addOption(interfaceOption);

    QCommandLineOption fileOption(
        QStringList() << "f" << "file",
        "Open pcap file",
        "file"
    );
    parser.addOption(fileOption);

    QCommandLineOption noGuiOption(
        QStringList() << "no-gui",
        "Run in command-line mode (no GUI)"
    );
    parser.addOption(noGuiOption);

    // Process arguments
    parser.process(app);

    // Setup logging
    QString logLevel = parser.value(logLevelOption);
    setupLogging(logLevel);

    // Check permissions
    if (!checkPermissions()) {
        spdlog::error("Insufficient permissions!");
        spdlog::error("This application requires root privileges or CAP_NET_RAW capability");
        spdlog::error("Run with: sudo ./NetworkSecurityAnalyzer");
        spdlog::error("Or set capabilities: sudo setcap cap_net_raw+ep ./NetworkSecurityAnalyzer");

        QMessageBox::critical(
            nullptr,
            "Permission Denied",
            "This application requires root privileges or CAP_NET_RAW capability.\n\n"
            "Please run with:\n"
            "  sudo ./NetworkSecurityAnalyzer\n\n"
            "Or set capabilities:\n"
            "  sudo setcap cap_net_raw+ep ./NetworkSecurityAnalyzer"
        );
        return 1;
    }

    spdlog::info("Permission check passed");

    // Apply theme
    QString theme = parser.value(themeOption);
    applyStylesheet(app, theme);

    // Set application style
    app.setStyle(QStyleFactory::create("Fusion"));

    try {
        // Create main window
        NetworkSecurity::GUI::MainWindow mainWindow;
        
        // Handle command line options
        if (parser.isSet(fileOption)) {
            QString file = parser.value(fileOption);
            spdlog::info("Opening file from command line: {}", file.toStdString());
            // TODO: Load file
        }

        if (parser.isSet(interfaceOption)) {
            QString interface = parser.value(interfaceOption);
            spdlog::info("Starting capture on interface: {}", interface.toStdString());
            // TODO: Start capture
        }

        // Show main window
        mainWindow.show();

        spdlog::info("Application started successfully");

        // Run application
        int result = app.exec();

        spdlog::info("Application exiting with code {}", result);
        spdlog::info("========================================");

        return result;
    }
    catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        
        QMessageBox::critical(
            nullptr,
            "Fatal Error",
            QString("An unexpected error occurred:\n\n%1\n\n"
                   "The application will now exit.")
            .arg(e.what())
        );
        
        return 1;
    }
}
