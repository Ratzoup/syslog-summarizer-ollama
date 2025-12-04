#include <QApplication>
#include <QStyleFactory>
#include <QFont>
#include <QFile>
#include <QTextStream>
#include <QTranslator>
#include <QLibraryInfo>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer>
#include "gui/MainWindow.hpp"

void loadStyleSheet(QApplication& app) {
    // Try to load dark style sheet
    QFile styleFile(":/styles/dark_style.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        app.setStyleSheet(styleSheet);
    } else {
        // Use Fusion style with dark palette as fallback
        app.setStyle(QStyleFactory::create("Fusion"));
        
        QPalette darkPalette;
        darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::WindowText, Qt::white);
        darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
        darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ToolTipBase, Qt::black);
        darkPalette.setColor(QPalette::ToolTipText, Qt::white);
        darkPalette.setColor(QPalette::Text, Qt::white);
        darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ButtonText, Qt::white);
        darkPalette.setColor(QPalette::BrightText, Qt::red);
        darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::HighlightedText, Qt::black);
        
        darkPalette.setColor(QPalette::Disabled, QPalette::Text, Qt::darkGray);
        darkPalette.setColor(QPalette::Disabled, QPalette::ButtonText, Qt::darkGray);
        
        app.setPalette(darkPalette);
    }
}

void showSplashScreen(QApplication& app) {
    QPixmap pixmap(":/splash/splash.png");
    if (pixmap.isNull()) {
        // Create a simple splash screen if image not found
        pixmap = QPixmap(400, 300);
        pixmap.fill(QColor(53, 53, 53));
    }
    
    QSplashScreen splash(pixmap);
    splash.show();
    
    // Show splash for minimum time
    QTimer::singleShot(1500, &splash, &QWidget::close);
    
    // Process events to show splash
    app.processEvents();
}

int main(int argc, char* argv[]) {
    // Set application attributes
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    
    QApplication app(argc, argv);
    
    // Set application metadata
    app.setApplicationName("Log Summarizer");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("Security Analytics");
    app.setOrganizationDomain("security.example.com");
    
    // Load translations if available
    QTranslator translator;
    if (translator.load(QLocale(), "logsummarizer", "_", ":/translations")) {
        app.installTranslator(&translator);
    }
    
    // Parse command line arguments
    QCommandLineParser parser;
    parser.setApplicationDescription("Log Summarizer - Security Log Analysis Tool");
    parser.addHelpOption();
    parser.addVersionOption();
    
    QCommandLineOption fileOption("f", "Open log file on startup", "file");
    parser.addOption(fileOption);
    
    QCommandLineOption noSplashOption("no-splash", "Disable splash screen");
    parser.addOption(noSplashOption);
    
    QCommandLineOption debugOption("debug", "Enable debug mode");
    parser.addOption(debugOption);
    
    parser.process(app);
    
    // Show splash screen
    if (!parser.isSet(noSplashOption)) {
        showSplashScreen(app);
    }
    
    // Load stylesheet
    loadStyleSheet(app);
    
    // Set font
    QFont font("Segoe UI", 10);
    app.setFont(font);
    
    try {
        // Create and show main window
        MainWindow mainWindow;
        mainWindow.show();
        
        // Open file if specified
        if (parser.isSet(fileOption)) {
            QString filePath = parser.value(fileOption);
            QTimer::singleShot(100, [&mainWindow, filePath]() {
                mainWindow.openFile(filePath);
            });
        }
        
        return app.exec();
        
    } catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Fatal Error",
                            QString("Failed to start application: %1").arg(e.what()));
        return 1;
    }
}