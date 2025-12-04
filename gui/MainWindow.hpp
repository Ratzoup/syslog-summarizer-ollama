#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include <QTabWidget>
#include <QProgressBar>
#include <QStatusBar>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QThread>
#include <memory>
#include "LogEntry.hpp"
#include "SecurityAnalyzer.hpp"
#include "OllamaClient.hpp"

// Forward declarations
class LogViewer;
class AnalysisPanel;
class SettingsDialog;
class AnalysisWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT
    
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    
protected:
    void closeEvent(QCloseEvent *event) override;
    
private slots:
    // File operations
    void openFile();
    void openFolder();
    void saveReport();
    void exportToPDF();
    void exitApplication();
    
    // Analysis operations
    void startAnalysis();
    void stopAnalysis();
    void clearResults();
    
    // Settings
    void showSettings();
    void applySettings();
    
    // Help
    void showAbout();
    void showHelp();
    void checkForUpdates();
    
    // System tray
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void showHideWindow();
    
    // Analysis progress
    void onAnalysisStarted();
    void onAnalysisProgress(int value, const QString& message);
    void onAnalysisCompleted(const QString& summary, 
                           const std::vector<SecurityEvent>& events);
    void onAnalysisError(const QString& error);
    
    // Model operations
    void refreshModels();
    void testOllamaConnection();
    
private:
    // UI Components
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createSystemTray();
    void createCentralWidget();
    
    // Helper methods
    void loadSettings();
    void saveSettings();
    void updateRecentFiles(const QString& filePath);
    void setupConnections();
    void applyStyleSheet();
    
    // Core components
    std::unique_ptr<SecurityAnalyzer> securityAnalyzer_;
    std::unique_ptr<OllamaClient> ollamaClient_;
    
    // GUI Components
    QTabWidget *tabWidget_;
    LogViewer *logViewer_;
    AnalysisPanel *analysisPanel_;
    SettingsDialog *settingsDialog_;
    
    // Thread management
    QThread *analysisThread_;
    AnalysisWorker *analysisWorker_;
    
    // System tray
    QSystemTrayIcon *trayIcon_;
    QMenu *trayMenu_;
    
    // Actions
    QAction *openFileAction_;
    QAction *openFolderAction_;
    QAction *saveReportAction_;
    QAction *exportPDFAction_;
    QAction *exitAction_;
    QAction *analyzeAction_;
    QAction *stopAnalysisAction_;
    QAction *clearAction_;
    QAction *settingsAction_;
    QAction *aboutAction_;
    QAction *helpAction_;
    QAction *refreshModelsAction_;
    QAction *testConnectionAction_;
    
    // Toolbars
    QToolBar *fileToolBar_;
    QToolBar *analysisToolBar_;
    
    // Status bar widgets
    QProgressBar *progressBar_;
    QLabel *statusLabel_;
    
    // Settings
    QString currentLogFile_;
    QString currentModel_;
    bool useLLM_;
    bool minimizeToTray_;
    
    // Constants
    static const int MAX_RECENT_FILES = 10;
};

// Worker thread for analysis
class AnalysisWorker : public QObject {
    Q_OBJECT
    
public:
    AnalysisWorker(const QString& filePath, 
                  LogSource source,
                  bool useLLM,
                  const QString& model,
                  QObject* parent = nullptr);
    
public slots:
    void process();
    
signals:
    void progress(int value, const QString& message);
    void completed(const QString& summary,
                  const std::vector<SecurityEvent>& events);
    void error(const QString& errorMessage);
    
private:
    QString filePath_;
    LogSource source_;
    bool useLLM_;
    QString model_;
    std::unique_ptr<LogParser> parser_;
    std::unique_ptr<SecurityAnalyzer> analyzer_;
    std::unique_ptr<OllamaClient> ollamaClient_;
};

#endif // MAINWINDOW_HPP