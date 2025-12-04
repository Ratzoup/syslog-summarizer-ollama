#include "MainWindow.hpp"
#include "LogViewer.hpp"
#include "AnalysisPanel.hpp"
#include "SettingsDialog.hpp"
#include "AboutDialog.hpp"
#include "StatusBar.hpp"
#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QToolBar>
#include <QMenuBar>
#include <QStatusBar>
#include <QProgressBar>
#include <QLabel>
#include <QTabWidget>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QSettings>
#include <QStyleFactory>
#include <QThread>
#include <QDesktopServices>
#include <QUrl>
#include <QTimer>
#include <QDateTime>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QTextEdit>
#include <QSplitter>
#include <QTableView>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QStyledItemDelegate>
#include <QPainter>
#include <QStyleOptionViewItem>
#include <QIcon>
#include <QPixmap>
#include <QFont>
#include <QFontMetrics>
#include <QPrinter>
#include <QPrintDialog>
#include <QTextDocument>
#include <QFile>
#include <QTextStream>
#include <QDir>
#include <QProcess>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslConfiguration>
#include <QFileInfo>

// Custom delegate for risk score visualization
class RiskScoreDelegate : public QStyledItemDelegate {
public:
    RiskScoreDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}
    
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override {
        if (index.column() == 2) { // Risk score column
            int score = index.data(Qt::DisplayRole).toInt();
            
            // Draw background
            painter->save();
            
            QRect rect = option.rect.adjusted(2, 2, -2, -2);
            
            // Color based on risk score
            QColor bgColor;
            if (score >= 8) bgColor = Qt::red;
            else if (score >= 5) bgColor = QColor(255, 165, 0); // Orange
            else if (score >= 3) bgColor = Qt::yellow;
            else bgColor = Qt::green;
            
            painter->setBrush(bgColor);
            painter->setPen(Qt::black);
            painter->drawRect(rect);
            
            // Draw score text
            painter->setPen(Qt::black);
            QFont font = painter->font();
            font.setBold(true);
            painter->setFont(font);
            painter->drawText(rect, Qt::AlignCenter, QString::number(score));
            
            painter->restore();
        } else {
            QStyledItemDelegate::paint(painter, option, index);
        }
    }
    
    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override {
        if (index.column() == 2) {
            return QSize(50, option.rect.height());
        }
        return QStyledItemDelegate::sizeHint(option, index);
    }
};

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      currentModel_("llama3"),
      useLLM_(true),
      minimizeToTray_(true) {
    
    // Set window properties
    setWindowTitle("Log Summarizer - Security Analysis Tool");
    setWindowIcon(QIcon(":/icons/app_icon.png"));
    setMinimumSize(1200, 800);
    
    // Initialize core components
    securityAnalyzer_ = std::make_unique<SecurityAnalyzer>();
    ollamaClient_ = std::make_unique<OllamaClient>();
    
    // Create GUI
    createActions();
    createMenus();
    createToolBars();
    createCentralWidget();
    createStatusBar();
    createSystemTray();
    
    // Apply styling
    applyStyleSheet();
    
    // Load settings
    loadSettings();
    
    // Setup connections
    setupConnections();
    
    // Test OLLAMA connection
    QTimer::singleShot(1000, this, &MainWindow::testOllamaConnection);
}

MainWindow::~MainWindow() {
    saveSettings();
    
    if (analysisThread_) {
        analysisThread_->quit();
        analysisThread_->wait();
    }
}

void MainWindow::createActions() {
    // File actions
    openFileAction_ = new QAction(QIcon(":/icons/open_file.png"), tr("&Open Log File..."), this);
    openFileAction_->setShortcut(QKeySequence::Open);
    openFileAction_->setStatusTip(tr("Open a log file for analysis"));
    
    openFolderAction_ = new QAction(QIcon(":/icons/open_folder.png"), tr("Open &Folder..."), this);
    openFolderAction_->setShortcut(Qt::CTRL | Qt::SHIFT | Qt::Key_O);
    openFolderAction_->setStatusTip(tr("Open a folder containing log files"));
    
    saveReportAction_ = new QAction(QIcon(":/icons/save.png"), tr("&Save Report..."), this);
    saveReportAction_->setShortcut(QKeySequence::Save);
    saveReportAction_->setStatusTip(tr("Save the current analysis report"));
    saveReportAction_->setEnabled(false);
    
    exportPDFAction_ = new QAction(QIcon(":/icons/pdf.png"), tr("Export to &PDF..."), this);
    exportPDFAction_->setStatusTip(tr("Export report to PDF format"));
    exportPDFAction_->setEnabled(false);
    
    exitAction_ = new QAction(tr("E&xit"), this);
    exitAction_->setShortcut(QKeySequence::Quit);
    exitAction_->setStatusTip(tr("Exit the application"));
    
    // Analysis actions
    analyzeAction_ = new QAction(QIcon(":/icons/analyze.png"), tr("&Start Analysis"), this);
    analyzeAction_->setShortcut(Qt::Key_F5);
    analyzeAction_->setStatusTip(tr("Start analyzing the loaded log file"));
    analyzeAction_->setEnabled(false);
    
    stopAnalysisAction_ = new QAction(QIcon(":/icons/stop.png"), tr("&Stop Analysis"), this);
    stopAnalysisAction_->setStatusTip(tr("Stop the current analysis"));
    stopAnalysisAction_->setEnabled(false);
    
    clearAction_ = new QAction(QIcon(":/icons/clear.png"), tr("&Clear Results"), this);
    clearAction_->setStatusTip(tr("Clear all analysis results"));
    clearAction_->setEnabled(false);
    
    // Settings actions
    settingsAction_ = new QAction(QIcon(":/icons/settings.png"), tr("&Settings..."), this);
    settingsAction_->setStatusTip(tr("Configure application settings"));
    
    refreshModelsAction_ = new QAction(QIcon(":/icons/refresh.png"), tr("&Refresh Models"), this);
    refreshModelsAction_->setStatusTip(tr("Refresh available OLLAMA models"));
    
    testConnectionAction_ = new QAction(QIcon(":/icons/test.png"), tr("&Test Connection"), this);
    testConnectionAction_->setStatusTip(tr("Test OLLAMA connection"));
    
    // Help actions
    aboutAction_ = new QAction(tr("&About"), this);
    aboutAction_->setStatusTip(tr("Show information about this application"));
    
    helpAction_ = new QAction(QIcon(":/icons/help.png"), tr("&Help"), this);
    helpAction_->setShortcut(QKeySequence::HelpContents);
    helpAction_->setStatusTip(tr("Show help documentation"));
}

void MainWindow::createMenus() {
    // File menu
    QMenu* fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(openFileAction_);
    fileMenu->addAction(openFolderAction_);
    fileMenu->addSeparator();
    
    // Recent files submenu
    QMenu* recentMenu = fileMenu->addMenu(tr("Recent Files"));
    // Recent files will be populated dynamically
    
    fileMenu->addSeparator();
    fileMenu->addAction(saveReportAction_);
    fileMenu->addAction(exportPDFAction_);
    fileMenu->addSeparator();
    fileMenu->addAction(exitAction_);
    
    // Analysis menu
    QMenu* analysisMenu = menuBar()->addMenu(tr("&Analysis"));
    analysisMenu->addAction(analyzeAction_);
    analysisMenu->addAction(stopAnalysisAction_);
    analysisMenu->addSeparator();
    analysisMenu->addAction(clearAction_);
    analysisMenu->addSeparator();
    
    QMenu* logTypeMenu = analysisMenu->addMenu(tr("Log Type"));
    // Log type actions will be created dynamically
    
    // Tools menu
    QMenu* toolsMenu = menuBar()->addMenu(tr("&Tools"));
    toolsMenu->addAction(refreshModelsAction_);
    toolsMenu->addAction(testConnectionAction_);
    toolsMenu->addSeparator();
    toolsMenu->addAction(settingsAction_);
    
    // View menu
    QMenu* viewMenu = menuBar()->addMenu(tr("&View"));
    // View options will be added dynamically
    
    // Help menu
    QMenu* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(helpAction_);
    helpMenu->addSeparator();
    helpMenu->addAction(aboutAction_);
}

void MainWindow::createToolBars() {
    // File toolbar
    fileToolBar_ = addToolBar(tr("File"));
    fileToolBar_->setObjectName("FileToolBar");
    fileToolBar_->addAction(openFileAction_);
    fileToolBar_->addAction(saveReportAction_);
    fileToolBar_->addSeparator();
    
    // Analysis toolbar
    analysisToolBar_ = addToolBar(tr("Analysis"));
    analysisToolBar_->setObjectName("AnalysisToolBar");
    analysisToolBar_->addAction(analyzeAction_);
    analysisToolBar_->addAction(stopAnalysisAction_);
    analysisToolBar_->addAction(clearAction_);
    analysisToolBar_->addSeparator();
    analysisToolBar_->addAction(refreshModelsAction_);
    analysisToolBar_->addAction(testConnectionAction_);
}

void MainWindow::createCentralWidget() {
    // Create main splitter
    QSplitter* mainSplitter = new QSplitter(Qt::Horizontal, this);
    
    // Create left panel (log viewer)
    logViewer_ = new LogViewer(this);
    mainSplitter->addWidget(logViewer_);
    
    // Create right panel (analysis results)
    analysisPanel_ = new AnalysisPanel(this);
    mainSplitter->addWidget(analysisPanel_);
    
    // Set splitter sizes
    mainSplitter->setSizes({400, 600});
    
    // Create tab widget for additional views
    tabWidget_ = new QTabWidget(this);
    tabWidget_->addTab(mainSplitter, tr("Analysis"));
    
    // Add statistics tab (will be populated later)
    QWidget* statsTab = new QWidget();
    tabWidget_->addTab(statsTab, tr("Statistics"));
    
    // Add raw data tab
    QTextEdit* rawDataView = new QTextEdit();
    rawDataView->setReadOnly(true);
    rawDataView->setFont(QFont("Monospace", 10));
    tabWidget_->addTab(rawDataView, tr("Raw Data"));
    
    setCentralWidget(tabWidget_);
}

void MainWindow::createStatusBar() {
    statusBar()->setObjectName("StatusBar");
    
    // Progress bar
    progressBar_ = new QProgressBar();
    progressBar_->setRange(0, 100);
    progressBar_->setTextVisible(true);
    progressBar_->setFormat("%p%");
    progressBar_->setMaximumWidth(200);
    progressBar_->setVisible(false);
    
    // Status label
    statusLabel_ = new QLabel(tr("Ready"));
    statusLabel_->setMinimumWidth(300);
    
    // Connection status
    QLabel* connectionStatus = new QLabel();
    connectionStatus->setObjectName("ConnectionStatus");
    connectionStatus->setText(tr("❌ OLLAMA: Disconnected"));
    connectionStatus->setToolTip(tr("Click to test connection"));
    
    // Add widgets to status bar
    statusBar()->addWidget(statusLabel_, 1);
    statusBar()->addWidget(progressBar_);
    statusBar()->addPermanentWidget(connectionStatus);
    
    // Make connection status clickable
    connectionStatus->setCursor(Qt::PointingHandCursor);
    connect(connectionStatus, &QLabel::linkActivated, 
            this, &MainWindow::testOllamaConnection);
}

void MainWindow::createSystemTray() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        return;
    }
    
    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setIcon(QIcon(":/icons/app_icon.png"));
    trayIcon_->setToolTip("Log Summarizer");
    
    // Create tray menu
    trayMenu_ = new QMenu(this);
    trayMenu_->addAction(tr("Show/Hide"), this, &MainWindow::showHideWindow);
    trayMenu_->addSeparator();
    trayMenu_->addAction(analyzeAction_);
    trayMenu_->addSeparator();
    trayMenu_->addAction(exitAction_);
    
    trayIcon_->setContextMenu(trayMenu_);
    trayIcon_->show();
    
    connect(trayIcon_, &QSystemTrayIcon::activated,
            this, &MainWindow::trayIconActivated);
}

void MainWindow::applyStyleSheet() {
    QFile styleFile(":/styles/dark_style.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        qApp->setStyleSheet(styleSheet);
    } else {
        // Fallback to a default dark theme
        qApp->setStyle(QStyleFactory::create("Fusion"));
        
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
        
        qApp->setPalette(darkPalette);
    }
}

void MainWindow::setupConnections() {
    // File actions
    connect(openFileAction_, &QAction::triggered, this, &MainWindow::openFile);
    connect(openFolderAction_, &QAction::triggered, this, &MainWindow::openFolder);
    connect(saveReportAction_, &QAction::triggered, this, &MainWindow::saveReport);
    connect(exportPDFAction_, &QAction::triggered, this, &MainWindow::exportToPDF);
    connect(exitAction_, &QAction::triggered, this, &MainWindow::exitApplication);
    
    // Analysis actions
    connect(analyzeAction_, &QAction::triggered, this, &MainWindow::startAnalysis);
    connect(stopAnalysisAction_, &QAction::triggered, this, &MainWindow::stopAnalysis);
    connect(clearAction_, &QAction::triggered, this, &MainWindow::clearResults);
    
    // Settings actions
    connect(settingsAction_, &QAction::triggered, this, &MainWindow::showSettings);
    connect(refreshModelsAction_, &QAction::triggered, this, &MainWindow::refreshModels);
    connect(testConnectionAction_, &QAction::triggered, this, &MainWindow::testOllamaConnection);
    
    // Help actions
    connect(aboutAction_, &QAction::triggered, this, &MainWindow::showAbout);
    connect(helpAction_, &QAction::triggered, this, &MainWindow::showHelp);
    
    // Log viewer signals
    connect(logViewer_, &LogViewer::analysisRequested, this, &MainWindow::startAnalysis);
}

void MainWindow::openFile() {
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Open Log File"),
        QDir::homePath(),
        tr("Log Files (*.log *.txt *.json *.csv *.evtx *.xml);;All Files (*)")
    );
    
    if (!filePath.isEmpty()) {
        currentLogFile_ = filePath;
        logViewer_->loadFile(filePath);
        analyzeAction_->setEnabled(true);
        updateRecentFiles(filePath);
        statusLabel_->setText(tr("Loaded: %1").arg(QFileInfo(filePath).fileName()));
    }
}

void MainWindow::openFolder() {
    QString folderPath = QFileDialog::getExistingDirectory(
        this,
        tr("Open Log Folder"),
        QDir::homePath()
    );
    
    if (!folderPath.isEmpty()) {
        // Process all log files in folder
        QDir dir(folderPath);
        QStringList logFiles = dir.entryList(
            {"*.log", "*.txt", "*.json", "*.csv", "*.evtx", "*.xml"},
            QDir::Files
        );
        
        if (logFiles.isEmpty()) {
            QMessageBox::information(this, tr("No Log Files"),
                                   tr("No log files found in the selected folder."));
            return;
        }
        
        // Show selection dialog
        QDialog selectionDialog(this);
        selectionDialog.setWindowTitle(tr("Select Log Files"));
        selectionDialog.setMinimumSize(500, 400);
        
        QVBoxLayout* layout = new QVBoxLayout(&selectionDialog);
        
        QListWidget* fileList = new QListWidget();
        fileList->setSelectionMode(QAbstractItemView::MultiSelection);
        
        foreach (const QString& file, logFiles) {
            QListWidgetItem* item = new QListWidgetItem(file);
            item->setCheckState(Qt::Checked);
            item->setData(Qt::UserRole, dir.filePath(file));
            fileList->addItem(item);
        }
        
        layout->addWidget(new QLabel(tr("Select log files to analyze:")));
        layout->addWidget(fileList);
        
        QDialogButtonBox* buttonBox = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel
        );
        layout->addWidget(buttonBox);
        
        connect(buttonBox, &QDialogButtonBox::accepted, &selectionDialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &selectionDialog, &QDialog::reject);
        
        if (selectionDialog.exec() == QDialog::Accepted) {
            QStringList selectedFiles;
            for (int i = 0; i < fileList->count(); ++i) {
                QListWidgetItem* item = fileList->item(i);
                if (item->checkState() == Qt::Checked) {
                    selectedFiles.append(item->data(Qt::UserRole).toString());
                }
            }
            
            if (!selectedFiles.isEmpty()) {
                // Process first file, others can be queued
                currentLogFile_ = selectedFiles.first();
                logViewer_->loadFile(currentLogFile_);
                analyzeAction_->setEnabled(true);
                statusLabel_->setText(tr("Loaded %1 files").arg(selectedFiles.size()));
            }
        }
    }
}

void MainWindow::startAnalysis() {
    if (currentLogFile_.isEmpty() || !QFile::exists(currentLogFile_)) {
        QMessageBox::warning(this, tr("No File"),
                           tr("Please open a log file first."));
        return;
    }
    
    // Determine log source from file extension
    LogSource source = LogSource::SYSLOG; // Default
    QString ext = QFileInfo(currentLogFile_).suffix().toLower();
    
    if (ext == "json") source = LogSource::JSON;
    else if (ext == "evtx" || ext == "xml") source = LogSource::WINDOWS_EVENT;
    else if (ext == "csv") source = LogSource::CSV;
    
    // Create worker thread
    analysisThread_ = new QThread();
    analysisWorker_ = new AnalysisWorker(currentLogFile_, source, useLLM_, currentModel_);
    analysisWorker_->moveToThread(analysisThread_);
    
    // Connect signals
    connect(analysisThread_, &QThread::started, analysisWorker_, &AnalysisWorker::process);
    connect(analysisWorker_, &AnalysisWorker::progress, this, &MainWindow::onAnalysisProgress);
    connect(analysisWorker_, &AnalysisWorker::completed, this, &MainWindow::onAnalysisCompleted);
    connect(analysisWorker_, &AnalysisWorker::error, this, &MainWindow::onAnalysisError);
    connect(analysisWorker_, &AnalysisWorker::finished, analysisThread_, &QThread::quit);
    connect(analysisWorker_, &AnalysisWorker::finished, analysisWorker_, &QObject::deleteLater);
    connect(analysisThread_, &QThread::finished, analysisThread_, &QObject::deleteLater);
    
    // Update UI
    analyzeAction_->setEnabled(false);
    stopAnalysisAction_->setEnabled(true);
    progressBar_->setVisible(true);
    progressBar_->setValue(0);
    statusLabel_->setText(tr("Starting analysis..."));
    
    // Start thread
    analysisThread_->start();
    onAnalysisStarted();
}

void MainWindow::onAnalysisStarted() {
    analysisPanel_->clearResults();
    statusBar()->showMessage(tr("Analysis started"), 2000);
}

void MainWindow::onAnalysisProgress(int value, const QString& message) {
    progressBar_->setValue(value);
    statusLabel_->setText(message);
    
    if (trayIcon_ && trayIcon_->isVisible()) {
        trayIcon_->showMessage(
            tr("Analysis Progress"),
            QString("%1% - %2").arg(value).arg(message),
            QSystemTrayIcon::Information,
            1000
        );
    }
}

void MainWindow::onAnalysisCompleted(const QString& summary,
                                   const std::vector<SecurityEvent>& events) {
    progressBar_->setValue(100);
    progressBar_->setVisible(false);
    
    analyzeAction_->setEnabled(true);
    stopAnalysisAction_->setEnabled(false);
    saveReportAction_->setEnabled(true);
    exportPDFAction_->setEnabled(true);
    clearAction_->setEnabled(true);
    
    // Update analysis panel
    analysisPanel_->displayResults(summary, events);
    
    // Update statistics tab
    updateStatisticsTab(events);
    
    // Show notification
    QString message = tr("Analysis completed: %1 events found").arg(events.size());
    statusLabel_->setText(message);
    
    if (events.size() > 0) {
        QMessageBox::information(this, tr("Analysis Complete"), message);
        
        if (trayIcon_ && trayIcon_->isVisible()) {
            trayIcon_->showMessage(
                tr("Analysis Complete"),
                message,
                QSystemTrayIcon::Information,
                5000
            );
        }
    }
}

void MainWindow::onAnalysisError(const QString& error) {
    progressBar_->setVisible(false);
    analyzeAction_->setEnabled(true);
    stopAnalysisAction_->setEnabled(false);
    
    QMessageBox::critical(this, tr("Analysis Error"), error);
    statusLabel_->setText(tr("Analysis failed: %1").arg(error));
}

void MainWindow::stopAnalysis() {
    if (analysisThread_ && analysisThread_->isRunning()) {
        analysisThread_->requestInterruption();
        analysisThread_->quit();
        analysisThread_->wait();
        
        stopAnalysisAction_->setEnabled(false);
        analyzeAction_->setEnabled(true);
        progressBar_->setVisible(false);
        
        statusLabel_->setText(tr("Analysis stopped by user"));
    }
}

void MainWindow::saveReport() {
    QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Save Report"),
        QDir::homePath() + "/log_analysis_report_" + 
        QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss") + ".html",
        tr("HTML Files (*.html *.htm);;Text Files (*.txt);;All Files (*)")
    );
    
    if (!filePath.isEmpty()) {
        QString report = analysisPanel_->generateReport();
        
        QFile file(filePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            stream << report;
            file.close();
            
            statusBar()->showMessage(tr("Report saved to %1").arg(filePath), 3000);
        } else {
            QMessageBox::warning(this, tr("Save Error"),
                               tr("Could not save report to %1").arg(filePath));
        }
    }
}

void MainWindow::exportToPDF() {
    QPrinter printer(QPrinter::HighResolution);
    printer.setOutputFormat(QPrinter::PdfFormat);
    
    QString filePath = QFileDialog::getSaveFileName(
        this,
        tr("Export to PDF"),
        QDir::homePath() + "/log_analysis_report_" + 
        QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss") + ".pdf",
        tr("PDF Files (*.pdf);;All Files (*)")
    );
    
    if (!filePath.isEmpty()) {
        printer.setOutputFileName(filePath);
        printer.setPageSize(QPageSize(QPageSize::A4));
        printer.setPageOrientation(QPageLayout::Portrait);
        
        QPrintDialog printDialog(&printer, this);
        if (printDialog.exec() == QDialog::Accepted) {
            QTextDocument document;
            document.setHtml(analysisPanel_->generateReport());
            document.print(&printer);
            
            statusBar()->showMessage(tr("PDF exported to %1").arg(filePath), 3000);
        }
    }
}

void MainWindow::testOllamaConnection() {
    statusLabel_->setText(tr("Testing OLLAMA connection..."));
    
    try {
        auto models = ollamaClient_->list_models();
        
        QLabel* connectionStatus = findChild<QLabel*>("ConnectionStatus");
        if (connectionStatus) {
            if (!models.empty()) {
                connectionStatus->setText(tr("✅ OLLAMA: Connected (%1 models)").arg(models.size()));
                connectionStatus->setStyleSheet("color: green;");
                
                // Update model selection in settings if needed
                if (settingsDialog_) {
                    settingsDialog_->updateModelList(models);
                }
            } else {
                connectionStatus->setText(tr("⚠️ OLLAMA: No models found"));
                connectionStatus->setStyleSheet("color: orange;");
            }
        }
        
        statusLabel_->setText(tr("OLLAMA connection successful"));
        
    } catch (const std::exception& e) {
        QLabel* connectionStatus = findChild<QLabel*>("ConnectionStatus");
        if (connectionStatus) {
            connectionStatus->setText(tr("❌ OLLAMA: Connection failed"));
            connectionStatus->setStyleSheet("color: red;");
        }
        
        statusLabel_->setText(tr("OLLAMA connection failed: %1").arg(e.what()));
        QMessageBox::warning(this, tr("Connection Error"),
                           tr("Could not connect to OLLAMA: %1").arg(e.what()));
    }
}

void MainWindow::showSettings() {
    if (!settingsDialog_) {
        settingsDialog_ = new SettingsDialog(this);
        connect(settingsDialog_, &SettingsDialog::settingsChanged,
                this, &MainWindow::applySettings);
    }
    
    settingsDialog_->setCurrentSettings(currentModel_, useLLM_, minimizeToTray_);
    settingsDialog_->exec();
}

void MainWindow::applySettings() {
    if (settingsDialog_) {
        currentModel_ = settingsDialog_->getSelectedModel();
        useLLM_ = settingsDialog_->useLLM();
        minimizeToTray_ = settingsDialog_->minimizeToTray();
        
        saveSettings();
        statusBar()->showMessage(tr("Settings applied"), 2000);
    }
}

void MainWindow::showAbout() {
    AboutDialog aboutDialog(this);
    aboutDialog.exec();
}

void MainWindow::updateStatisticsTab(const std::vector<SecurityEvent>& events) {
    QWidget* statsTab = tabWidget_->widget(1);
    if (!statsTab) return;
    
    // Clear existing layout
    QLayout* oldLayout = statsTab->layout();
    if (oldLayout) {
        QLayoutItem* item;
        while ((item = oldLayout->takeAt(0)) != nullptr) {
            delete item->widget();
            delete item;
        }
        delete oldLayout;
    }
    
    QVBoxLayout* layout = new QVBoxLayout(statsTab);
    
    // Calculate statistics
    std::map<std::string, int> eventCounts;
    std::map<int, int> riskDistribution;
    int totalRisk = 0;
    
    for (const auto& event : events) {
        eventCounts[event.event_type]++;
        riskDistribution[event.risk_score]++;
        totalRisk += event.risk_score;
    }
    
    // Create statistics widgets
    QGroupBox* summaryGroup = new QGroupBox(tr("Summary Statistics"));
    QFormLayout* summaryLayout = new QFormLayout();
    
    summaryLayout->addRow(tr("Total Events:"), new QLabel(QString::number(events.size())));
    summaryLayout->addRow(tr("Unique Event Types:"), new QLabel(QString::number(eventCounts.size())));
    summaryLayout->addRow(tr("Average Risk Score:"), 
                         new QLabel(QString::number(events.empty() ? 0 : totalRisk / events.size())));
    
    summaryGroup->setLayout(summaryLayout);
    layout->addWidget(summaryGroup);
    
    // Event type distribution
    QGroupBox* typeGroup = new QGroupBox(tr("Event Type Distribution"));
    QVBoxLayout* typeLayout = new QVBoxLayout();
    
    for (const auto& [type, count] : eventCounts) {
        QProgressBar* bar = new QProgressBar();
        bar->setRange(0, events.size());
        bar->setValue(count);
        bar->setFormat(QString("%1: %2 (%3%)")
                      .arg(QString::fromStdString(type))
                      .arg(count)
                      .arg(100 * count / events.size()));
        typeLayout->addWidget(bar);
    }
    
    typeGroup->setLayout(typeLayout);
    layout->addWidget(typeGroup);
    
    // Risk score distribution
    QGroupBox* riskGroup = new QGroupBox(tr("Risk Score Distribution"));
    QVBoxLayout* riskLayout = new QVBoxLayout();
    
    for (const auto& [score, count] : riskDistribution) {
        QHBoxLayout* rowLayout = new QHBoxLayout();
        
        QLabel* scoreLabel = new QLabel(QString::number(score));
        scoreLabel->setMinimumWidth(30);
        
        QProgressBar* bar = new QProgressBar();
        bar->setRange(0, events.size());
        bar->setValue(count);
        bar->setFormat(QString("%1 events").arg(count));
        
        // Color based on risk score
        QPalette pal = bar->palette();
        if (score >= 8) pal.setColor(QPalette::Highlight, Qt::red);
        else if (score >= 5) pal.setColor(QPalette::Highlight, QColor(255, 165, 0));
        else if (score >= 3) pal.setColor(QPalette::Highlight, Qt::yellow);
        else pal.setColor(QPalette::Highlight, Qt::green);
        bar->setPalette(pal);
        
        rowLayout->addWidget(scoreLabel);
        rowLayout->addWidget(bar);
        riskLayout->addLayout(rowLayout);
    }
    
    riskGroup->setLayout(riskLayout);
    layout->addWidget(riskGroup);
    
    layout->addStretch();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (minimizeToTray_ && trayIcon_ && trayIcon_->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::trayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        showHideWindow();
    }
}

void MainWindow::showHideWindow() {
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::loadSettings() {
    QSettings settings("LogSummarizer", "SecurityAnalysis");
    
    currentModel_ = settings.value("model", "llama3").toString();
    useLLM_ = settings.value("use_llm", true).toBool();
    minimizeToTray_ = settings.value("minimize_to_tray", true).toBool();
    
    // Load window geometry
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
    
    // Load recent files
    QStringList recentFiles = settings.value("recent_files").toStringList();
    // Update recent files menu
}

void MainWindow::saveSettings() {
    QSettings settings("LogSummarizer", "SecurityAnalysis");
    
    settings.setValue("model", currentModel_);
    settings.setValue("use_llm", useLLM_);
    settings.setValue("minimize_to_tray", minimizeToTray_);
    
    // Save window geometry
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
    
    // Save recent files
    // settings.setValue("recent_files", recentFiles_);
}

// AnalysisWorker implementation
AnalysisWorker::AnalysisWorker(const QString& filePath, 
                             LogSource source,
                             bool useLLM,
                             const QString& model,
                             QObject* parent)
    : QObject(parent),
      filePath_(filePath),
      source_(source),
      useLLM_(useLLM),
      model_(model) {
}

void AnalysisWorker::process() {
    try {
        emit progress(10, tr("Initializing parser..."));
        
        // Create parser
        parser_ = LogParser::create_parser(source_);
        if (!parser_) {
            throw std::runtime_error("Failed to create parser for the specified source");
        }
        
        emit progress(20, tr("Parsing log file..."));
        
        // Parse logs
        std::string filePathStd = filePath_.toStdString();
        auto logs = parser_->parse_file(filePathStd);
        
        emit progress(40, tr("Analyzing for security events..."));
        
        // Analyze logs
        analyzer_ = std::make_unique<SecurityAnalyzer>();
        auto events = analyzer_->analyze_logs(logs);
        
        QString summary;
        if (useLLM_ && !events.empty()) {
            emit progress(60, tr("Generating LLM summary..."));
            
            // Generate LLM summary
            ollamaClient_ = std::make_unique<OllamaClient>();
            ollamaClient_->initialize();
            
            std::string llmSummary = ollamaClient_->generate_summary(events, model_.toStdString());
            summary = QString::fromStdString(llmSummary);
        } else {
            // Generate basic summary
            emit progress(80, tr("Generating basic summary..."));
            
            std::stringstream basicSummary;
            basicSummary << "Security Analysis Report\n";
            basicSummary << "========================\n\n";
            basicSummary << "Total events detected: " << events.size() << "\n\n";
            
            std::map<std::string, int> eventCounts;
            for (const auto& event : events) {
                eventCounts[event.event_type]++;
            }
            
            for (const auto& [type, count] : eventCounts) {
                basicSummary << type << ": " << count << " events\n";
            }
            
            summary = QString::fromStdString(basicSummary.str());
        }
        
        emit progress(100, tr("Analysis complete"));
        emit completed(summary, events);
        
    } catch (const std::exception& e) {
        emit error(QString::fromStdString(e.what()));
    }
    
    emit finished();
}