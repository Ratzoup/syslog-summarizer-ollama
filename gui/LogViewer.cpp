#include "LogViewer.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QTextStream>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QMessageBox>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QLabel>
#include <QProgressBar>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QColor>
#include <QFont>
#include <QFontMetrics>
#include <QStandardItemModel>
#include <QSplitter>
#include <QTreeWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QApplication>
#include <QClipboard>
#include <QMenu>
#include <QContextMenuEvent>
#include <algorithm>

LogViewer::LogViewer(QWidget* parent) 
    : QWidget(parent), currentFile_("") {
    setupUI();
}

void LogViewer::setupUI() {
    // Create main layout
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    
    // Create filter controls
    QGroupBox* filterGroup = new QGroupBox(tr("Filter Controls"));
    QHBoxLayout* filterLayout = new QHBoxLayout(filterGroup);
    
    // Search box
    searchBox_ = new QLineEdit();
    searchBox_->setPlaceholderText(tr("Search in logs..."));
    searchBox_->setClearButtonEnabled(true);
    connect(searchBox_, &QLineEdit::textChanged, this, &LogViewer::onSearchTextChanged);
    
    // Severity filter
    severityFilter_ = new QComboBox();
    severityFilter_->addItem(tr("All Severities"));
    severityFilter_->addItem(tr("Info"));
    severityFilter_->addItem(tr("Warning"));
    severityFilter_->addItem(tr("Error"));
    severityFilter_->addItem(tr("Critical"));
    connect(severityFilter_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LogViewer::onSeverityFilterChanged);
    
    // Source filter
    sourceFilter_ = new QComboBox();
    sourceFilter_->addItem(tr("All Sources"));
    sourceFilter_->addItem(tr("Syslog"));
    sourceFilter_->addItem(tr("Windows Event"));
    sourceFilter_->addItem(tr("JSON"));
    sourceFilter_->addItem(tr("CSV"));
    
    // Date filters
    dateFrom_ = new QLineEdit();
    dateFrom_->setPlaceholderText(tr("From (YYYY-MM-DD)"));
    dateFrom_->setMaximumWidth(150);
    
    dateTo_ = new QLineEdit();
    dateTo_->setPlaceholderText(tr("To (YYYY-MM-DD)"));
    dateTo_->setMaximumWidth(150);
    
    // Security events checkbox
    showOnlySecurity_ = new QCheckBox(tr("Security Events Only"));
    
    // Filter buttons
    applyFilterButton_ = new QPushButton(tr("Apply Filters"));
    applyFilterButton_->setIcon(QIcon(":/icons/filter.png"));
    connect(applyFilterButton_, &QPushButton::clicked, this, &LogViewer::onFilterChanged);
    
    clearFilterButton_ = new QPushButton(tr("Clear Filters"));
    clearFilterButton_->setIcon(QIcon(":/icons/clear.png"));
    connect(clearFilterButton_, &QPushButton::clicked, this, [this]() {
        searchBox_->clear();
        severityFilter_->setCurrentIndex(0);
        sourceFilter_->setCurrentIndex(0);
        dateFrom_->clear();
        dateTo_->clear();
        showOnlySecurity_->setChecked(false);
        onFilterChanged();
    });
    
    // Add widgets to filter layout
    filterLayout->addWidget(new QLabel(tr("Search:")));
    filterLayout->addWidget(searchBox_);
    filterLayout->addWidget(new QLabel(tr("Severity:")));
    filterLayout->addWidget(severityFilter_);
    filterLayout->addWidget(new QLabel(tr("Source:")));
    filterLayout->addWidget(sourceFilter_);
    filterLayout->addWidget(new QLabel(tr("Date Range:")));
    filterLayout->addWidget(dateFrom_);
    filterLayout->addWidget(new QLabel(tr("to")));
    filterLayout->addWidget(dateTo_);
    filterLayout->addWidget(showOnlySecurity_);
    filterLayout->addWidget(applyFilterButton_);
    filterLayout->addWidget(clearFilterButton_);
    filterLayout->addStretch();
    
    mainLayout->addWidget(filterGroup);
    
    // Create main splitter for different views
    mainSplitter_ = new QSplitter(Qt::Vertical, this);
    
    // Create raw text view
    QGroupBox* rawTextGroup = new QGroupBox(tr("Raw Log View"));
    QVBoxLayout* rawTextLayout = new QVBoxLayout(rawTextGroup);
    rawTextView_ = new QTextEdit();
    rawTextView_->setReadOnly(true);
    rawTextView_->setFont(QFont("Monospace", 9));
    rawTextView_->setLineWrapMode(QTextEdit::NoWrap);
    
    // Add context menu to raw text view
    rawTextView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(rawTextView_, &QTextEdit::customContextMenuRequested,
            this, [this](const QPoint& pos) {
        QMenu* menu = rawTextView_->createStandardContextMenu();
        menu->addSeparator();
        menu->addAction(tr("Copy Selected"), rawTextView_, &QTextEdit::copy);
        menu->addAction(tr("Select All"), rawTextView_, &QTextEdit::selectAll);
        menu->addAction(tr("Clear"), rawTextView_, &QTextEdit::clear);
        menu->exec(rawTextView_->mapToGlobal(pos));
    });
    
    rawTextLayout->addWidget(rawTextView_);
    
    // Create structured view
    QGroupBox* structuredGroup = new QGroupBox(tr("Structured View"));
    QVBoxLayout* structuredLayout = new QVBoxLayout(structuredGroup);
    structuredView_ = new QTableWidget();
    structuredView_->setColumnCount(6);
    structuredView_->setHorizontalHeaderLabels({
        tr("Timestamp"), tr("Severity"), tr("Source"), 
        tr("Host"), tr("Process"), tr("Message")
    });
    structuredView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    structuredView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    structuredView_->setSelectionMode(QAbstractItemView::SingleSelection);
    structuredView_->setAlternatingRowColors(true);
    structuredView_->horizontalHeader()->setStretchLastSection(true);
    structuredView_->verticalHeader()->setVisible(false);
    
    // Set column widths
    structuredView_->setColumnWidth(0, 150); // Timestamp
    structuredView_->setColumnWidth(1, 80);  // Severity
    structuredView_->setColumnWidth(2, 100); // Source
    structuredView_->setColumnWidth(3, 120); // Host
    structuredView_->setColumnWidth(4, 120); // Process
    
    structuredLayout->addWidget(structuredView_);
    
    // Create tree view for hierarchical display
    QGroupBox* treeGroup = new QGroupBox(tr("Hierarchical View"));
    QVBoxLayout* treeLayout = new QVBoxLayout(treeGroup);
    treeView_ = new QTreeWidget();
    treeView_->setHeaderLabels({tr("Log Entry"), tr("Details")});
    treeView_->setAlternatingRowColors(true);
    treeView_->setSelectionMode(QAbstractItemView::SingleSelection);
    
    treeLayout->addWidget(treeView_);
    
    // Add views to tab widget instead of splitter
    QTabWidget* viewTabs = new QTabWidget();
    viewTabs->addTab(rawTextGroup, tr("Raw Text"));
    viewTabs->addTab(structuredGroup, tr("Structured"));
    viewTabs->addTab(treeGroup, tr("Hierarchical"));
    
    mainSplitter_->addWidget(viewTabs);
    
    // Statistics panel at the bottom
    QGroupBox* statsGroup = new QGroupBox(tr("Statistics"));
    QHBoxLayout* statsLayout = new QHBoxLayout(statsGroup);
    
    totalLogsLabel_ = new QLabel(tr("Total Logs: 0"));
    securityEventsLabel_ = new QLabel(tr("Security Events: 0"));
    criticalEventsLabel_ = new QLabel(tr("Critical Events: 0"));
    
    statsLayout->addWidget(totalLogsLabel_);
    statsLayout->addWidget(securityEventsLabel_);
    statsLayout->addWidget(criticalEventsLabel_);
    statsLayout->addStretch();
    
    // Action buttons
    QPushButton* analyzeButton = new QPushButton(tr("Analyze for Security Events"));
    analyzeButton->setIcon(QIcon(":/icons/analyze.png"));
    connect(analyzeButton, &QPushButton::clicked, this, &LogViewer::onAnalyzeClicked);
    
    QPushButton* exportButton = new QPushButton(tr("Export Filtered Logs"));
    exportButton->setIcon(QIcon(":/icons/export.png"));
    connect(exportButton, &QPushButton::clicked, this, &LogViewer::onExportClicked);
    
    statsLayout->addWidget(analyzeButton);
    statsLayout->addWidget(exportButton);
    
    mainSplitter_->addWidget(statsGroup);
    mainSplitter_->setStretchFactor(0, 8); // 80% for logs
    mainSplitter_->setStretchFactor(1, 1); // 10% for stats
    
    mainLayout->addWidget(mainSplitter_, 1);
    
    // Set initial state
    clear();
}

void LogViewer::loadFile(const QString& filePath) {
    if (filePath.isEmpty() || !QFile::exists(filePath)) {
        QMessageBox::warning(this, tr("File Error"), 
                           tr("File does not exist: %1").arg(filePath));
        return;
    }
    
    currentFile_ = filePath;
    clear();
    
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, tr("File Error"),
                            tr("Cannot open file: %1").arg(filePath));
        return;
    }
    
    QTextStream stream(&file);
    QString content = stream.readAll();
    file.close();
    
    // Display raw content
    rawTextView_->setPlainText(content);
    
    // For now, we'll just show the raw content
    // In a real implementation, this would parse the logs
    // and populate the structured and tree views
    
    // Update statistics
    totalLogsLabel_->setText(tr("Total Logs: %1").arg(content.count('\n') + 1));
    
    // Enable analyze button
    emit analysisRequested();
}

void LogViewer::clear() {
    rawTextView_->clear();
    structuredView_->setRowCount(0);
    treeView_->clear();
    
    totalLogsLabel_->setText(tr("Total Logs: 0"));
    securityEventsLabel_->setText(tr("Security Events: 0"));
    criticalEventsLabel_->setText(tr("Critical Events: 0"));
}

void LogViewer::loadLogEntries(const std::vector<LogEntry>& entries) {
    allEntries_ = entries;
    filteredEntries_ = entries;
    
    // Clear existing content
    structuredView_->setRowCount(0);
    treeView_->clear();
    rawTextView_->clear();
    
    // Build raw text
    QString rawText;
    for (const auto& entry : entries) {
        rawText += QString::fromStdString(entry.to_string()) + "\n";
    }
    rawTextView_->setPlainText(rawText);
    
    // Populate structured view
    structuredView_->setRowCount(static_cast<int>(entries.size()));
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        
        // Timestamp
        structuredView_->setItem(static_cast<int>(i), 0,
            new QTableWidgetItem(QString::fromStdString(entry.timestamp)));
        
        // Severity with color coding
        QTableWidgetItem* severityItem = new QTableWidgetItem(
            QString::fromStdString(entry.severity_to_string()));
        
        QColor severityColor;
        switch (entry.severity) {
            case LogSeverity::CRITICAL: severityColor = Qt::red; break;
            case LogSeverity::ERROR: severityColor = Qt::darkRed; break;
            case LogSeverity::WARNING: severityColor = QColor(255, 165, 0); break;
            case LogSeverity::INFO: severityColor = Qt::darkGreen; break;
        }
        
        severityItem->setForeground(severityColor);
        severityItem->setFont(QFont("", -1, QFont::Bold));
        structuredView_->setItem(static_cast<int>(i), 1, severityItem);
        
        // Source
        QString sourceStr;
        switch (entry.source_type) {
            case LogSource::SYSLOG: sourceStr = "Syslog"; break;
            case LogSource::WINDOWS_EVENT: sourceStr = "Windows"; break;
            case LogSource::JSON: sourceStr = "JSON"; break;
            case LogSource::CSV: sourceStr = "CSV"; break;
            case LogSource::PCAP: sourceStr = "PCAP"; break;
            case LogSource::VULN_SCAN: sourceStr = "Vuln Scan"; break;
        }
        structuredView_->setItem(static_cast<int>(i), 2,
            new QTableWidgetItem(sourceStr));
        
        // Host
        structuredView_->setItem(static_cast<int>(i), 3,
            new QTableWidgetItem(QString::fromStdString(entry.source_host)));
        
        // Process
        structuredView_->setItem(static_cast<int>(i), 4,
            new QTableWidgetItem(QString::fromStdString(entry.process)));
        
        // Message (truncated if too long)
        QString message = QString::fromStdString(entry.message);
        if (message.length() > 200) {
            message = message.left(200) + "...";
        }
        structuredView_->setItem(static_cast<int>(i), 5,
            new QTableWidgetItem(message));
        structuredView_->item(static_cast<int>(i), 5)->setToolTip(
            QString::fromStdString(entry.message));
    }
    
    // Populate tree view
    for (const auto& entry : entries) {
        QTreeWidgetItem* topItem = new QTreeWidgetItem(treeView_);
        topItem->setText(0, QString::fromStdString(entry.timestamp));
        topItem->setText(1, QString::fromStdString(entry.severity_to_string()));
        
        // Add child items for details
        QTreeWidgetItem* hostItem = new QTreeWidgetItem(topItem);
        hostItem->setText(0, tr("Host"));
        hostItem->setText(1, QString::fromStdString(entry.source_host));
        
        QTreeWidgetItem* processItem = new QTreeWidgetItem(topItem);
        processItem->setText(0, tr("Process"));
        processItem->setText(1, QString::fromStdString(entry.process));
        
        QTreeWidgetItem* messageItem = new QTreeWidgetItem(topItem);
        messageItem->setText(0, tr("Message"));
        messageItem->setText(1, QString::fromStdString(entry.message));
        
        // Color code based on severity
        QColor itemColor;
        switch (entry.severity) {
            case LogSeverity::CRITICAL: itemColor = Qt::red; break;
            case LogSeverity::ERROR: itemColor = Qt::darkRed; break;
            case LogSeverity::WARNING: itemColor = QColor(255, 165, 0); break;
            default: itemColor = Qt::black; break;
        }
        
        for (int i = 0; i < topItem->childCount(); ++i) {
            topItem->child(i)->setForeground(1, itemColor);
        }
    }
    
    treeView_->expandAll();
    
    // Update statistics
    updateStatistics();
}

void LogViewer::onFilterChanged() {
    applyFilters();
    highlightSearchResults();
}

void LogViewer::onSearchTextChanged(const QString& text) {
    Q_UNUSED(text);
    highlightSearchResults();
}

void LogViewer::onSeverityFilterChanged(int index) {
    Q_UNUSED(index);
    applyFilters();
}

void LogViewer::onExportClicked() {
    if (currentFile_.isEmpty()) {
        QMessageBox::warning(this, tr("Export Error"),
                           tr("No log file loaded."));
        return;
    }
    
    QString exportPath = QFileDialog::getSaveFileName(
        this,
        tr("Export Filtered Logs"),
        QFileInfo(currentFile_).baseName() + "_filtered.txt",
        tr("Text Files (*.txt);;CSV Files (*.csv);;All Files (*)")
    );
    
    if (!exportPath.isEmpty()) {
        QFile file(exportPath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            
            // Export filtered entries if available, otherwise raw text
            if (!filteredEntries_.empty()) {
                for (const auto& entry : filteredEntries_) {
                    stream << QString::fromStdString(entry.to_string()) << "\n";
                }
            } else {
                stream << rawTextView_->toPlainText();
            }
            
            file.close();
            QMessageBox::information(this, tr("Export Complete"),
                                   tr("Logs exported to: %1").arg(exportPath));
        }
    }
}

void LogViewer::onAnalyzeClicked() {
    emit analysisRequested();
}

void LogViewer::applyFilters() {
    // This is a simplified filter implementation
    // In a real application, you would filter the actual LogEntry objects
    
    QString searchText = searchBox_->text().toLower();
    int severityIndex = severityFilter_->currentIndex();
    
    // Apply filtering to structured view
    for (int row = 0; row < structuredView_->rowCount(); ++row) {
        bool shouldShow = true;
        
        // Apply severity filter
        if (severityIndex > 0) {
            QString severityText = structuredView_->item(row, 1)->text();
            int currentSeverity = severityFilter_->findText(severityText);
            if (currentSeverity != severityIndex) {
                shouldShow = false;
            }
        }
        
        // Apply text search
        if (!searchText.isEmpty()) {
            bool found = false;
            for (int col = 0; col < structuredView_->columnCount(); ++col) {
                QString cellText = structuredView_->item(row, col)->text().toLower();
                if (cellText.contains(searchText)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                shouldShow = false;
            }
        }
        
        structuredView_->setRowHidden(row, !shouldShow);
    }
    
    // Update statistics for filtered items
    int visibleRows = 0;
    for (int row = 0; row < structuredView_->rowCount(); ++row) {
        if (!structuredView_->isRowHidden(row)) {
            visibleRows++;
        }
    }
    
    totalLogsLabel_->setText(tr("Filtered Logs: %1").arg(visibleRows));
}

void LogViewer::highlightSearchResults() {
    QString searchText = searchBox_->text();
    if (searchText.isEmpty()) {
        rawTextView_->setExtraSelections({});
        return;
    }
    
    QTextDocument* document = rawTextView_->document();
    QTextCursor highlightCursor(document);
    QTextCursor cursor(document);
    
    QList<QTextEdit::ExtraSelection> extraSelections;
    QColor highlightColor = QColor(255, 255, 0, 100); // Yellow with transparency
    
    cursor.beginEditBlock();
    
    QTextCharFormat plainFormat(highlightCursor.charFormat());
    QTextCharFormat colorFormat = plainFormat;
    colorFormat.setBackground(highlightColor);
    
    while (!highlightCursor.isNull() && !highlightCursor.atEnd()) {
        highlightCursor = document->find(searchText, highlightCursor);
        if (!highlightCursor.isNull()) {
            QTextEdit::ExtraSelection extra;
            extra.cursor = highlightCursor;
            extra.format = colorFormat;
            extraSelections.append(extra);
        }
    }
    
    cursor.endEditBlock();
    rawTextView_->setExtraSelections(extraSelections);
}

void LogViewer::updateStatistics() {
    int totalLogs = static_cast<int>(allEntries_.size());
    int securityEvents = 0;
    int criticalEvents = 0;
    
    // Count security and critical events
    for (const auto& entry : allEntries_) {
        if (entry.severity == LogSeverity::CRITICAL) {
            criticalEvents++;
        }
        
        // Simple heuristic for security events
        QString message = QString::fromStdString(entry.message).toLower();
        if (message.contains("failed") || message.contains("error") ||
            message.contains("attack") || message.contains("malicious") ||
            message.contains("breach") || message.contains("intrusion")) {
            securityEvents++;
        }
    }
    
    totalLogsLabel_->setText(tr("Total Logs: %1").arg(totalLogs));
    securityEventsLabel_->setText(tr("Security Events: %1").arg(securityEvents));
    criticalEventsLabel_->setText(tr("Critical Events: %1").arg(criticalEvents));
}