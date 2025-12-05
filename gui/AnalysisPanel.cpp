#include "AnalysisPanel.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QSplitter>
#include <QTextDocument>
#include <QTextCursor>
#include <QTextTable>
#include <QTextTableFormat>
#include <QTextCharFormat>
#include <QTextBlockFormat>
#include <QColor>
#include <QFont>
#include <QFontMetrics>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QPrintDialog>
#include <QPrinter>
#include <QPainter>
#include <algorithm>

AnalysisPanel::AnalysisPanel(QWidget* parent) 
    : QWidget(parent) {
    setupUI();
}

void AnalysisPanel::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    
    // Create main splitter
    mainSplitter_ = new QSplitter(Qt::Vertical, this);
    
    // Summary view at the top
    QGroupBox* summaryGroup = new QGroupBox(tr("Analysis Summary"));
    QVBoxLayout* summaryLayout = new QVBoxLayout(summaryGroup);
    
    summaryView_ = new QTextBrowser();
    summaryView_->setOpenExternalLinks(true);
    summaryView_->setReadOnly(true);
    summaryView_->setFont(QFont("Arial", 10));
    
    summaryLayout->addWidget(summaryView_);
    mainSplitter_->addWidget(summaryGroup);
    
    // Event details in the middle
    QGroupBox* eventsGroup = new QGroupBox(tr("Security Events"));
    QVBoxLayout* eventsLayout = new QVBoxLayout(eventsGroup);
    
    // Create tab widget for different event views
    detailsTab_ = new QTabWidget();
    
    // Table view
    eventTable_ = new QTableWidget();
    setupEventTable();
    detailsTab_->addTab(eventTable_, tr("Table View"));
    
    // Tree view
    eventTree_ = new QTreeWidget();
    setupEventTree();
    detailsTab_->addTab(eventTree_, tr("Tree View"));
    
    eventsLayout->addWidget(detailsTab_);
    
    // Control buttons below the events
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    exportButton_ = new QPushButton(tr("Export Report"));
    exportButton_->setIcon(QIcon(":/icons/export.png"));
    exportButton_->setEnabled(false);
    connect(exportButton_, &QPushButton::clicked, this, &AnalysisPanel::onExportDetails);
    
    copyButton_ = new QPushButton(tr("Copy to Clipboard"));
    copyButton_->setIcon(QIcon(":/icons/copy.png"));
    copyButton_->setEnabled(false);
    connect(copyButton_, &QPushButton::clicked, this, &AnalysisPanel::onCopyToClipboard);
    
    detailsButton_ = new QPushButton(tr("Show Raw Log"));
    detailsButton_->setIcon(QIcon(":/icons/details.png"));
    detailsButton_->setEnabled(false);
    connect(detailsButton_, &QPushButton::clicked, this, &AnalysisPanel::onShowRawLog);
    
    buttonLayout->addWidget(exportButton_);
    buttonLayout->addWidget(copyButton_);
    buttonLayout->addWidget(detailsButton_);
    buttonLayout->addStretch();
    
    eventsLayout->addLayout(buttonLayout);
    mainSplitter_->addWidget(eventsGroup);
    
    // Statistics at the bottom
    QGroupBox* statsGroup = new QGroupBox(tr("Statistics"));
    QHBoxLayout* statsLayout = new QHBoxLayout(statsGroup);
    
    totalEventsLabel_ = new QLabel(tr("Total Events: 0"));
    highRiskLabel_ = new QLabel(tr("High Risk (≥7): 0"));
    avgRiskLabel_ = new QLabel(tr("Average Risk: 0.0"));
    
    QFont statsFont = totalEventsLabel_->font();
    statsFont.setBold(true);
    totalEventsLabel_->setFont(statsFont);
    highRiskLabel_->setFont(statsFont);
    avgRiskLabel_->setFont(statsFont);
    
    statsLayout->addWidget(totalEventsLabel_);
    statsLayout->addWidget(highRiskLabel_);
    statsLayout->addWidget(avgRiskLabel_);
    statsLayout->addStretch();
    
    // Risk visualization
    riskVisualization_ = new QWidget();
    riskVisualization_->setMinimumHeight(20);
    riskVisualization_->setMaximumHeight(30);
    statsLayout->addWidget(riskVisualization_);
    
    mainSplitter_->addWidget(statsGroup);
    
    // Set stretch factors
    mainSplitter_->setStretchFactor(0, 3); // Summary (30%)
    mainSplitter_->setStretchFactor(1, 6); // Events (60%)
    mainSplitter_->setStretchFactor(2, 1); // Stats (10%)
    
    mainLayout->addWidget(mainSplitter_, 1);
    
    // Connect signals
    connect(eventTable_, &QTableWidget::cellClicked, 
            this, &AnalysisPanel::onEventSelected);
    connect(eventTree_, &QTreeWidget::itemClicked,
            this, &AnalysisPanel::onTreeItemSelected);
}

void AnalysisPanel::setupEventTable() {
    eventTable_->setColumnCount(6);
    eventTable_->setHorizontalHeaderLabels({
        tr("Event Type"), tr("Risk"), tr("Timestamp"), 
        tr("Host"), tr("Source"), tr("Description")
    });
    
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    eventTable_->setAlternatingRowColors(true);
    eventTable_->setSortingEnabled(true);
    
    // Set column widths
    eventTable_->setColumnWidth(0, 150); // Event Type
    eventTable_->setColumnWidth(1, 60);  // Risk
    eventTable_->setColumnWidth(2, 150); // Timestamp
    eventTable_->setColumnWidth(3, 120); // Host
    eventTable_->setColumnWidth(4, 100); // Source
    // Description column will stretch
    
    eventTable_->horizontalHeader()->setStretchLastSection(true);
    eventTable_->verticalHeader()->setVisible(false);
}

void AnalysisPanel::setupEventTree() {
    eventTree_->setHeaderLabels({tr("Property"), tr("Value")});
    eventTree_->setAlternatingRowColors(true);
    eventTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    eventTree_->setColumnWidth(0, 200);
}

void AnalysisPanel::displayResults(const QString& summary, 
                                  const std::vector<SecurityEvent>& events) {
    currentSummary_ = summary;
    currentEvents_ = events;
    
    // Display summary
    summaryView_->setHtml("<h3>Security Analysis Summary</h3>" + summary);
    
    // Clear existing events
    eventTable_->setRowCount(0);
    eventTree_->clear();
    
    // Populate table with events
    eventTable_->setRowCount(static_cast<int>(events.size()));
    
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        
        // Event Type
        QTableWidgetItem* typeItem = new QTableWidgetItem(
            QString::fromStdString(event.event_type));
        eventTable_->setItem(static_cast<int>(i), 0, typeItem);
        
        // Risk Score with color coding
        QTableWidgetItem* riskItem = new QTableWidgetItem(
            QString::number(event.risk_score));
        
        QColor riskColor;
        if (event.risk_score >= 8) {
            riskColor = Qt::red;
        } else if (event.risk_score >= 5) {
            riskColor = QColor(255, 165, 0); // Orange
        } else if (event.risk_score >= 3) {
            riskColor = Qt::yellow;
        } else {
            riskColor = Qt::green;
        }
        
        riskItem->setBackground(riskColor);
        riskItem->setTextAlignment(Qt::AlignCenter);
        riskItem->setFont(QFont("", -1, QFont::Bold));
        eventTable_->setItem(static_cast<int>(i), 1, riskItem);
        
        // Timestamp
        eventTable_->setItem(static_cast<int>(i), 2,
            new QTableWidgetItem(QString::fromStdString(event.log_entry.timestamp)));
        
        // Host
        eventTable_->setItem(static_cast<int>(i), 3,
            new QTableWidgetItem(QString::fromStdString(event.log_entry.source_host)));
        
        // Source
        QString sourceStr;
        switch (event.log_entry.source_type) {
            case LogSource::SYSLOG: sourceStr = "Syslog"; break;
            case LogSource::WINDOWS_EVENT: sourceStr = "Windows"; break;
            case LogSource::JSON: sourceStr = "JSON"; break;
            case LogSource::CSV: sourceStr = "CSV"; break;
            default: sourceStr = "Unknown"; break;
        }
        eventTable_->setItem(static_cast<int>(i), 4,
            new QTableWidgetItem(sourceStr));
        
        // Description (truncated)
        QString description = QString::fromStdString(event.description);
        if (description.length() > 200) {
            description = description.left(200) + "...";
        }
        QTableWidgetItem* descItem = new QTableWidgetItem(description);
        descItem->setToolTip(QString::fromStdString(event.description));
        eventTable_->setItem(static_cast<int>(i), 5, descItem);
        
        // Populate tree view
        QTreeWidgetItem* topItem = new QTreeWidgetItem(eventTree_);
        topItem->setText(0, QString::fromStdString(event.event_type));
        topItem->setText(1, QString("Risk: %1/10").arg(event.risk_score));
        
        // Set color based on risk
        QColor itemColor = riskColor;
        topItem->setForeground(0, itemColor);
        topItem->setForeground(1, itemColor);
        
        // Add child items
        QTreeWidgetItem* timestampItem = new QTreeWidgetItem(topItem);
        timestampItem->setText(0, tr("Timestamp"));
        timestampItem->setText(1, QString::fromStdString(event.log_entry.timestamp));
        
        QTreeWidgetItem* hostItem = new QTreeWidgetItem(topItem);
        hostItem->setText(0, tr("Host"));
        hostItem->setText(1, QString::fromStdString(event.log_entry.source_host));
        
        QTreeWidgetItem* sourceItem = new QTreeWidgetItem(topItem);
        sourceItem->setText(0, tr("Source"));
        sourceItem->setText(1, sourceStr);
        
        QTreeWidgetItem* descTreeItem = new QTreeWidgetItem(topItem);
        descTreeItem->setText(0, tr("Description"));
        descTreeItem->setText(1, QString::fromStdString(event.description));
        
        // Add indicators if available
        if (!event.indicators.empty()) {
            QTreeWidgetItem* indicatorsItem = new QTreeWidgetItem(topItem);
            indicatorsItem->setText(0, tr("Indicators"));
            
            QString indicatorsText;
            for (const auto& indicator : event.indicators) {
                indicatorsText += QString::fromStdString(indicator) + "; ";
            }
            indicatorsItem->setText(1, indicatorsText);
        }
    }
    
    // Sort by risk score (highest first)
    eventTable_->sortItems(1, Qt::DescendingOrder);
    
    // Update statistics
    updateStatistics();
    
    // Enable buttons
    exportButton_->setEnabled(!events.empty());
    copyButton_->setEnabled(!events.empty());
    detailsButton_->setEnabled(!events.empty());
    
    // Create risk visualization
    createRiskVisualization();
}

void AnalysisPanel::clearResults() {
    currentSummary_.clear();
    currentEvents_.clear();
    
    summaryView_->clear();
    eventTable_->setRowCount(0);
    eventTree_->clear();
    
    totalEventsLabel_->setText(tr("Total Events: 0"));
    highRiskLabel_->setText(tr("High Risk (≥7): 0"));
    avgRiskLabel_->setText(tr("Average Risk: 0.0"));
    
    exportButton_->setEnabled(false);
    copyButton_->setEnabled(false);
    detailsButton_->setEnabled(false);
    
    riskVisualization_->update();
}

void AnalysisPanel::addEvent(const SecurityEvent& event) {
    currentEvents_.push_back(event);
    // Update display
    displayResults(currentSummary_, currentEvents_);
}

void AnalysisPanel::updateSummary(const QString& summary) {
    currentSummary_ = summary;
    summaryView_->setHtml("<h3>Security Analysis Summary</h3>" + summary);
}

void AnalysisPanel::updateStatistics() {
    if (currentEvents_.empty()) {
        totalEventsLabel_->setText(tr("Total Events: 0"));
        highRiskLabel_->setText(tr("High Risk (≥7): 0"));
        avgRiskLabel_->setText(tr("Average Risk: 0.0"));
        return;
    }
    
    int totalEvents = static_cast<int>(currentEvents_.size());
    int highRiskCount = 0;
    double totalRisk = 0.0;
    
    for (const auto& event : currentEvents_) {
        totalRisk += event.risk_score;
        if (event.risk_score >= 7) {
            highRiskCount++;
        }
    }
    
    double averageRisk = totalRisk / totalEvents;
    
    totalEventsLabel_->setText(tr("Total Events: %1").arg(totalEvents));
    highRiskLabel_->setText(tr("High Risk (≥7): %1").arg(highRiskCount));
    avgRiskLabel_->setText(tr("Average Risk: %1").arg(averageRisk, 0, 'f', 1));
}

void AnalysisPanel::createRiskVisualization() {
    if (currentEvents_.empty()) {
        riskVisualization_->update();
        return;
    }
    
    // Count events by risk level
    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& event : currentEvents_) {
        if (event.risk_score >= 8) critical++;
        else if (event.risk_score >= 5) high++;
        else if (event.risk_score >= 3) medium++;
        else low++;
    }
    
    // Create a custom paint