#ifndef ANALYSISPANEL_HPP
#define ANALYSISPANEL_HPP

#include <QWidget>
#include <QSplitter>
#include <QTextBrowser>
#include <QTableWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include "LogEntry.hpp"

class AnalysisPanel : public QWidget {
    Q_OBJECT
    
public:
    AnalysisPanel(QWidget* parent = nullptr);
    
    void displayResults(const QString& summary, 
                       const std::vector<SecurityEvent>& events);
    void clearResults();
    QString generateReport() const;
    
    void addEvent(const SecurityEvent& event);
    void updateSummary(const QString& summary);
    
private slots:
    void onEventSelected(int row, int column);
    void onTreeItemSelected(QTreeWidgetItem* item, int column);
    void onExportDetails();
    void onCopyToClipboard();
    void onShowRawLog();
    
private:
    void setupUI();
    void setupEventTable();
    void setupEventTree();
    void updateStatistics();
    void createRiskVisualization();
    QString generateHTMLReport() const;
    
    // UI Components
    QTextBrowser* summaryView_;
    QTableWidget* eventTable_;
    QTreeWidget* eventTree_;
    QTabWidget* detailsTab_;
    QSplitter* mainSplitter_;
    
    // Controls
    QPushButton* exportButton_;
    QPushButton* copyButton_;
    QPushButton* detailsButton_;
    
    // Statistics display
    QLabel* totalEventsLabel_;
    QLabel* highRiskLabel_;
    QLabel* avgRiskLabel_;
    
    // Data
    std::vector<SecurityEvent> currentEvents_;
    QString currentSummary_;
    
    // Risk visualization
    QWidget* riskVisualization_;
};

#endif // ANALYSISPANEL_HPP