#ifndef LOGVIEWER_HPP
#define LOGVIEWER_HPP

#include <QWidget>
#include <QTextEdit>
#include <QSplitter>
#include <QTreeWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QProgressBar>
#include "LogEntry.hpp"

class LogViewer : public QWidget {
    Q_OBJECT
    
public:
    LogViewer(QWidget* parent = nullptr);
    
    void loadFile(const QString& filePath);
    void clear();
    QString getCurrentFile() const { return currentFile_; }
    
signals:
    void analysisRequested();
    
private slots:
    void onFilterChanged();
    void onSearchTextChanged(const QString& text);
    void onSeverityFilterChanged(int index);
    void onExportClicked();
    void onAnalyzeClicked();
    void updateStatistics();
    
private:
    void setupUI();
    void loadLogEntries(const std::vector<LogEntry>& entries);
    void applyFilters();
    void highlightSearchResults();
    void createSeverityDelegate();
    
    // UI Components
    QTextEdit* rawTextView_;
    QTableWidget* structuredView_;
    QTreeWidget* treeView_;
    QSplitter* mainSplitter_;
    
    // Filter controls
    QLineEdit* searchBox_;
    QComboBox* severityFilter_;
    QComboBox* sourceFilter_;
    QLineEdit* dateFrom_;
    QLineEdit* dateTo_;
    QCheckBox* showOnlySecurity_;
    QPushButton* applyFilterButton_;
    QPushButton* clearFilterButton_;
    
    // Statistics
    QLabel* totalLogsLabel_;
    QLabel* securityEventsLabel_;
    QLabel* criticalEventsLabel_;
    
    // Data
    QString currentFile_;
    std::vector<LogEntry> allEntries_;
    std::vector<LogEntry> filteredEntries_;
    
    // Search highlight
    QList<QTextEdit::ExtraSelection> searchSelections_;
};

#endif // LOGVIEWER_HPP