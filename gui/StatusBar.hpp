#ifndef STATUSBAR_HPP
#define STATUSBAR_HPP

#include <QStatusBar>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QHBoxLayout>
#include <QTimer>
#include <QElapsedTimer>

class StatusBar : public QStatusBar {
    Q_OBJECT
    
public:
    StatusBar(QWidget* parent = nullptr);
    
    void showMessage(const QString& message, int timeout = 0) override;
    void showProgress(const QString& message, int minimum = 0, int maximum = 100);
    void updateProgress(int value);
    void hideProgress();
    void showConnectionStatus(bool connected, const QString& details = "");
    void showMemoryUsage();
    
signals:
    void connectionTestRequested();
    
private slots:
    void updateClock();
    void onConnectionStatusClicked();
    
private:
    void setupUI();
    
    // Status widgets
    QLabel* statusLabel_;
    QProgressBar* progressBar_;
    QLabel* connectionStatus_;
    QLabel* memoryUsage_;
    QLabel* clockLabel_;
    
    // Timers
    QTimer* clockTimer_;
    QElapsedTimer progressTimer_;
    
    // Progress tracking
    bool showProgress_;
    QString progressMessage_;
};

#endif // STATUSBAR_HPP