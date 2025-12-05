#include "StatusBar.hpp"
#include <QApplication>
#include <QDateTime>
#include <QTimer>
#include <QElapsedTimer>
#include <QProcess>
#include <QRegularExpression>
#include <QMenu>
#include <QAction>
#include <QClipboard>
#include <QMessageBox>
#include <QSysInfo>

#ifdef Q_OS_LINUX
#include <sys/sysinfo.h>
#elif defined(Q_OS_WIN)
#include <windows.h>
#elif defined(Q_OS_MAC)
#include <mach/mach.h>
#endif

StatusBar::StatusBar(QWidget* parent) 
    : QStatusBar(parent), showProgress_(false) {
    setupUI();
}

void StatusBar::setupUI() {
    setContentsMargins(5, 0, 5, 0);
    
    // Status label (left side, stretches)
    statusLabel_ = new QLabel(tr("Ready"));
    statusLabel_->setMinimumWidth(200);
    addWidget(statusLabel_, 1); // Stretch factor 1
    
    // Progress bar
    progressBar_ = new QProgressBar();
    progressBar_->setRange(0, 100);
    progressBar_->setTextVisible(true);
    progressBar_->setFormat("%p%");
    progressBar_->setMaximumWidth(150);
    progressBar_->setVisible(false);
    addWidget(progressBar_);
    
    // Memory usage label
    memoryUsage_ = new QLabel();
    memoryUsage_->setMinimumWidth(100);
    memoryUsage_->setAlignment(Qt::AlignRight);
    memoryUsage_->setToolTip(tr("System memory usage"));
    addWidget(memoryUsage_);
    
    // Connection status
    connectionStatus_ = new QLabel(tr("🔴 OLLAMA: Not Connected"));
    connectionStatus_->setMinimumWidth(150);
    connectionStatus_->setAlignment(Qt::AlignRight);
    connectionStatus_->setCursor(Qt::PointingHandCursor);
    connectionStatus_->setToolTip(tr("Click to test connection"));
    connect(connectionStatus_, &QLabel::linkActivated,
            this, &StatusBar::onConnectionStatusClicked);
    addPermanentWidget(connectionStatus_);
    
    // Clock
    clockLabel_ = new QLabel();
    clockLabel_->setMinimumWidth(80);
    clockLabel_->setAlignment(Qt::AlignRight);
    addPermanentWidget(clockLabel_);
    
    // Setup clock timer
    clockTimer_ = new QTimer(this);
    clockTimer_->setInterval(1000); // Update every second
    connect(clockTimer_, &QTimer::timeout, this, &StatusBar::updateClock);
    clockTimer_->start();
    
    // Initial updates
    updateClock();
    showMemoryUsage();
    
    // Setup memory update timer (every 5 seconds)
    QTimer* memoryTimer = new QTimer(this);
    memoryTimer->setInterval(5000);
    connect(memoryTimer, &QTimer::timeout, this, &StatusBar::showMemoryUsage);
    memoryTimer->start();
}

void StatusBar::showMessage(const QString& message, int timeout) {
    statusLabel_->setText(message);
    QStatusBar::showMessage(message, timeout);
}

void StatusBar::showProgress(const QString& message, int minimum, int maximum) {
    showProgress_ = true;
    progressMessage_ = message;
    
    progressBar_->setRange(minimum, maximum);
    progressBar_->setValue(minimum);
    progressBar_->setVisible(true);
    
    statusLabel_->setText(message);
    progressTimer_.start();
}

void StatusBar::updateProgress(int value) {
    if (showProgress_) {
        progressBar_->setValue(value);
        
        // Calculate estimated time remaining
        if (value > progressBar_->minimum()) {
            qint64 elapsed = progressTimer_.elapsed();
            double speed = static_cast<double>(value - progressBar_->minimum()) / elapsed;
            int remaining = static_cast<int>((progressBar_->maximum() - value) / speed / 1000);
            
            if (remaining > 0) {
                QString timeStr;
                if (remaining < 60) {
                    timeStr = tr("%1 seconds").arg(remaining);
                } else if (remaining < 3600) {
                    timeStr = tr("%1 minutes").arg(remaining / 60);
                } else {
                    timeStr = tr("%1 hours").arg(remaining / 3600);
                }
                
                statusLabel_->setText(QString("%1 (%2 remaining)")
                                     .arg(progressMessage_).arg(timeStr));
            }
        }
    }
}

void StatusBar::hideProgress() {
    showProgress_ = false;
    progressBar_->setVisible(false);
    statusLabel_->setText(tr("Ready"));
}

void StatusBar::showConnectionStatus(bool connected, const QString& details) {
    if (connected) {
        connectionStatus_->setText(tr("🟢 OLLAMA: Connected"));
        connectionStatus_->setStyleSheet("color: green; font-weight: bold;");
        
        if (!details.isEmpty()) {
            connectionStatus_->setToolTip(details);
        }
    } else {
        connectionStatus_->setText(tr("🔴 OLLAMA: Not Connected"));
        connectionStatus_->setStyleSheet("color: red; font-weight: bold;");
        
        if (!details.isEmpty()) {
            connectionStatus_->setToolTip(tr("Click to reconnect: %1").arg(details));
        }
    }
}

void StatusBar::showMemoryUsage() {
#ifdef Q_OS_LINUX
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        double total = static_cast<double>(info.totalram) / (1024 * 1024);
        double free = static_cast<double>(info.freeram) / (1024 * 1024);
        double used = total - free;
        double percent = (used / total) * 100;
        
        memoryUsage_->setText(QString("RAM: %1%").arg(percent, 0, 'f', 1));
        
        // Color code based on usage
        if (percent > 90) {
            memoryUsage_->setStyleSheet("color: red; font-weight: bold;");
        } else if (percent > 70) {
            memoryUsage_->setStyleSheet("color: orange;");
        } else {
            memoryUsage_->setStyleSheet("color: green;");
        }
    }
#elif defined(Q_OS_WIN)
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (GlobalMemoryStatusEx(&memoryStatus)) {
        double total = static_cast<double>(memoryStatus.ullTotalPhys) / (1024 * 1024);
        double free = static_cast<double>(memoryStatus.ullAvailPhys) / (1024 * 1024);
        double used = total - free;
        double percent = (used / total) * 100;
        
        memoryUsage_->setText(QString("RAM: %1%").arg(percent, 0, 'f', 1));
        
        if (percent > 90) {
            memoryUsage_->setStyleSheet("color: red; font-weight: bold;");
        } else if (percent > 70) {
            memoryUsage_->setStyleSheet("color: orange;");
        } else {
            memoryUsage_->setStyleSheet("color: green;");
        }
    }
#elif defined(Q_OS_MAC)
    vm_size_t pageSize;
    mach_port_t machPort = mach_host_self();
    vm_statistics64_data_t vmStats;
    mach_msg_type_number_t count = sizeof(vmStats) / sizeof(natural_t);
    
    if (host_page_size(machPort, &pageSize) == KERN_SUCCESS &&
        host_statistics64(machPort, HOST_VM_INFO,
                         reinterpret_cast<host_info64_t>(&vmStats), &count) == KERN_SUCCESS) {
        quint64 total = vmStats.wire_count + vmStats.active_count + 
                       vmStats.inactive_count + vmStats.free_count;
        total *= pageSize;
        
        quint64 free = vmStats.free_count * pageSize;
        double used = static_cast<double>(total - free) / (1024 * 1024);
        double totalMB = static_cast<double>(total) / (1024 * 1024);
        double percent = (used / totalMB) * 100;
        
        memoryUsage_->setText(QString("RAM: %1%").arg(percent, 0, 'f', 1));
        
        if (percent > 90) {
            memoryUsage_->setStyleSheet("color: red; font-weight: bold;");
        } else if (percent > 70) {
            memoryUsage_->setStyleSheet("color: orange;");
        } else {
            memoryUsage_->setStyleSheet("color: green;");
        }
    }
#else
    // Generic fallback
    memoryUsage_->setText(tr("RAM: N/A"));
    memoryUsage_->setStyleSheet("color: gray;");
#endif
}

void StatusBar::updateClock() {
    QDateTime now = QDateTime::currentDateTime();
    clockLabel_->setText(now.toString("HH:mm:ss"));
    
    // Update tooltip with full date
    clockLabel_->setToolTip(now.toString("yyyy-MM-dd dddd"));
}

void StatusBar::onConnectionStatusClicked() {
    emit connectionTestRequested();
}