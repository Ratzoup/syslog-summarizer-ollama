#ifndef ABOUTDIALOG_HPP
#define ABOUTDIALOG_HPP

#include <QDialog>
#include <QLabel>
#include <QTextBrowser>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QGroupBox>
#include <QFormLayout>

class AboutDialog : public QDialog {
    Q_OBJECT
    
public:
    AboutDialog(QWidget* parent = nullptr);
    
private:
    void setupUI();
    QString getVersionInfo() const;
    QString getLicenseInfo() const;
    QString getDependenciesInfo() const;
    
    // UI Components
    QTabWidget* tabWidget_;
    QLabel* iconLabel_;
    QLabel* titleLabel_;
    QLabel* versionLabel_;
    QTextBrowser* aboutText_;
    QTextBrowser* licenseText_;
    QTextBrowser* dependenciesText_;
    QPushButton* closeButton_;
    
    // Info sections
    QGroupBox* infoGroup_;
    QFormLayout* infoLayout_;
};

#endif // ABOUTDIALOG_HPP