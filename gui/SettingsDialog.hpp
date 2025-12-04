#ifndef SETTINGSDIALOG_HPP
#define SETTINGSDIALOG_HPP

#include <QDialog>
#include <QTabWidget>
#include <QGroupBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTextEdit>
#include <QNetworkAccessManager>

class SettingsDialog : public QDialog {
    Q_OBJECT
    
public:
    SettingsDialog(QWidget* parent = nullptr);
    
    void setCurrentSettings(const QString& model, bool useLLM, bool minimizeToTray);
    QString getSelectedModel() const { return modelCombo_->currentText(); }
    bool useLLM() const { return useLLMCheck_->isChecked(); }
    bool minimizeToTray() const { return trayCheck_->isChecked(); }
    
    void updateModelList(const std::vector<std::string>& models);
    
signals:
    void settingsChanged();
    
private slots:
    void onTestConnection();
    void onRefreshModels();
    void onSaveSettings();
    void onRestoreDefaults();
    void onConnectionTestFinished();
    
private:
    void setupUI();
    void loadSettings();
    void saveCurrentSettings();
    
    // OLLAMA Settings
    QLineEdit* ollamaUrlEdit_;
    QComboBox* modelCombo_;
    QCheckBox* useLLMCheck_;
    QSpinBox* timeoutSpin_;
    QSpinBox* maxTokensSpin_;
    QDoubleSpinBox* temperatureSpin_;
    
    // Application Settings
    QCheckBox* trayCheck_;
    QCheckBox* autoStartCheck_;
    QCheckBox* updateCheck_;
    QSpinBox* maxLogSizeSpin_;
    QLineEdit* reportDirEdit_;
    
    // Analysis Settings
    QSpinBox* riskThresholdSpin_;
    QCheckBox* emailAlertsCheck_;
    QLineEdit* emailRecipientEdit_;
    QCheckBox* soundAlertsCheck_;
    
    // Network
    QNetworkAccessManager* networkManager_;
    
    // Buttons
    QPushButton* testButton_;
    QPushButton* refreshButton_;
    QPushButton* saveButton_;
    QPushButton* defaultsButton_;
    QPushButton* cancelButton_;
};

#endif // SETTINGSDIALOG_HPP