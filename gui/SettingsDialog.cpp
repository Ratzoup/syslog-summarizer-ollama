#include "SettingsDialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTextEdit>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardPaths>
#include <QSettings>
#include <QDir>
#include <QTimer>

SettingsDialog::SettingsDialog(QWidget* parent)
    : QDialog(parent), networkManager_(new QNetworkAccessManager(this)) {
    setupUI();
    loadSettings();
    
    connect(networkManager_, &QNetworkAccessManager::finished,
            this, &SettingsDialog::onConnectionTestFinished);
}

void SettingsDialog::setupUI() {
    setWindowTitle(tr("Settings"));
    setWindowIcon(QIcon(":/icons/settings.png"));
    setMinimumSize(600, 500);
    
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Create tab widget
    QTabWidget* tabWidget = new QTabWidget();
    
    // OLLAMA Settings Tab
    QWidget* ollamaTab = new QWidget();
    QVBoxLayout* ollamaLayout = new QVBoxLayout(ollamaTab);
    
    QGroupBox* connectionGroup = new QGroupBox(tr("Connection Settings"));
    QFormLayout* connectionLayout = new QFormLayout(connectionGroup);
    
    ollamaUrlEdit_ = new QLineEdit("http://localhost:11434");
    ollamaUrlEdit_->setPlaceholderText("http://localhost:11434");
    connectionLayout->addRow(tr("OLLAMA URL:"), ollamaUrlEdit_);
    
    modelCombo_ = new QComboBox();
    modelCombo_->setEditable(true);
    modelCombo_->addItem("llama3");
    modelCombo_->addItem("mistral");
    modelCombo_->addItem("cogito");
    connectionLayout->addRow(tr("Default Model:"), modelCombo_);
    
    useLLMCheck_ = new QCheckBox(tr("Enable LLM Analysis"));
    useLLMCheck_->setChecked(true);
    connectionLayout->addRow(tr(""), useLLMCheck_);
    
    ollamaLayout->addWidget(connectionGroup);
    
    QGroupBox* generationGroup = new QGroupBox(tr("Generation Settings"));
    QFormLayout* generationLayout = new QFormLayout(generationGroup);
    
    timeoutSpin_ = new QSpinBox();
    timeoutSpin_->setRange(10, 300);
    timeoutSpin_->setValue(30);
    timeoutSpin_->setSuffix(" seconds");
    generationLayout->addRow(tr("Request Timeout:"), timeoutSpin_);
    
    maxTokensSpin_ = new QSpinBox();
    maxTokensSpin_->setRange(100, 4096);
    maxTokensSpin_->setValue(1024);
    maxTokensSpin_->setSuffix(" tokens");
    generationLayout->addRow(tr("Max Tokens:"), maxTokensSpin_);
    
    temperatureSpin_ = new QDoubleSpinBox();
    temperatureSpin_->setRange(0.0, 2.0);
    temperatureSpin_->setValue(0.3);
    temperatureSpin_->setSingleStep(0.1);
    generationLayout->addRow(tr("Temperature:"), temperatureSpin_);
    
    ollamaLayout->addWidget(generationGroup);
    
    // Connection test button
    QHBoxLayout* testLayout = new QHBoxLayout();
    testButton_ = new QPushButton(tr("Test Connection"));
    testButton_->setIcon(QIcon(":/icons/test.png"));
    connect(testButton_, &QPushButton::clicked, this, &SettingsDialog::onTestConnection);
    
    refreshButton_ = new QPushButton(tr("Refresh Models"));
    refreshButton_->setIcon(QIcon(":/icons/refresh.png"));
    connect(refreshButton_, &QPushButton::clicked, this, &SettingsDialog::onRefreshModels);
    
    testLayout->addWidget(testButton_);
    testLayout->addWidget(refreshButton_);
    testLayout->addStretch();
    
    ollamaLayout->addLayout(testLayout);
    ollamaLayout->addStretch();
    
    tabWidget->addTab(ollamaTab, tr("OLLAMA"));
    
    // Application Settings Tab
    QWidget* appTab = new QWidget();
    QVBoxLayout* appLayout = new QVBoxLayout(appTab);
    
    QGroupBox* behaviorGroup = new QGroupBox(tr("Application Behavior"));
    QFormLayout* behaviorLayout = new QFormLayout(behaviorGroup);
    
    trayCheck_ = new QCheckBox(tr("Minimize to system tray"));
    trayCheck_->setChecked(true);
    behaviorLayout->addRow(tr(""), trayCheck_);
    
    autoStartCheck_ = new QCheckBox(tr("Start with system"));
    autoStartCheck_->setChecked(false);
    behaviorLayout->addRow(tr(""), autoStartCheck_);
    
    updateCheck_ = new QCheckBox(tr("Check for updates on startup"));
    updateCheck_->setChecked(true);
    behaviorLayout->addRow(tr(""), updateCheck_);
    
    maxLogSizeSpin_ = new QSpinBox();
    maxLogSizeSpin_->setRange(1, 1000);
    maxLogSizeSpin_->setValue(100);
    maxLogSizeSpin_->setSuffix(" MB");
    behaviorLayout->addRow(tr("Max Log File Size:"), maxLogSizeSpin_);
    
    reportDirEdit_ = new QLineEdit();
    reportDirEdit_->setPlaceholderText(tr("Default: User documents folder"));
    
    QPushButton* browseButton = new QPushButton(tr("Browse..."));
    connect(browseButton, &QPushButton::clicked, this, [this]() {
        QString dir = QFileDialog::getExistingDirectory(
            this, tr("Select Report Directory"), reportDirEdit_->text());
        if (!dir.isEmpty()) {
            reportDirEdit_->setText(dir);
        }
    });
    
    QHBoxLayout* dirLayout = new QHBoxLayout();
    dirLayout->addWidget(reportDirEdit_);
    dirLayout->addWidget(browseButton);
    behaviorLayout->addRow(tr("Report Directory:"), dirLayout);
    
    appLayout->addWidget(behaviorGroup);
    appLayout->addStretch();
    
    tabWidget->addTab(appTab, tr("Application"));
    
    // Analysis Settings Tab
    QWidget* analysisTab = new QWidget();
    QVBoxLayout* analysisLayout = new QVBoxLayout(analysisTab);
    
    QGroupBox* riskGroup = new QGroupBox(tr("Risk Assessment"));
    QFormLayout* riskLayout = new QFormLayout(riskGroup);
    
    riskThresholdSpin_ = new QSpinBox();
    riskThresholdSpin_->setRange(0, 10);
    riskThresholdSpin_->setValue(5);
    riskLayout->addRow(tr("Risk Threshold (Alert):"), riskThresholdSpin_);
    
    analysisLayout->addWidget(riskGroup);
    
    QGroupBox* alertGroup = new QGroupBox(tr("Alerts & Notifications"));
    QFormLayout* alertLayout = new QFormLayout(alertGroup);
    
    emailAlertsCheck_ = new QCheckBox(tr("Enable email alerts"));
    emailAlertsCheck_->setChecked(false);
    alertLayout->addRow(tr(""), emailAlertsCheck_);
    
    emailRecipientEdit_ = new QLineEdit();
    emailRecipientEdit_->setPlaceholderText("admin@example.com");
    emailRecipientEdit_->setEnabled(false);
    connect(emailAlertsCheck_, &QCheckBox::toggled,
            emailRecipientEdit_, &QLineEdit::setEnabled);
    alertLayout->addRow(tr("Email Recipient:"), emailRecipientEdit_);
    
    soundAlertsCheck_ = new QCheckBox(tr("Enable sound alerts"));
    soundAlertsCheck_->setChecked(true);
    alertLayout->addRow(tr(""), soundAlertsCheck_);
    
    analysisLayout->addWidget(alertGroup);
    analysisLayout->addStretch();
    
    tabWidget->addTab(analysisTab, tr("Analysis"));
    
    mainLayout->addWidget(tabWidget);
    
    // Dialog buttons
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    
    saveButton_ = new QPushButton(tr("Save"));
    saveButton_->setIcon(QIcon(":/icons/save.png"));
    connect(saveButton_, &QPushButton::clicked, this, &SettingsDialog::onSaveSettings);
    
    defaultsButton_ = new QPushButton(tr("Restore Defaults"));
    defaultsButton_->setIcon(QIcon(":/icons/defaults.png"));
    connect(defaultsButton_, &QPushButton::clicked, this, &SettingsDialog::onRestoreDefaults);
    
    cancelButton_ = new QPushButton(tr("Cancel"));
    cancelButton_->setIcon(QIcon(":/icons/cancel.png"));
    connect(cancelButton_, &QPushButton::clicked, this, &QDialog::reject);
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(saveButton_);
    buttonLayout->addWidget(defaultsButton_);
    buttonLayout->addWidget(cancelButton_);
    
    mainLayout->addLayout(buttonLayout);
}

void SettingsDialog::setCurrentSettings(const QString& model, bool useLLM, bool minimizeToTray) {
    modelCombo_->setCurrentText(model);
    useLLMCheck_->setChecked(useLLM);
    trayCheck_->setChecked(minimizeToTray);
}

void SettingsDialog::updateModelList(const std::vector<std::string>& models) {
    modelCombo_->clear();
    for (const auto& model : models) {
        modelCombo_->addItem(QString::fromStdString(model));
    }
    
    // Try to restore the previously selected model
    QSettings settings;
    QString lastModel = settings.value("model", "llama3").toString();
    int index = modelCombo_->findText(lastModel);
    if (index >= 0) {
        modelCombo_->setCurrentIndex(index);
    }
}

void SettingsDialog::onTestConnection() {
    QString url = ollamaUrlEdit_->text().trimmed();
    if (url.isEmpty()) {
        QMessageBox::warning(this, tr("Connection Error"),
                           tr("Please enter an OLLAMA URL."));
        return;
    }
    
    // Test connection by getting available models
    QNetworkRequest request(QUrl(url + "/api/tags"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setHeader(QNetworkRequest::UserAgentHeader, "LogSummarizer/1.0");
    
    testButton_->setEnabled(false);
    testButton_->setText(tr("Testing..."));
    
    networkManager_->get(request);
}

void SettingsDialog::onRefreshModels() {
    onTestConnection(); // Refresh does the same as test for now
}

void SettingsDialog::onConnectionTestFinished(QNetworkReply* reply) {
    testButton_->setEnabled(true);
    testButton_->setText(tr("Test Connection"));
    
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray response = reply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response);
        
        if (jsonDoc.isObject()) {
            QJsonObject jsonObj = jsonDoc.object();
            
            if (jsonObj.contains("models")) {
                QJsonArray modelsArray = jsonObj["models"].toArray();
                std::vector<std::string> models;
                
                for (const QJsonValue& value : modelsArray) {
                    QJsonObject modelObj = value.toObject();
                    if (modelObj.contains("name")) {
                        models.push_back(modelObj["name"].toString().toStdString());
                    }
                }
                
                updateModelList(models);
                
                QMessageBox::information(this, tr("Connection Successful"),
                                       tr("Successfully connected to OLLAMA.\nFound %1 models.")
                                       .arg(models.size()));
            } else {
                QMessageBox::warning(this, tr("Connection Warning"),
                                   tr("Connected but no models found."));
            }
        } else {
            QMessageBox::warning(this, tr("Connection Error"),
                               tr("Invalid response from OLLAMA server."));
        }
    } else {
        QMessageBox::critical(this, tr("Connection Failed"),
                            tr("Failed to connect to OLLAMA:\n%1")
                            .arg(reply->errorString()));
    }
    
    reply->deleteLater();
}

void SettingsDialog::onSaveSettings() {
    saveCurrentSettings();
    emit settingsChanged();
    accept();
}

void SettingsDialog::onRestoreDefaults() {
    int result = QMessageBox::question(this, tr("Restore Defaults"),
                                      tr("Are you sure you want to restore all settings to defaults?"),
                                      QMessageBox::Yes | QMessageBox::No);
    
    if (result == QMessageBox::Yes) {
        ollamaUrlEdit_->setText("http://localhost:11434");
        modelCombo_->setCurrentText("llama3");
        useLLMCheck_->setChecked(true);
        timeoutSpin_->setValue(30);
        maxTokensSpin_->setValue(1024);
        temperatureSpin_->setValue(0.3);
        
        trayCheck_->setChecked(true);
        autoStartCheck_->setChecked(false);
        updateCheck_->setChecked(true);
        maxLogSizeSpin_->setValue(100);
        reportDirEdit_->clear();
        
        riskThresholdSpin_->setValue(5);
        emailAlertsCheck_->setChecked(false);
        emailRecipientEdit_->clear();
        soundAlertsCheck_->setChecked(true);
    }
}

void SettingsDialog::loadSettings() {
    QSettings settings;
    
    ollamaUrlEdit_->setText(settings.value("ollama_url", "http://localhost:11434").toString());
    modelCombo_->setCurrentText(settings.value("model", "llama3").toString());
    useLLMCheck_->setChecked(settings.value("use_llm", true).toBool());
    timeoutSpin_->setValue(settings.value("timeout", 30).toInt());
    maxTokensSpin_->setValue(settings.value("max_tokens", 1024).toInt());
    temperatureSpin_->setValue(settings.value("temperature", 0.3).toDouble());
    
    trayCheck_->setChecked(settings.value("minimize_to_tray", true).toBool());
    autoStartCheck_->setChecked(settings.value("auto_start", false).toBool());
    updateCheck_->setChecked(settings.value("check_updates", true).toBool());
    maxLogSizeSpin_->setValue(settings.value("max_log_size", 100).toInt());
    reportDirEdit_->setText(settings.value("report_dir", "").toString());
    
    riskThresholdSpin_->setValue(settings.value("risk_threshold", 5).toInt());
    emailAlertsCheck_->setChecked(settings.value("email_alerts", false).toBool());
    emailRecipientEdit_->setText(settings.value("email_recipient", "").toString());
    soundAlertsCheck_->setChecked(settings.value("sound_alerts", true).toBool());
}

void SettingsDialog::saveCurrentSettings() {
    QSettings settings;
    
    settings.setValue("ollama_url", ollamaUrlEdit_->text());
    settings.setValue("model", modelCombo_->currentText());
    settings.setValue("use_llm", useLLMCheck_->isChecked());
    settings.setValue("timeout", timeoutSpin_->value());
    settings.setValue("max_tokens", maxTokensSpin_->value());
    settings.setValue("temperature", temperatureSpin_->value());
    
    settings.setValue("minimize_to_tray", trayCheck_->isChecked());
    settings.setValue("auto_start", autoStartCheck_->isChecked());
    settings.setValue("check_updates", updateCheck_->isChecked());
    settings.setValue("max_log_size", maxLogSizeSpin_->value());
    settings.setValue("report_dir", reportDirEdit_->text());
    
    settings.setValue("risk_threshold", riskThresholdSpin_->value());
    settings.setValue("email_alerts", emailAlertsCheck_->isChecked());
    settings.setValue("email_recipient", emailRecipientEdit_->text());
    settings.setValue("sound_alerts", soundAlertsCheck_->isChecked());
    
    settings.sync();
}