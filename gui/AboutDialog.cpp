#include "AboutDialog.hpp"
#include <QApplication>
#include <QDateTime>
#include <QSysInfo>
#include <QScreen>
#include <QStyle>
#include <QIcon>
#include <QFont>
#include <QFontMetrics>
#include <QClipboard>
#include <QMessageBox>
#include <QLibraryInfo>

AboutDialog::AboutDialog(QWidget* parent) 
    : QDialog(parent) {
    setupUI();
    setWindowTitle(tr("About Log Summarizer"));
    setWindowIcon(QIcon(":/icons/app_icon.png"));
    setMinimumSize(500, 400);
}

void AboutDialog::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    
    // Header with icon and title
    QHBoxLayout* headerLayout = new QHBoxLayout();
    
    iconLabel_ = new QLabel();
    iconLabel_->setPixmap(QIcon(":/icons/app_icon.png").pixmap(64, 64));
    iconLabel_->setAlignment(Qt::AlignCenter);
    
    QVBoxLayout* titleLayout = new QVBoxLayout();
    titleLabel_ = new QLabel(tr("Log Summarizer"));
    QFont titleFont = titleLabel_->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel_->setFont(titleFont);
    titleLabel_->setAlignment(Qt::AlignCenter);
    
    versionLabel_ = new QLabel(tr("Version 1.0.0"));
    versionLabel_->setAlignment(Qt::AlignCenter);
    
    titleLayout->addWidget(titleLabel_);
    titleLayout->addWidget(versionLabel_);
    titleLayout->addStretch();
    
    headerLayout->addWidget(iconLabel_);
    headerLayout->addLayout(titleLayout);
    headerLayout->addStretch();
    
    mainLayout->addLayout(headerLayout);
    
    // Tab widget for different information sections
    tabWidget_ = new QTabWidget();
    
    // About tab
    aboutText_ = new QTextBrowser();
    aboutText_->setOpenExternalLinks(true);
    aboutText_->setHtml(getVersionInfo());
    aboutText_->setReadOnly(true);
    tabWidget_->addTab(aboutText_, tr("About"));
    
    // License tab
    licenseText_ = new QTextBrowser();
    licenseText_->setPlainText(getLicenseInfo());
    licenseText_->setReadOnly(true);
    tabWidget_->addTab(licenseText_, tr("License"));
    
    // Dependencies tab
    dependenciesText_ = new QTextBrowser();
    dependenciesText_->setPlainText(getDependenciesInfo());
    dependenciesText_->setReadOnly(true);
    tabWidget_->addTab(dependenciesText_, tr("Dependencies"));
    
    mainLayout->addWidget(tabWidget_, 1);
    
    // System information group
    infoGroup_ = new QGroupBox(tr("System Information"));
    infoLayout_ = new QFormLayout(infoGroup_);
    
    // Add system info
    infoLayout_->addRow(tr("Qt Version:"), new QLabel(QLibraryInfo::version().toString()));
    infoLayout_->addRow(tr("Build Date:"), new QLabel(__DATE__ " " __TIME__));
    infoLayout_->addRow(tr("Platform:"), new QLabel(QSysInfo::prettyProductName()));
    infoLayout_->addRow(tr("Architecture:"), new QLabel(QSysInfo::currentCpuArchitecture()));
    
    mainLayout->addWidget(infoGroup_);
    
    // Close button
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    QPushButton* copyInfoButton = new QPushButton(tr("Copy Info"));
    copyInfoButton->setIcon(QIcon(":/icons/copy.png"));
    connect(copyInfoButton, &QPushButton::clicked, this, [this]() {
        QString info = getVersionInfo() + "\n\n" + getDependenciesInfo();
        QApplication::clipboard()->setText(info);
        QMessageBox::information(this, tr("Information Copied"),
                               tr("Version and dependency information copied to clipboard."));
    });
    
    closeButton_ = new QPushButton(tr("Close"));
    closeButton_->setIcon(QIcon(":/icons/close.png"));
    connect(closeButton_, &QPushButton::clicked, this, &QDialog::accept);
    
    buttonLayout->addWidget(copyInfoButton);
    buttonLayout->addWidget(closeButton_);
    
    mainLayout->addLayout(buttonLayout);
}

QString AboutDialog::getVersionInfo() const {
    QString info;
    
    info += "<h2>Log Summarizer - Security Log Analysis Tool</h2>";
    info += "<p><strong>Version:</strong> 1.0.0</p>";
    info += "<p><strong>Build Date:</strong> " + QString(__DATE__) + " " + QString(__TIME__) + "</p>";
    info += "<p><strong>Description:</strong> Advanced security log analysis tool with AI-powered insights.</p>";
    info += "<hr>";
    
    info += "<h3>Features:</h3>";
    info += "<ul>";
    info += "<li>Multi-format log parsing (Syslog, Windows Event, JSON, CSV)</li>";
    info += "<li>AI-powered analysis using local LLM (OLLAMA integration)</li>";
    info += "<li>Real-time security event detection</li>";
    info += "<li>Comprehensive reporting and export capabilities</li>";
    info += "<li>Customizable detection rules and filters</li>";
    info += "<li>Professional GUI with dark theme</li>";
    info += "</ul>";
    
    info += "<h3>System Requirements:</h3>";
    info += "<ul>";
    info += "<li>CPU: x86-64 or ARM64 processor</li>";
    info += "<li>RAM: 4GB minimum, 8GB recommended</li>";
    info += "<li>Storage: 500MB free space</li>";
    info += "<li>OLLAMA with at least 4GB VRAM for LLM models</li>";
    info += "</ul>";
    
    info += "<h3>Contact & Support:</h3>";
    info += "<p>For support, feature requests, or bug reports:</p>";
    info += "<ul>";
    info += "<li>GitHub: <a href='https://github.com/example/log-summarizer'>github.com/example/log-summarizer</a></li>";
    info += "<li>Email: support@securitytools.example.com</li>";
    info += "<li>Documentation: <a href='https://docs.securitytools.example.com'>Online Documentation</a></li>";
    info += "</ul>";
    
    info += "<p><em>© 2024 Security Analytics Team. All rights reserved.</em></p>";
    
    return info;
}

QString AboutDialog::getLicenseInfo() const {
    QString license;
    
    license += "Log Summarizer - Security Log Analysis Tool\n";
    license += "Copyright (c) 2024 Security Analytics Team\n\n";
    
    license += "MIT License\n\n";
    
    license += "Permission is hereby granted, free of charge, to any person obtaining a copy\n";
    license += "of this software and associated documentation files (the \"Software\"), to deal\n";
    license += "in the Software without restriction, including without limitation the rights\n";
    license += "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n";
    license += "copies of the Software, and to permit persons to whom the Software is\n";
    license += "furnished to do so, subject to the following conditions:\n\n";
    
    license += "The above copyright notice and this permission notice shall be included in all\n";
    license += "copies or substantial portions of the Software.\n\n";
    
    license += "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n";
    license += "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n";
    license += "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n";
    license += "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n";
    license += "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n";
    license += "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n";
    license += "SOFTWARE.\n\n";
    
    license += "===========================================================================\n\n";
    
    license += "Third-Party Licenses:\n\n";
    
    license += "1. Qt Framework (LGPL v3)\n";
    license += "   Copyright (c) The Qt Company Ltd.\n";
    license += "   https://www.qt.io/\n\n";
    
    license += "2. OLLAMA\n";
    license += "   Copyright (c) OLLAMA Contributors\n";
    license += "   https://ollama.ai/\n\n";
    
    license += "3. JSON for Modern C++ (MIT)\n";
    license += "   Copyright (c) Niels Lohmann\n";
    license += "   https://github.com/nlohmann/json\n\n";
    
    license += "4. libcurl (MIT/X derivate)\n";
    license += "   Copyright (c) Daniel Stenberg\n";
    license += "   https://curl.se/\n\n";
    
    license += "===========================================================================\n\n";
    
    license += "Disclaimer:\n";
    license += "This software is provided for security analysis and educational purposes only.\n";
    license += "The authors are not responsible for any misuse or damage caused by this software.\n";
    license += "Always ensure you have proper authorization before analyzing any system logs.\n";
    
    return license;
}

QString AboutDialog::getDependenciesInfo() const {
    QString deps;
    
    deps += "Required Dependencies:\n";
    deps += "=====================\n\n";
    
    deps += "1. OLLAMA\n";
    deps += "   Version: 0.1.0 or later\n";
    deps += "   Purpose: Local LLM inference engine\n";
    deps += "   Website: https://ollama.ai/\n";
    deps += "   Installation: curl -fsSL https://ollama.ai/install.sh | sh\n\n";
    
    deps += "2. Qt Framework\n";
    deps += "   Version: 6.5.0 or later\n";
    deps += "   Purpose: GUI framework\n";
    deps += "   Modules: Core, Widgets, Network, PrintSupport\n";
    deps += "   Website: https://www.qt.io/\n\n";
    
    deps += "3. libcurl\n";
    deps += "   Version: 7.68.0 or later\n";
    deps += "   Purpose: HTTP client for OLLAMA API\n";
    deps += "   Website: https://curl.se/\n\n";
    
    deps += "4. JSON for Modern C++\n";
    deps += "   Version: 3.11.2 or later\n";
    deps += "   Purpose: JSON parsing and generation\n";
    deps += "   Website: https://github.com/nlohmann/json\n\n";
    
    deps += "Optional Dependencies:\n";
    deps += "=====================\n\n";
    
    deps += "1. LLM Models (for OLLAMA)\n";
    deps += "   - llama3: General purpose model\n";
    deps += "     Command: ollama pull llama3\n\n";
    deps += "   - mistral: Efficient bilingual model\n";
    deps += "     Command: ollama pull mistral\n\n";
    deps += "   - cogito: Specialized for security analysis\n";
    deps += "     Command: ollama pull cogito\n\n";
    
    deps += "2. Additional Parsers\n";
    deps += "   - libpcap: For PCAP file analysis\n";
    deps += "   - libxml2: For XML log parsing\n";
    deps += "   - zlib: For compressed log files\n\n";
    
    deps += "Build Dependencies:\n";
    deps += "==================\n\n";
    
    deps += "1. CMake\n";
    deps += "   Version: 3.16 or later\n";
    deps += "   Purpose: Build system\n\n";
    
    deps += "2. C++ Compiler\n";
    deps += "   - GCC 9.0 or later\n";
    deps += "   - Clang 10.0 or later\n";
    deps += "   - MSVC 2019 or later\n\n";
    
    deps += "3. Development Headers\n";
    deps += "   - qt6-base-dev\n";
    deps += "   - libcurl4-openssl-dev\n";
    deps += "   - libjsoncpp-dev\n\n";
    
    deps += "Installation Commands:\n";
    deps += "=====================\n\n";
    
    deps += "Ubuntu/Debian:\n";
    deps += "sudo apt-get update\n";
    deps += "sudo apt-get install build-essential cmake libcurl4-openssl-dev libjsoncpp-dev qt6-base-dev\n\n";
    
    deps += "macOS:\n";
    deps += "brew install cmake curl jsoncpp qt6\n\n";
    
    deps += "Windows:\n";
    deps += "vcpkg install curl jsoncpp\n";
    deps += "Download Qt installer from qt.io\n";
    
    return deps;
}