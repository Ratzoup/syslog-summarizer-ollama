#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>

class Config {
public:
    static Config& getInstance() {
        static Config instance;
        return instance;
    }
    
    // Load configuration from file
    bool load(const std::string& filepath = "config.json");
    
    // Save configuration to file
    bool save(const std::string& filepath = "config.json");
    
    // Get configuration values
    std::string getString(const std::string& key, const std::string& defaultValue = "") const;
    int getInt(const std::string& key, int defaultValue = 0) const;
    double getDouble(const std::string& key, double defaultValue = 0.0) const;
    bool getBool(const std::string& key, bool defaultValue = false) const;
    std::vector<std::string> getStringArray(const std::string& key) const;
    
    // Set configuration values
    void setString(const std::string& key, const std::string& value);
    void setInt(const std::string& key, int value);
    void setDouble(const std::string& key, double value);
    void setBool(const std::string& key, bool value);
    void setStringArray(const std::string& key, const std::vector<std::string>& values);
    
    // Check if key exists
    bool hasKey(const std::string& key) const;
    
    // Get all configuration as string
    std::string toString() const;
    
    // Reset to defaults
    void resetToDefaults();
    
private:
    Config();
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    // Helper methods
    std::string escapeJsonString(const std::string& str) const;
    std::string unescapeJsonString(const std::string& str) const;
    std::vector<std::string> parseJsonArray(const std::string& jsonArray) const;
    std::string createJsonArray(const std::vector<std::string>& values) const;
    
    // Configuration storage
    std::map<std::string, std::string> configMap_;
    std::string configFile_;
    
    // Default configuration
    void initDefaults();
};

// Configuration keys
namespace ConfigKeys {
    // OLLAMA Settings
    constexpr const char* OLLAMA_URL = "ollama.url";
    constexpr const char* DEFAULT_MODEL = "ollama.default_model";
    constexpr const char* USE_LLM = "ollama.enable";
    constexpr const char* REQUEST_TIMEOUT = "ollama.timeout";
    constexpr const char* MAX_TOKENS = "ollama.max_tokens";
    constexpr const char* TEMPERATURE = "ollama.temperature";
    
    // Application Settings
    constexpr const char* MINIMIZE_TO_TRAY = "app.minimize_to_tray";
    constexpr const char* AUTO_START = "app.auto_start";
    constexpr const char* CHECK_UPDATES = "app.check_updates";
    constexpr const char* MAX_LOG_SIZE = "app.max_log_size_mb";
    constexpr const char* REPORT_DIR = "app.report_directory";
    constexpr const char* RECENT_FILES = "app.recent_files";
    constexpr const char* WINDOW_GEOMETRY = "app.window_geometry";
    constexpr const char* WINDOW_STATE = "app.window_state";
    
    // Analysis Settings
    constexpr const char* RISK_THRESHOLD = "analysis.risk_threshold";
    constexpr const char* EMAIL_ALERTS = "analysis.email_alerts";
    constexpr const char* EMAIL_RECIPIENT = "analysis.email_recipient";
    constexpr const char* SOUND_ALERTS = "analysis.sound_alerts";
    constexpr const char* AUTO_ANALYZE = "analysis.auto_analyze";
    constexpr const char* SAVE_REPORTS = "analysis.auto_save_reports";
    
    // Security Patterns
    constexpr const char* CUSTOM_PATTERNS = "security.custom_patterns";
    constexpr const char* WHITELIST_IPS = "security.whitelist_ips";
    constexpr const char* BLACKLIST_IPS = "security.blacklist_ips";
    
    // UI Settings
    constexpr const char* THEME = "ui.theme";
    constexpr const char* FONT_SIZE = "ui.font_size";
    constexpr const char* SHOW_STATUSBAR = "ui.show_statusbar";
    constexpr const char* SHOW_TOOLBARS = "ui.show_toolbars";
    constexpr const char* LANGUAGE = "ui.language";
}

#endif // CONFIG_HPP