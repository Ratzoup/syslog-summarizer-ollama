#ifndef LOG_ENTRY_HPP
#define LOG_ENTRY_HPP

#include <string>
#include <vector>
#include <chrono>
#include <map>

enum class LogSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

enum class LogSource {
    SYSLOG,
    WINDOWS_EVENT,
    CSV,
    JSON,
    PCAP,
    VULN_SCAN
};

struct LogEntry {
    std::string timestamp;
    std::string source_host;
    std::string process;
    std::string message;
    LogSeverity severity;
    LogSource source_type;
    int event_id;
    std::map<std::string, std::string> additional_fields;
    
    // Constructor
    LogEntry() : event_id(0), severity(LogSeverity::INFO), 
                source_type(LogSource::SYSLOG) {}
    
    std::string to_string() const;
    std::string severity_to_string() const;
};

struct SecurityEvent {
    std::string event_type;  // e.g., "FailedLogin", "PrivilegeEscalation"
    LogEntry log_entry;
    int risk_score;
    std::vector<std::string> indicators;
    std::string description;
    
    SecurityEvent() : risk_score(0) {}
};

#endif // LOG_ENTRY_HPP