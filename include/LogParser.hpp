#ifndef LOG_PARSER_HPP
#define LOG_PARSER_HPP

#include "LogEntry.hpp"
#include <memory>
#include <vector>
#include <fstream>

class LogParser {
public:
    virtual ~LogParser() = default;
    
    // Factory method to create appropriate parser
    static std::unique_ptr<LogParser> create_parser(LogSource source);
    
    // Parse logs from file
    virtual std::vector<LogEntry> parse_file(const std::string& filepath) = 0;
    
    // Parse logs from string (for streaming)
    virtual std::vector<LogEntry> parse_string(const std::string& log_data) = 0;
    
    // Filter logs by severity
    static std::vector<LogEntry> filter_by_severity(
        const std::vector<LogEntry>& logs, 
        LogSeverity min_severity);
    
protected:
    virtual LogEntry parse_line(const std::string& line) = 0;
    
    // Helper methods for safe parsing
    std::string sanitize_input(const std::string& input) const;
    bool is_malicious_input(const std::string& input) const;
};

// Concrete parser implementations
class SyslogParser : public LogParser {
public:
    std::vector<LogEntry> parse_file(const std::string& filepath) override;
    std::vector<LogEntry> parse_string(const std::string& log_data) override;
    
private:
    LogEntry parse_line(const std::string& line) override;
};

class WindowsEventParser : public LogParser {
public:
    std::vector<LogEntry> parse_file(const std::string& filepath) override;
    std::vector<LogEntry> parse_string(const std::string& log_data) override;
    
private:
    LogEntry parse_line(const std::string& line) override;
    LogSeverity parse_event_level(int level) const;
};

class JSONLogParser : public LogParser {
public:
    std::vector<LogEntry> parse_file(const std::string& filepath) override;
    std::vector<LogEntry> parse_string(const std::string& log_data) override;
    
private:
    LogEntry parse_line(const std::string& line) override;
    LogEntry parse_json_object(const std::string& json_str);
};

#endif // LOG_PARSER_HPP