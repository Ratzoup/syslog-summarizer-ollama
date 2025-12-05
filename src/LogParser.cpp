#include "LogParser.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <iostream>
#include <json/json.h>
#include <ctime>
#include <iomanip>

// ============================================================================
// LogEntry Implementation
// ============================================================================

std::string LogEntry::to_string() const {
    std::stringstream ss;
    ss << "[" << timestamp << "] ";
    ss << severity_to_string() << " ";
    ss << source_host << " ";
    ss << process << ": ";
    ss << message;
    return ss.str();
}

std::string LogEntry::severity_to_string() const {
    switch (severity) {
        case LogSeverity::INFO: return "INFO";
        case LogSeverity::WARNING: return "WARNING";
        case LogSeverity::ERROR: return "ERROR";
        case LogSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// LogParser Base Implementation
// ============================================================================

std::unique_ptr<LogParser> LogParser::create_parser(LogSource source) {
    switch (source) {
        case LogSource::SYSLOG:
            return std::make_unique<SyslogParser>();
        case LogSource::WINDOWS_EVENT:
            return std::make_unique<WindowsEventParser>();
        case LogSource::JSON:
            return std::make_unique<JSONLogParser>();
        case LogSource::CSV:
            // CSVParser implementation would go here
            throw std::runtime_error("CSV parser not implemented");
        case LogSource::PCAP:
            // PCAPParser implementation would go here
            throw std::runtime_error("PCAP parser not implemented");
        case LogSource::VULN_SCAN:
            // VulnScanParser implementation would go here
            throw std::runtime_error("Vulnerability scan parser not implemented");
        default:
            throw std::runtime_error("Unknown log source type");
    }
}

std::vector<LogEntry> LogParser::filter_by_severity(
    const std::vector<LogEntry>& logs, 
    LogSeverity min_severity) {
    
    std::vector<LogEntry> filtered;
    std::copy_if(logs.begin(), logs.end(), std::back_inserter(filtered),
        [min_severity](const LogEntry& entry) {
            return static_cast<int>(entry.severity) >= static_cast<int>(min_severity);
        });
    return filtered;
}

std::string LogParser::sanitize_input(const std::string& input) const {
    // Remove null characters and control characters (except newline and tab)
    std::string sanitized;
    sanitized.reserve(input.size());
    
    for (char c : input) {
        if (c == '\0') {
            continue; // Remove null characters
        }
        
        // Keep printable characters, newlines, and tabs
        if (std::isprint(static_cast<unsigned char>(c)) || c == '\n' || c == '\t') {
            sanitized.push_back(c);
        } else {
            // Replace control characters with space
            sanitized.push_back(' ');
        }
    }
    
    return sanitized;
}

bool LogParser::is_malicious_input(const std::string& input) const {
    // Basic security checks for malicious patterns
    static const std::vector<std::regex> malicious_patterns = {
        // Command injection patterns
        std::regex(R"((\bexec\s*\(|\bsystem\s*\(|\bpopen\s*\())", std::regex::icase),
        std::regex(R"(\|\s*\/bin\/bash|\|\s*\/bin\/sh)", std::regex::icase),
        
        // Path traversal
        std::regex(R"(\.\.\/)", std::regex::icase),
        
        // SQL injection patterns (simplified)
        std::regex(R"((\bunion\s+select|\bdrop\s+table|\bdelete\s+from))", std::regex::icase),
        
        // XSS patterns
        std::regex(R"(<script[^>]*>.*?</script>)", std::regex::icase),
        std::regex(R"(\bjavascript\s*:)", std::regex::icase),
        
        // Suspicious encoded patterns
        std::regex(R"(%00|%0a|%0d|%2f%2e%2e%2f)", std::regex::icase)
    };
    
    for (const auto& pattern : malicious_patterns) {
        if (std::regex_search(input, pattern)) {
            return true;
        }
    }
    
    // Check for overly long lines (potential DoS)
    if (input.length() > 10000) {
        return true;
    }
    
    return false;
}

// ============================================================================
// SyslogParser Implementation
// ============================================================================

std::vector<LogEntry> SyslogParser::parse_file(const std::string& filepath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // Skip empty lines
        if (line.empty()) {
            continue;
        }
        
        // Security check
        if (is_malicious_input(line)) {
            std::cerr << "Warning: Skipping potentially malicious input at line " 
                     << line_number << std::endl;
            continue;
        }
        
        try {
            LogEntry entry = parse_line(line);
            entries.push_back(entry);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse line " << line_number 
                     << ": " << e.what() << std::endl;
            // Continue parsing other lines
        }
    }
    
    return entries;
}

std::vector<LogEntry> SyslogParser::parse_string(const std::string& log_data) {
    std::vector<LogEntry> entries;
    std::stringstream ss(log_data);
    std::string line;
    int line_number = 0;
    
    while (std::getline(ss, line)) {
        line_number++;
        
        if (line.empty()) {
            continue;
        }
        
        if (is_malicious_input(line)) {
            std::cerr << "Warning: Skipping potentially malicious input at line " 
                     << line_number << std::endl;
            continue;
        }
        
        try {
            LogEntry entry = parse_line(line);
            entries.push_back(entry);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse line " << line_number 
                     << ": " << e.what() << std::endl;
        }
    }
    
    return entries;
}

LogEntry SyslogParser::parse_line(const std::string& line) {
    LogEntry entry;
    entry.source_type = LogSource::SYSLOG;
    
    // Syslog pattern examples:
    // Traditional: Jan  1 10:00:00 hostname process[pid]: message
    // RFC 5424: <priority>timestamp hostname process pid - - message
    
    static const std::regex traditional_pattern(
        R"(^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)$)"
    );
    
    static const std::regex rfc5424_pattern(
        R"(^<(\d+)>(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\S+)\s+(\S+)\s+(\d+)\s+- - (.*)$)"
    );
    
    std::smatch match;
    
    // Try RFC 5424 format first
    if (std::regex_match(line, match, rfc5424_pattern)) {
        // Parse priority (facility * 8 + severity)
        int priority = std::stoi(match[1].str());
        int severity_code = priority % 8;
        
        entry.timestamp = match[2].str();
        entry.source_host = sanitize_input(match[3].str());
        entry.process = sanitize_input(match[4].str());
        // match[5] is PID
        
        // Parse message, remove BOM if present
        std::string message = match[6].str();
        if (message.size() >= 3 && 
            static_cast<unsigned char>(message[0]) == 0xEF &&
            static_cast<unsigned char>(message[1]) == 0xBB &&
            static_cast<unsigned char>(message[2]) == 0xBF) {
            message = message.substr(3);
        }
        entry.message = sanitize_input(message);
        
        // Map syslog severity to our enum
        switch (severity_code) {
            case 0: // Emergency
            case 1: // Alert
            case 2: // Critical
                entry.severity = LogSeverity::CRITICAL;
                break;
            case 3: // Error
                entry.severity = LogSeverity::ERROR;
                break;
            case 4: // Warning
                entry.severity = LogSeverity::WARNING;
                break;
            case 5: // Notice
            case 6: // Informational
            case 7: // Debug
            default:
                entry.severity = LogSeverity::INFO;
                break;
        }
        
    } 
    // Try traditional format
    else if (std::regex_match(line, match, traditional_pattern)) {
        // Parse timestamp (add current year if missing)
        std::string timestamp = match[1].str();
        std::time_t now = std::time(nullptr);
        std::tm* tm_now = std::localtime(&now);
        int current_year = tm_now->tm_year + 1900;
        
        // Check if year is missing (traditional syslog format)
        if (timestamp.find('-') == std::string::npos) {
            std::stringstream full_timestamp;
            full_timestamp << current_year << " " << timestamp;
            entry.timestamp = full_timestamp.str();
        } else {
            entry.timestamp = timestamp;
        }
        
        entry.source_host = sanitize_input(match[2].str());
        entry.process = sanitize_input(match[3].str());
        
        // Parse PID if available
        if (match[4].matched) {
            try {
                entry.event_id = std::stoi(match[4].str());
            } catch (...) {
                // PID might not be numeric
            }
        }
        
        entry.message = sanitize_input(match[5].str());
        
        // Determine severity from message content
        entry.severity = determine_severity_from_message(entry.message);
        
    } else {
        // Fallback: treat entire line as message
        entry.message = sanitize_input(line);
        entry.severity = LogSeverity::INFO;
        entry.timestamp = get_current_timestamp();
        
        // Try to extract hostname and process from common patterns
        extract_metadata_from_message(line, entry);
    }
    
    return entry;
}

LogSeverity SyslogParser::determine_severity_from_message(const std::string& message) {
    std::string lower_msg = message;
    std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    
    // Check for critical indicators
    static const std::vector<std::string> critical_indicators = {
        "fatal", "panic", "emergency", "hardware error", "kernel panic",
        "out of memory", "disk full", "filesystem full", "corruption"
    };
    
    for (const auto& indicator : critical_indicators) {
        if (lower_msg.find(indicator) != std::string::npos) {
            return LogSeverity::CRITICAL;
        }
    }
    
    // Check for error indicators
    static const std::vector<std::string> error_indicators = {
        "error", "failed", "failure", "unable to", "cannot",
        "invalid", "illegal", "bad", "rejected", "denied"
    };
    
    for (const auto& indicator : error_indicators) {
        if (lower_msg.find(indicator) != std::string::npos) {
            return LogSeverity::ERROR;
        }
    }
    
    // Check for warning indicators
    static const std::vector<std::string> warning_indicators = {
        "warning", "warn", "caution", "attention", "notice",
        "deprecated", "obsolete", "slow", "timeout", "retry"
    };
    
    for (const auto& indicator : warning_indicators) {
        if (lower_msg.find(indicator) != std::string::npos) {
            return LogSeverity::WARNING;
        }
    }
    
    return LogSeverity::INFO;
}

void SyslogParser::extract_metadata_from_message(const std::string& message, LogEntry& entry) {
    // Try to extract IP address
    static const std::regex ip_pattern(
        R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    );
    
    std::smatch ip_match;
    if (std::regex_search(message, ip_match, ip_pattern)) {
        entry.additional_fields["source_ip"] = ip_match.str();
    }
    
    // Try to extract port number
    static const std::regex port_pattern(
        R"(\bport\s+(\d+)\b)"
    );
    
    std::smatch port_match;
    if (std::regex_search(message, port_match, port_pattern)) {
        entry.additional_fields["port"] = port_match[1].str();
    }
    
    // Try to extract user
    static const std::regex user_pattern(
        R"(\buser[=\s]+(\w+)\b)"
    );
    
    std::smatch user_match;
    if (std::regex_search(message, user_match, user_pattern)) {
        entry.additional_fields["user"] = user_match[1].str();
    }
}

// ============================================================================
// WindowsEventParser Implementation
// ============================================================================

std::vector<LogEntry> WindowsEventParser::parse_file(const std::string& filepath) {
    std::vector<LogEntry> entries;
    
    // Check file extension
    std::string extension = filepath.substr(filepath.find_last_of(".") + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    
    if (extension == "evtx") {
        // Binary EVTX format - would require additional library like libevtx
        // For now, we'll parse exported XML
        throw std::runtime_error("EVTX binary parsing requires libevtx. Export to XML first.");
    } else if (extension == "xml" || extension == "txt") {
        // Parse as XML or text export
        return parse_windows_xml(filepath);
    } else {
        // Assume text export
        return parse_windows_text(filepath);
    }
}

std::vector<LogEntry> WindowsEventParser::parse_string(const std::string& log_data) {
    std::vector<LogEntry> entries;
    std::stringstream ss(log_data);
    std::string line;
    
    // Check if it's XML
    if (log_data.find("<?xml") != std::string::npos ||
        log_data.find("<Event") != std::string::npos) {
        return parse_windows_xml_string(log_data);
    } else {
        // Parse as text
        return parse_windows_text_string(log_data);
    }
}

LogEntry WindowsEventParser::parse_line(const std::string& line) {
    // This method is for text-based Windows Event Log exports
    LogEntry entry;
    entry.source_type = LogSource::WINDOWS_EVENT;
    
    // Common Windows Event Log text format patterns
    static const std::regex pattern1(
        R"(^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+"
        R"((Information|Warning|Error|Critical|Verbose)\s+"
        R"((\d+)\s+None\s+"
        R"((.+?)\s+"
        R"((.+))$)"
    );
    
    static const std::regex pattern2(
        R"(^<Event.*?</Event>)", std::regex::dotall
    );
    
    std::smatch match;
    
    if (std::regex_match(line, match, pattern1)) {
        entry.timestamp = match[1].str();
        
        std::string level = match[2].str();
        if (level == "Error" || level == "Critical") {
            entry.severity = LogSeverity::ERROR;
        } else if (level == "Warning") {
            entry.severity = LogSeverity::WARNING;
        } else {
            entry.severity = LogSeverity::INFO;
        }
        
        try {
            entry.event_id = std::stoi(match[3].str());
        } catch (...) {
            entry.event_id = 0;
        }
        
        entry.source_host = sanitize_input(match[4].str());
        entry.process = "Windows Event Log";
        entry.message = sanitize_input(match[5].str());
        
    } else if (line.find("<Event") != std::string::npos) {
        // XML event - parse with dedicated method
        return parse_xml_event(line);
        
    } else {
        // Fallback
        entry.message = sanitize_input(line);
        entry.severity = LogSeverity::INFO;
        entry.timestamp = get_current_timestamp();
        entry.process = "Windows Event Log";
    }
    
    return entry;
}

LogSeverity WindowsEventParser::parse_event_level(int level) const {
    // Windows Event Log levels:
    // 1: Critical
    // 2: Error
    // 3: Warning
    // 4: Information
    // 5: Verbose
    
    switch (level) {
        case 1:
            return LogSeverity::CRITICAL;
        case 2:
            return LogSeverity::ERROR;
        case 3:
            return LogSeverity::WARNING;
        case 4:
        case 5:
        default:
            return LogSeverity::INFO;
    }
}

std::vector<LogEntry> WindowsEventParser::parse_windows_xml(const std::string& filepath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    
    // Read entire file
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string xml_content = buffer.str();
    
    return parse_windows_xml_string(xml_content);
}

std::vector<LogEntry> WindowsEventParser::parse_windows_xml_string(const std::string& xml_content) {
    std::vector<LogEntry> entries;
    
    try {
        Json::CharReaderBuilder reader;
        Json::Value root;
        std::string errors;
        
        // First, try to parse as JSON (some exports are JSON)
        std::stringstream ss(xml_content);
        if (Json::parseFromStream(reader, ss, &root, &errors)) {
            return parse_windows_json(root);
        }
        
        // Not JSON, parse as XML
        // Simple XML parsing for Windows Event Log format
        // Note: For production use, consider using a proper XML library like pugixml
        
        size_t pos = 0;
        while ((pos = xml_content.find("<Event", pos)) != std::string::npos) {
            size_t end_pos = xml_content.find("</Event>", pos);
            if (end_pos == std::string::npos) {
                break;
            }
            
            std::string event_xml = xml_content.substr(pos, end_pos - pos + 8);
            
            try {
                LogEntry entry = parse_xml_event(event_xml);
                entries.push_back(entry);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to parse XML event: " << e.what() << std::endl;
            }
            
            pos = end_pos + 8;
        }
        
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to parse Windows Event XML: " + std::string(e.what()));
    }
    
    return entries;
}

LogEntry WindowsEventParser::parse_xml_event(const std::string& xml) {
    LogEntry entry;
    entry.source_type = LogSource::WINDOWS_EVENT;
    
    // Extract System element
    std::smatch match;
    
    // Extract EventID
    static const std::regex event_id_pattern(R"(<EventID[^>]*>(\d+)</EventID>)");
    if (std::regex_search(xml, match, event_id_pattern)) {
        try {
            entry.event_id = std::stoi(match[1].str());
        } catch (...) {
            entry.event_id = 0;
        }
    }
    
    // Extract Level
    static const std::regex level_pattern(R"(<Level[^>]*>(\d+)</Level>)");
    if (std::regex_search(xml, match, level_pattern)) {
        try {
            int level = std::stoi(match[1].str());
            entry.severity = parse_event_level(level);
        } catch (...) {
            entry.severity = LogSeverity::INFO;
        }
    }
    
    // Extract TimeCreated
    static const std::regex time_pattern(R"(SystemTime='([^']+)')");
    if (std::regex_search(xml, match, time_pattern)) {
        entry.timestamp = match[1].str();
    } else {
        // Try alternative format
        static const std::regex time_pattern2(R"(<TimeCreated[^>]*SystemTime='([^']+)')");
        if (std::regex_search(xml, match, time_pattern2)) {
            entry.timestamp = match[1].str();
        }
    }
    
    // Extract Computer
    static const std::regex computer_pattern(R"(<Computer[^>]*>([^<]+)</Computer>)");
    if (std::regex_search(xml, match, computer_pattern)) {
        entry.source_host = sanitize_input(match[1].str());
    }
    
    // Extract Provider Name
    static const std::regex provider_pattern(R"(<Provider[^>]*Name='([^']+)')");
    if (std::regex_search(xml, match, provider_pattern)) {
        entry.process = sanitize_input(match[1].str());
    }
    
    // Extract EventData/Data or UserData
    static const std::regex message_pattern(
        R"(<Data[^>]*>([^<]+)</Data>|<Message>([^<]+)</Message>)"
    );
    
    std::string message;
    std::sregex_iterator it(xml.begin(), xml.end(), message_pattern);
    std::sregex_iterator end;
    
    while (it != end) {
        std::smatch data_match = *it;
        if (data_match[1].matched) {
            if (!message.empty()) message += " | ";
            message += data_match[1].str();
        } else if (data_match[2].matched) {
            if (!message.empty()) message += " | ";
            message += data_match[2].str();
        }
        ++it;
    }
    
    entry.message = sanitize_input(message);
    
    // If no message found, use a summary
    if (entry.message.empty()) {
        std::stringstream summary;
        summary << "Windows Event " << entry.event_id;
        if (!entry.process.empty()) {
            summary << " from " << entry.process;
        }
        entry.message = summary.str();
    }
    
    return entry;
}

std::vector<LogEntry> WindowsEventParser::parse_windows_text(const std::string& filepath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    
    std::string line;
    int line_number = 0;
    std::string current_event;
    
    // Windows Event Log text export can be multi-line
    while (std::getline(file, line)) {
        line_number++;
        
        if (line.empty()) {
            continue;
        }
        
        if (is_malicious_input(line)) {
            std::cerr << "Warning: Skipping potentially malicious input at line " 
                     << line_number << std::endl;
            continue;
        }
        
        // Check if this is the start of a new event
        if (line.find("Log Name:") == 0 || 
            line.find("Source:") == 0 ||
            (line.find("Date and Time:") == 0 && !current_event.empty())) {
            
            // Parse the completed event
            if (!current_event.empty()) {
                try {
                    LogEntry entry = parse_text_event(current_event);
                    entries.push_back(entry);
                } catch (const std::exception& e) {
                    std::cerr << "Warning: Failed to parse event at line " 
                             << line_number << ": " << e.what() << std::endl;
                }
                current_event.clear();
            }
        }
        
        current_event += line + "\n";
    }
    
    // Parse the last event
    if (!current_event.empty()) {
        try {
            LogEntry entry = parse_text_event(current_event);
            entries.push_back(entry);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse final event: " << e.what() << std::endl;
        }
    }
    
    return entries;
}

std::vector<LogEntry> WindowsEventParser::parse_windows_text_string(const std::string& text) {
    std::vector<LogEntry> entries;
    std::stringstream ss(text);
    std::string line;
    std::string current_event;
    
    while (std::getline(ss, line)) {
        if (line.empty()) {
            continue;
        }
        
        if (is_malicious_input(line)) {
            continue;
        }
        
        // Check if this is the start of a new event
        if (line.find("Log Name:") == 0 || 
            line.find("Source:") == 0 ||
            (line.find("Date and Time:") == 0 && !current_event.empty())) {
            
            if (!current_event.empty()) {
                try {
                    LogEntry entry = parse_text_event(current_event);
                    entries.push_back(entry);
                } catch (const std::exception& e) {
                    // Skip invalid events
                }
                current_event.clear();
            }
        }
        
        current_event += line + "\n";
    }
    
    if (!current_event.empty()) {
        try {
            LogEntry entry = parse_text_event(current_event);
            entries.push_back(entry);
        } catch (const std::exception& e) {
            // Skip invalid event
        }
    }
    
    return entries;
}

LogEntry WindowsEventParser::parse_text_event(const std::string& text) {
    LogEntry entry;
    entry.source_type = LogSource::WINDOWS_EVENT;
    
    std::stringstream ss(text);
    std::string line;
    
    while (std::getline(ss, line)) {
        if (line.find("Date and Time:") == 0) {
            entry.timestamp = line.substr(14);
        } else if (line.find("Event ID:") == 0) {
            try {
                entry.event_id = std::stoi(line.substr(9));
            } catch (...) {
                entry.event_id = 0;
            }
        } else if (line.find("Source:") == 0) {
            entry.process = sanitize_input(line.substr(7));
        } else if (line.find("Computer:") == 0) {
            entry.source_host = sanitize_input(line.substr(9));
        } else if (line.find("Level:") == 0) {
            std::string level = line.substr(6);
            if (level.find("Error") != std::string::npos ||
                level.find("Critical") != std::string::npos) {
                entry.severity = LogSeverity::ERROR;
            } else if (level.find("Warning") != std::string::npos) {
                entry.severity = LogSeverity::WARNING;
            } else {
                entry.severity = LogSeverity::INFO;
            }
        } else if (line.find("Description:") == 0) {
            // Collect all remaining lines as the description
            std::string description = line.substr(12) + "\n";
            while (std::getline(ss, line)) {
                description += line + "\n";
            }
            entry.message = sanitize_input(description);
        }
    }
    
    return entry;
}

std::vector<LogEntry> WindowsEventParser::parse_windows_json(const Json::Value& root) {
    std::vector<LogEntry> entries;
    
    if (root.isArray()) {
        for (const auto& event : root) {
            try {
                LogEntry entry = parse_json_event(event);
                entries.push_back(entry);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to parse JSON event: " << e.what() << std::endl;
            }
        }
    } else if (root.isObject() && root.isMember("Events")) {
        for (const auto& event : root["Events"]) {
            try {
                LogEntry entry = parse_json_event(event);
                entries.push_back(entry);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to parse JSON event: " << e.what() << std::endl;
            }
        }
    } else if (root.isObject()) {
        try {
            LogEntry entry = parse_json_event(root);
            entries.push_back(entry);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse JSON event: " << e.what() << std::endl;
        }
    }
    
    return entries;
}

LogEntry WindowsEventParser::parse_json_event(const Json::Value& event) {
    LogEntry entry;
    entry.source_type = LogSource::WINDOWS_EVENT;
    
    // Extract common fields
    if (event.isMember("EventID")) {
        entry.event_id = event["EventID"].asInt();
    }
    
    if (event.isMember("Level")) {
        int level = event["Level"].asInt();
        entry.severity = parse_event_level(level);
    }
    
    if (event.isMember("TimeCreated")) {
        if (event["TimeCreated"].isMember("SystemTime")) {
            entry.timestamp = event["TimeCreated"]["SystemTime"].asString();
        }
    }
    
    if (event.isMember("Computer")) {
        entry.source_host = sanitize_input(event["Computer"].asString());
    }
    
    if (event.isMember("Provider")) {
        if (event["Provider"].isMember("Name")) {
            entry.process = sanitize_input(event["Provider"]["Name"].asString());
        }
    }
    
    // Extract message
    std::string message;
    if (event.isMember("EventData") && event["EventData"].isMember("Data")) {
        const auto& data = event["EventData"]["Data"];
        if (data.isArray()) {
            for (const auto& item : data) {
                if (!message.empty()) message += " | ";
                message += item.asString();
            }
        }
    }
    
    if (event.isMember("Message")) {
        if (!message.empty()) message += " | ";
        message += event["Message"].asString();
    }
    
    entry.message = sanitize_input(message);
    
    return entry;
}

// ============================================================================
// JSONLogParser Implementation
// ============================================================================

std::vector<LogEntry> JSONLogParser::parse_file(const std::string& filepath) {
    std::vector<LogEntry> entries;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    
    // Read entire file
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json_content = buffer.str();
    
    return parse_string(json_content);
}

std::vector<LogEntry> JSONLogParser::parse_string(const std::string& log_data) {
    std::vector<LogEntry> entries;
    
    // Check if it's a JSON array or one JSON object per line
    if (log_data.find('[') == 0) {
        // Parse as JSON array
        return parse_json_array(log_data);
    } else {
        // Parse as JSON lines (one JSON object per line)
        return parse_json_lines(log_data);
    }
}

LogEntry JSONLogParser::parse_line(const std::string& line) {
    return parse_json_object(line);
}

LogEntry JSONLogParser::parse_json_object(const std::string& json_str) {
    LogEntry entry;
    entry.source_type = LogSource::JSON;
    
    try {
        Json::Value root;
        Json::CharReaderBuilder reader;
        std::string errors;
        std::stringstream ss(json_str);
        
        if (!Json::parseFromStream(reader, ss, &root, &errors)) {
            throw std::runtime_error("Failed to parse JSON: " + errors);
        }
        
        // Extract timestamp
        if (root.isMember("timestamp")) {
            entry.timestamp = root["timestamp"].asString();
        } else if (root.isMember("time")) {
            entry.timestamp = root["time"].asString();
        } else if (root.isMember("@timestamp")) {
            entry.timestamp = root["@timestamp"].asString();
        } else if (root.isMember("date")) {
            entry.timestamp = root["date"].asString();
        } else {
            entry.timestamp = get_current_timestamp();
        }
        
        // Extract host
        if (root.isMember("host")) {
            entry.source_host = sanitize_input(root["host"].asString());
        } else if (root.isMember("hostname")) {
            entry.source_host = sanitize_input(root["hostname"].asString());
        } else if (root.isMember("source_host")) {
            entry.source_host = sanitize_input(root["source_host"].asString());
        }
        
        // Extract process/application
        if (root.isMember("process")) {
            entry.process = sanitize_input(root["process"].asString());
        } else if (root.isMember("application")) {
            entry.process = sanitize_input(root["application"].asString());
        } else if (root.isMember("app")) {
            entry.process = sanitize_input(root["app"].asString());
        } else if (root.isMember("logger")) {
            entry.process = sanitize_input(root["logger"].asString());
        }
        
        // Extract message
        if (root.isMember("message")) {
            entry.message = sanitize_input(root["message"].asString());
        } else if (root.isMember("msg")) {
            entry.message = sanitize_input(root["msg"].asString());
        } else if (root.isMember("log")) {
            entry.message = sanitize_input(root["log"].asString());
        } else {
            // Use entire JSON as message
            Json::StreamWriterBuilder writer;
            entry.message = sanitize_input(Json::writeString(writer, root));
        }
        
        // Extract severity/level
        if (root.isMember("severity")) {
            std::string severity = root["severity"].asString();
            entry.severity = parse_json_severity(severity);
        } else if (root.isMember("level")) {
            std::string level = root["level"].asString();
            entry.severity = parse_json_severity(level);
        } else if (root.isMember("log_level")) {
            std::string log_level = root["log_level"].asString();
            entry.severity = parse_json_severity(log_level);
        } else {
            entry.severity = LogSeverity::INFO;
        }
        
        // Extract event_id if present
        if (root.isMember("event_id")) {
            entry.event_id = root["event_id"].asInt();
        } else if (root.isMember("id")) {
            entry.event_id = root["id"].asInt();
        }
        
        // Extract additional fields