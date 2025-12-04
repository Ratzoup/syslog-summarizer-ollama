#ifndef SECURITY_ANALYZER_HPP
#define SECURITY_ANALYZER_HPP

#include "LogEntry.hpp"
#include <vector>
#include <regex>
#include <mutex>

class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    
    // Analyze logs for security events
    std::vector<SecurityEvent> analyze_logs(
        const std::vector<LogEntry>& logs
    );
    
    // Add custom detection pattern
    void add_detection_pattern(
        const std::string& pattern_name,
        const std::regex& pattern,
        const std::string& event_type,
        int risk_score
    );
    
    // Get statistics
    struct AnalysisStats {
        int total_logs;
        int security_events;
        int critical_events;
        std::map<std::string, int> event_counts;
    };
    
    AnalysisStats get_statistics() const;
    
private:
    struct DetectionPattern {
        std::regex pattern;
        std::string event_type;
        int risk_score;
        std::vector<std::string> indicators;
    };
    
    std::vector<DetectionPattern> patterns_;
    std::mutex patterns_mutex_;
    AnalysisStats stats_;
    
    // Initialize default patterns
    void initialize_default_patterns();
    
    // Specific detection methods
    SecurityEvent detect_failed_login(const LogEntry& entry) const;
    SecurityEvent detect_privilege_escalation(const LogEntry& entry) const;
    SecurityEvent detect_brute_force(const std::vector<LogEntry>& logs, 
                                     size_t current_index) const;
    SecurityEvent detect_port_scan(const LogEntry& entry) const;
    SecurityEvent detect_malware_indicators(const LogEntry& entry) const;
    
    // Helper methods
    bool contains_pattern(const std::string& text, 
                         const std::regex& pattern) const;
    std::vector<std::string> extract_indicators(const std::string& text) const;
    
    // Update statistics
    void update_stats(const SecurityEvent& event);
};

#endif // SECURITY_ANALYZER_HPP