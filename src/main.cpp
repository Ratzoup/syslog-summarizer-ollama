#include "LogParser.hpp"
#include "SecurityAnalyzer.hpp"
#include "OllamaClient.hpp"
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <chrono>

class LogSummarizer {
private:
    std::unique_ptr<LogParser> parser_;
    SecurityAnalyzer analyzer_;
    OllamaClient ollama_client_;
    std::string output_dir_;
    
public:
    LogSummarizer(const std::string& ollama_url = "http://localhost:11434")
        : ollama_client_(ollama_url), output_dir_("./reports") {
        
        // Create output directory if it doesn't exist
        std::filesystem::create_directories(output_dir_);
    }
    
    void set_parser(LogSource source) {
        parser_ = LogParser::create_parser(source);
        if (!parser_) {
            throw std::runtime_error("Failed to create parser for the specified source");
        }
    }
    
    void process_logs(const std::string& input_file, bool generate_report = true) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        try {
            // Parse logs
            std::cout << "Parsing logs from: " << input_file << std::endl;
            auto logs = parser_->parse_file(input_file);
            std::cout << "Parsed " << logs.size() << " log entries" << std::endl;
            
            // Analyze for security events
            std::cout << "Analyzing for security events..." << std::endl;
            auto security_events = analyzer_.analyze_logs(logs);
            
            // Display statistics
            auto stats = analyzer_.get_statistics();
            std::cout << "\n=== Analysis Statistics ===" << std::endl;
            std::cout << "Total logs: " << stats.total_logs << std::endl;
            std::cout << "Security events: " << stats.security_events << std::endl;
            std::cout << "Critical events: " << stats.critical_events << std::endl;
            
            // Generate LLM summary if events found
            if (!security_events.empty() && generate_report) {
                std::cout << "\nGenerating LLM summary..." << std::endl;
                
                try {
                    std::string summary = ollama_client_.generate_summary(security_events);
                    std::cout << "\n=== LLM Security Summary ===\n" << std::endl;
                    std::cout << summary << std::endl;
                    
                    // Save summary to file
                    save_summary(summary, security_events);
                    
                } catch (const std::exception& e) {
                    std::cerr << "Warning: LLM summary generation failed: " 
                             << e.what() << std::endl;
                    std::cout << "Falling back to basic summary..." << std::endl;
                    generate_basic_summary(security_events);
                }
            }
            
            // Print notable events
            if (!security_events.empty()) {
                print_security_events(security_events);
            }
            
        } catch (const std::exception& e) {
            std::cerr << "Error processing logs: " << e.what() << std::endl;
            throw;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        std::cout << "\nProcessing completed in " << duration.count() 
                 << "ms" << std::endl;
    }
    
private:
    void save_summary(const std::string& summary, 
                     const std::vector<SecurityEvent>& events) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream filename;
        filename << output_dir_ << "/security_report_" 
                << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") 
                << ".txt";
        
        std::ofstream file(filename.str());
        if (file.is_open()) {
            file << "=== Security Analysis Report ===\n\n";
            file << "Generated: " 
                 << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
                 << "\n\n";
            file << "Total security events: " << events.size() << "\n\n";
            file << "=== LLM Analysis ===\n";
            file << summary << "\n\n";
            file << "=== Detailed Events ===\n";
            
            for (const auto& event : events) {
                file << "Event Type: " << event.event_type << "\n";
                file << "Risk Score: " << event.risk_score << "/10\n";
                file << "Timestamp: " << event.log_entry.timestamp << "\n";
                file << "Source: " << event.log_entry.source_host << "\n";
                file << "Description: " << event.description << "\n";
                file << "Indicators: ";
                for (const auto& indicator : event.indicators) {
                    file << indicator << "; ";
                }
                file << "\n---\n";
            }
            
            file.close();
            std::cout << "Report saved to: " << filename.str() << std::endl;
        }
    }
    
    void generate_basic_summary(const std::vector<SecurityEvent>& events) {
        std::cout << "\n=== Security Summary ===\n" << std::endl;
        
        std::map<std::string, int> event_counts;
        int total_risk = 0;
        
        for (const auto& event : events) {
            event_counts[event.event_type]++;
            total_risk += event.risk_score;
        }
        
        std::cout << "Total events detected: " << events.size() << std::endl;
        std::cout << "Average risk score: " 
                 << (events.empty() ? 0 : total_risk / events.size()) 
                 << "/10" << std::endl;
        
        std::cout << "\nEvent breakdown:" << std::endl;
        for (const auto& [type, count] : event_counts) {
            std::cout << "  " << type << ": " << count << std::endl;
        }
        
        std::cout << "\nRecommended actions:" << std::endl;
        if (event_counts.count("FailedLogin") > 0) {
            std::cout << "  - Review account lockout policies" << std::endl;
            std::cout << "  - Check for compromised accounts" << std::endl;
        }
        if (event_counts.count("PrivilegeEscalation") > 0) {
            std::cout << "  - Audit privileged accounts" << std::endl;
            std::cout << "  - Review sudo/administrator logs" << std::endl;
        }
    }
    
    void print_security_events(const std::vector<SecurityEvent>& events) {
        std::cout << "\n=== Notable Security Events ===\n" << std::endl;
        
        // Sort by risk score (highest first)
        auto sorted_events = events;
        std::sort(sorted_events.begin(), sorted_events.end(),
                 [](const SecurityEvent& a, const SecurityEvent& b) {
                     return a.risk_score > b.risk_score;
                 });
        
        for (const auto& event : sorted_events) {
            if (event.risk_score >= 5) {  // Only show medium/high risk events
                std::cout << "[RISK: " << event.risk_score << "/10] "
                         << event.event_type << std::endl;
                std::cout << "  Time: " << event.log_entry.timestamp << std::endl;
                std::cout << "  Host: " << event.log_entry.source_host << std::endl;
                std::cout << "  Desc: " << event.description << std::endl;
                
                if (!event.indicators.empty()) {
                    std::cout << "  Indicators: ";
                    for (size_t i = 0; i < std::min(event.indicators.size(), size_t(3)); ++i) {
                        std::cout << event.indicators[i];
                        if (i < std::min(event.indicators.size(), size_t(3)) - 1) {
                            std::cout << ", ";
                        }
                    }
                    if (event.indicators.size() > 3) {
                        std::cout << " (+" << (event.indicators.size() - 3) << " more)";
                    }
                    std::cout << std::endl;
                }
                std::cout << std::endl;
            }
        }
    }
};

void print_usage() {
    std::cout << "Log Summarizer - Security Log Analysis Tool\n\n";
    std::cout << "Usage:\n";
    std::cout << "  logsum <log_type> <input_file> [options]\n\n";
    std::cout << "Log types:\n";
    std::cout << "  syslog     - Syslog format logs\n";
    std::cout << "  windows    - Windows Event Logs (XML/EVTX)\n";
    std::cout << "  json       - JSON formatted logs\n";
    std::cout << "  csv        - CSV formatted logs\n\n";
    std::cout << "Options:\n";
    std::cout << "  --no-llm    - Disable LLM analysis (basic summary only)\n";
    std::cout << "  --help      - Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }
    
    std::string log_type = argv[1];
    std::string input_file = argv[2];
    bool use_llm = true;
    
    // Parse options
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--no-llm") {
            use_llm = false;
        } else if (arg == "--help") {
            print_usage();
            return 0;
        }
    }
    
    try {
        // Map log type to source
        LogSource source;
        if (log_type == "syslog") {
            source = LogSource::SYSLOG;
        } else if (log_type == "windows") {
            source = LogSource::WINDOWS_EVENT;
        } else if (log_type == "json") {
            source = LogSource::JSON;
        } else if (log_type == "csv") {
            // CSV would need a separate parser
            std::cout << "CSV parser not implemented in this example" << std::endl;
            return 1;
        } else {
            std::cerr << "Unknown log type: " << log_type << std::endl;
            print_usage();
            return 1;
        }
        
        // Create and run summarizer
        LogSummarizer summarizer;
        summarizer.set_parser(source);
        summarizer.process_logs(input_file, use_llm);
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}