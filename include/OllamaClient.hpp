#ifndef OLLAMA_CLIENT_HPP
#define OLLAMA_CLIENT_HPP

#include "LogEntry.hpp"
#include <string>
#include <vector>
#include <memory>
#include <curl/curl.h>

class OllamaClient {
public:
    OllamaClient(const std::string& base_url = "http://localhost:11434");
    ~OllamaClient();
    
    // Initialize the client
    bool initialize();
    
    // Generate summary using LLM
    std::string generate_summary(
        const std::vector<SecurityEvent>& security_events,
        const std::string& model = "llama3"
    );
    
    // Analyze specific log entries
    std::string analyze_logs(
        const std::vector<LogEntry>& logs,
        const std::string& model = "llama3"
    );
    
    // Generate report
    std::string generate_report(
        const std::vector<SecurityEvent>& events,
        const std::string& model = "llama3"
    );
    
    // List available models
    std::vector<std::string> list_models();
    
    // Check if model is available
    bool is_model_available(const std::string& model_name);
    
private:
    std::string base_url_;
    CURL* curl_handle_;
    bool initialized_;
    
    // HTTP POST request helper
    std::string post_request(
        const std::string& endpoint,
        const std::string& json_data
    );
    
    // Build prompt for LLM
    std::string build_security_prompt(
        const std::vector<SecurityEvent>& events
    ) const;
    
    std::string build_analysis_prompt(
        const std::vector<LogEntry>& logs
    ) const;
    
    // Callback for curl write
    static size_t write_callback(
        void* contents, 
        size_t size, 
        size_t nmemb, 
        void* userp
    );
    
    // Error handling
    void handle_curl_error(CURLcode res, const std::string& context);
    
    // Cleanup
    void cleanup();
};

#endif // OLLAMA_CLIENT_HPP