#include "OllamaClient.hpp"
#include <iostream>
#include <sstream>
#include <json/json.h>

OllamaClient::OllamaClient(const std::string& base_url) 
    : base_url_(base_url), curl_handle_(nullptr), initialized_(false) {
}

OllamaClient::~OllamaClient() {
    cleanup();
}

bool OllamaClient::initialize() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle_ = curl_easy_init();
    
    if (!curl_handle_) {
        std::cerr << "Failed to initialize CURL" << std::endl;
        return false;
    }
    
    initialized_ = true;
    return true;
}

std::string OllamaClient::generate_summary(
    const std::vector<SecurityEvent>& security_events,
    const std::string& model) {
    
    if (!initialized_) {
        if (!initialize()) {
            return "Error: Failed to initialize OLLAMA client";
        }
    }
    
    std::string prompt = build_security_prompt(security_events);
    
    Json::Value request;
    request["model"] = model;
    request["prompt"] = prompt;
    request["stream"] = false;
    
    // Add options for better output
    Json::Value options;
    options["temperature"] = 0.3;  // Lower temperature for more factual output
    options["top_p"] = 0.9;
    options["num_predict"] = 1024;  // Limit output length
    request["options"] = options;
    
    Json::StreamWriterBuilder writer;
    std::string json_request = Json::writeString(writer, request);
    
    std::string response = post_request("/api/generate", json_request);
    
    // Parse response
    Json::Value json_response;
    Json::CharReaderBuilder reader;
    std::stringstream response_stream(response);
    std::string parse_errors;
    
    if (Json::parseFromStream(reader, response_stream, &json_response, &parse_errors)) {
        if (json_response.isMember("response")) {
            return json_response["response"].asString();
        }
    }
    
    return "Error: Failed to parse LLM response";
}

std::string OllamaClient::build_security_prompt(
    const std::vector<SecurityEvent>& events) const {
    
    std::stringstream prompt;
    
    prompt << "You are a cybersecurity analyst. Analyze these security events and provide:\n";
    prompt << "1. Executive summary (2-3 sentences)\n";
    prompt << "2. Key findings and their severity\n";
    prompt << "3. Recommended immediate actions\n";
    prompt << "4. Long-term mitigation suggestions\n\n";
    
    prompt << "Security Events:\n";
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        prompt << "Event " << i + 1 << ":\n";
        prompt << "  Type: " << event.event_type << "\n";
        prompt << "  Risk Score: " << event.risk_score << "/10\n";
        prompt << "  Description: " << event.description << "\n";
        prompt << "  Timestamp: " << event.log_entry.timestamp << "\n";
        prompt << "  Source: " << event.log_entry.source_host << "\n";
        prompt << "  Indicators: ";
        for (const auto& indicator : event.indicators) {
            prompt << indicator << "; ";
        }
        prompt << "\n\n";
    }
    
    prompt << "Provide a concise, actionable analysis for a SOC team.";
    
    return prompt.str();
}

std::string OllamaClient::post_request(
    const std::string& endpoint,
    const std::string& json_data) {
    
    std::string url = base_url_ + endpoint;
    std::string response_data;
    
    curl_easy_setopt(curl_handle_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_handle_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDS, json_data.c_str());
    curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDSIZE, json_data.length());
    
    // Set headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl_handle_, CURLOPT_HTTPHEADER, headers);
    
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEDATA, &response_data);
    
    // Set timeout
    curl_easy_setopt(curl_handle_, CURLOPT_TIMEOUT, 30L);
    
    CURLcode res = curl_easy_perform(curl_handle_);
    
    if (res != CURLE_OK) {
        handle_curl_error(res, "POST request failed");
        curl_slist_free_all(headers);
        return "";
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl_handle_, CURLINFO_RESPONSE_CODE, &http_code);
    
    if (http_code != 200) {
        std::cerr << "HTTP Error: " << http_code << std::endl;
    }
    
    curl_slist_free_all(headers);
    return response_data;
}

size_t OllamaClient::write_callback(void* contents, size_t size, 
                                    size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

void OllamaClient::handle_curl_error(CURLcode res, const std::string& context) {
    std::cerr << context << ": " << curl_easy_strerror(res) << std::endl;
}

void OllamaClient::cleanup() {
    if (curl_handle_) {
        curl_easy_cleanup(curl_handle_);
        curl_handle_ = nullptr;
    }
    curl_global_cleanup();
    initialized_ = false;
}