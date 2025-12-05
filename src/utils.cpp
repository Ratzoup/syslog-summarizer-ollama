#include "../include/LogEntry.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <locale>
#include <codecvt>
#include <random>
#include <regex>
#include <filesystem>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <curl/curl.h>

namespace fs = std::filesystem;

// ============================================================================
// String Utilities
// ============================================================================

// Trim from start (in place)
void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// Trim from end (in place)
void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// Trim from both ends (in place)
void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// Trim from start (copying)
std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// Trim from end (copying)
std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}

// Trim from both ends (copying)
std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

// Convert string to lowercase
std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Convert string to uppercase
std::string to_upper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                  [](unsigned char c) { return std::toupper(c); });
    return result;
}

// Check if string starts with a prefix
bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && 
           str.compare(0, prefix.size(), prefix) == 0;
}

// Check if string ends with a suffix
bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Split string by delimiter
std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(str);
    
    while (std::getline(token_stream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    
    return tokens;
}

// Split string by delimiter with max splits
std::vector<std::string> split_string(const std::string& str, char delimiter, int max_splits) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(str);
    int count = 0;
    
    while (count < max_splits && std::getline(token_stream, token, delimiter)) {
        tokens.push_back(token);
        count++;
    }
    
    // Add the rest as last token
    if (std::getline(token_stream, token, '\0')) {
        tokens.push_back(token);
    }
    
    return tokens;
}

// Join vector of strings with delimiter
std::string join_strings(const std::vector<std::string>& strings, const std::string& delimiter) {
    std::ostringstream oss;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i != 0) {
            oss << delimiter;
        }
        oss << strings[i];
    }
    return oss.str();
}

// Replace all occurrences of a substring
std::string replace_all(const std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return str;
    
    std::string result = str;
    size_t start_pos = 0;
    while ((start_pos = result.find(from, start_pos)) != std::string::npos) {
        result.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return result;
}

// Check if string contains substring
bool contains(const std::string& str, const std::string& substr) {
    return str.find(substr) != std::string::npos;
}

// Check if string contains substring (case-insensitive)
bool contains_ci(const std::string& str, const std::string& substr) {
    std::string str_lower = to_lower(str);
    std::string substr_lower = to_lower(substr);
    return str_lower.find(substr_lower) != std::string::npos;
}

// Escape special characters for regex
std::string escape_regex(const std::string& str) {
    static const std::regex special_chars(R"([.^$|()\[\]{}*+?\\])");
    return std::regex_replace(str, special_chars, R"(\$&)");
}

// Remove non-alphanumeric characters
std::string remove_non_alnum(const std::string& str) {
    std::string result;
    std::copy_if(str.begin(), str.end(), std::back_inserter(result),
                [](char c) { return std::isalnum(static_cast<unsigned char>(c)); });
    return result;
}

// ============================================================================
// Time and Date Utilities
// ============================================================================

// Get current timestamp as string
std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Get current timestamp with milliseconds
std::string get_current_timestamp_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

// Parse timestamp string to time_t
std::time_t parse_timestamp(const std::string& timestamp_str) {
    std::tm tm = {};
    std::stringstream ss(timestamp_str);
    
    // Try different formats
    const char* formats[] = {
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a %b %d %H:%M:%S %Y",
        "%d-%b-%Y %H:%M:%S",
        "%Y%m%d %H:%M:%S",
        nullptr
    };
    
    for (int i = 0; formats[i] != nullptr; ++i) {
        ss.clear();
        ss.str(timestamp_str);
        ss >> std::get_time(&tm, formats[i]);
        if (!ss.fail()) {
            // For syslog format without year, add current year
            if (std::string(formats[i]) == "%b %d %H:%M:%S") {
                auto now = std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::now());
                std::tm* now_tm = std::localtime(&now);
                tm.tm_year = now_tm->tm_year;
            }
            
            std::time_t t = std::mktime(&tm);
            if (t != -1) {
                return t;
            }
        }
    }
    
    return 0; // Invalid timestamp
}

// Format time_t as string
std::string format_timestamp(std::time_t t, const std::string& format) {
    if (t == 0) return "";
    
    std::tm* tm = std::localtime(&t);
    if (!tm) return "";
    
    std::stringstream ss;
    ss << std::put_time(tm, format.c_str());
    return ss.str();
}

// Get time difference in seconds
double time_diff_seconds(const std::string& time1, const std::string& time2) {
    std::time_t t1 = parse_timestamp(time1);
    std::time_t t2 = parse_timestamp(time2);
    
    if (t1 == 0 || t2 == 0) {
        return 0.0;
    }
    
    return std::difftime(t1, t2);
}

// Check if timestamp is within time range
bool is_within_time_range(const std::string& timestamp, 
                         const std::string& start_time,
                         const std::string& end_time) {
    std::time_t t = parse_timestamp(timestamp);
    std::time_t start = parse_timestamp(start_time);
    std::time_t end = parse_timestamp(end_time);
    
    if (t == 0) return false;
    
    if (start != 0 && t < start) return false;
    if (end != 0 && t > end) return false;
    
    return true;
}

// ============================================================================
// File System Utilities
// ============================================================================

// Check if file exists
bool file_exists(const std::string& path) {
    return fs::exists(path) && fs::is_regular_file(path);
}

// Check if directory exists
bool dir_exists(const std::string& path) {
    return fs::exists(path) && fs::is_directory(path);
}

// Create directory (recursive)
bool create_directory(const std::string& path) {
    try {
        return fs::create_directories(path);
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

// Get file size
uint64_t get_file_size(const std::string& path) {
    try {
        return fs::file_size(path);
    } catch (const fs::filesystem_error&) {
        return 0;
    }
}

// Get file extension
std::string get_file_extension(const std::string& path) {
    fs::path p(path);
    return p.extension().string();
}

// Get filename without extension
std::string get_filename_without_extension(const std::string& path) {
    fs::path p(path);
    return p.stem().string();
}

// Get directory from path
std::string get_directory(const std::string& path) {
    fs::path p(path);
    return p.parent_path().string();
}

// Read entire file to string
std::string read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Read file lines to vector
std::vector<std::string> read_file_lines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    
    return lines;
}

// Write string to file
bool write_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

// Append string to file
bool append_to_file(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary | std::ios::app);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

// Copy file
bool copy_file(const std::string& source, const std::string& destination) {
    try {
        fs::copy_file(source, destination, fs::copy_options::overwrite_existing);
        return true;
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

// Delete file
bool delete_file(const std::string& path) {
    try {
        return fs::remove(path);
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

// List files in directory
std::vector<std::string> list_files(const std::string& directory, 
                                   const std::string& extension) {
    std::vector<std::string> files;
    
    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry.path())) {
                if (extension.empty() || 
                    entry.path().extension() == extension) {
                    files.push_back(entry.path().string());
                }
            }
        }
    } catch (const fs::filesystem_error&) {
        // Directory doesn't exist or can't be read
    }
    
    return files;
}

// Get temporary filename
std::string get_temp_filename(const std::string& prefix) {
    std::string temp_dir = fs::temp_directory_path().string();
    std::string filename = prefix + "_" + std::to_string(std::time(nullptr)) + 
                          "_" + std::to_string(rand() % 10000);
    return (fs::path(temp_dir) / filename).string();
}

// ============================================================================
// Security Utilities
// ============================================================================

// Generate random string
std::string generate_random_string(size_t length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    std::string result;
    result.reserve(length);
    
    // Use thread_local random engine for thread safety
    thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<int> distribution(0, sizeof(alphanum) - 2);
    
    for (size_t i = 0; i < length; ++i) {
        result += alphanum[distribution(generator)];
    }
    
    return result;
}

// Generate secure random bytes
std::vector<unsigned char> generate_random_bytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    
    return bytes;
}

// Calculate SHA256 hash
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input.c_str(), input.length()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to calculate SHA256 hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

// Calculate SHA256 hash of file
std::string sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize SHA256");
    }
    
    const size_t buffer_size = 4096;
    char buffer[buffer_size];
    
    while (file.read(buffer, buffer_size) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update SHA256 hash");
        }
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize SHA256 hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

// Calculate HMAC-SHA256
std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char* digest = HMAC(EVP_sha256(), 
                                key.c_str(), static_cast<int>(key.length()),
                                reinterpret_cast<const unsigned char*>(data.c_str()), 
                                data.length(),
                                nullptr, nullptr);
    
    if (digest == nullptr) {
        throw std::runtime_error("Failed to calculate HMAC-SHA256");
    }
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(digest[i]);
    }
    
    return ss.str();
}

// Validate IP address
bool is_valid_ip(const std::string& ip) {
    static const std::regex ipv4_pattern(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"
    );
    
    std::smatch match;
    if (!std::regex_match(ip, match, ipv4_pattern)) {
        return false;
    }
    
    // Check each octet
    for (int i = 1; i <= 4; ++i) {
        int octet = std::stoi(match[i].str());
        if (octet < 0 || octet > 255) {
            return false;
        }
    }
    
    return true;
}

// Validate email address
bool is_valid_email(const std::string& email) {
    static const std::regex email_pattern(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
    );
    
    return std::regex_match(email, email_pattern);
}

// Sanitize filename
std::string sanitize_filename(const std::string& filename) {
    std::string sanitized = filename;
    
    // Remove dangerous characters
    static const std::regex dangerous_chars(R"([\/\\:*?"<>|])");
    sanitized = std::regex_replace(sanitized, dangerous_chars, "_");
    
    // Remove leading/trailing spaces and dots
    trim(sanitized);
    while (!sanitized.empty() && sanitized.back() == '.') {
        sanitized.pop_back();
    }
    
    // Limit length
    const size_t max_length = 255;
    if (sanitized.length() > max_length) {
        sanitized = sanitized.substr(0, max_length);
    }
    
    return sanitized.empty() ? "unnamed" : sanitized;
}

// Sanitize HTML
std::string sanitize_html(const std::string& html) {
    std::string sanitized = html;
    
    // Replace HTML special characters
    sanitized = replace_all(sanitized, "&", "&amp;");
    sanitized = replace_all(sanitized, "<", "&lt;");
    sanitized = replace_all(sanitized, ">", "&gt;");
    sanitized = replace_all(sanitized, "\"", "&quot;");
    sanitized = replace_all(sanitized, "'", "&#39;");
    
    return sanitized;
}

// Check for SQL injection patterns
bool has_sql_injection(const std::string& input) {
    static const std::vector<std::regex> sql_patterns = {
        std::regex(R"(\b(?:union\s+select|select\s+.*from|insert\s+into|update\s+.*set|delete\s+from)\b)", std::regex::icase),
        std::regex(R"(\b(?:drop\s+table|create\s+table|alter\s+table)\b)", std::regex::icase),
        std::regex(R"(\b(?:exec\s*\(|execute\s*\(|sp_|xp_)\b)", std::regex::icase),
        std::regex(R"(--|\/\*|\*\/|;)", std::regex::icase)
    };
    
    for (const auto& pattern : sql_patterns) {
        if (std::regex_search(input, pattern)) {
            return true;
        }
    }
    
    return false;
}

// Check for XSS patterns
bool has_xss(const std::string& input) {
    static const std::vector<std::regex> xss_patterns = {
        std::regex(R"(<script[^>]*>.*?</script>)", std::regex::icase),
        std::regex(R"(javascript:)", std::regex::icase),
        std::regex(R"(on\w+\s*=)", std::regex::icase),
        std::regex(R"(data:text/html)", std::regex::icase),
        std::regex(R"(<iframe[^>]*>.*?</iframe>)", std::regex::icase),
        std::regex(R"(<object[^>]*>.*?</object>)", std::regex::icase),
        std::regex(R"(<embed[^>]*>.*?</embed>)", std::regex::icase)
    };
    
    for (const auto& pattern : xss_patterns) {
        if (std::regex_search(input, pattern)) {
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// Compression Utilities
// ============================================================================

// Compress string using gzip
std::vector<unsigned char> gzip_compress(const std::string& data) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                    15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib deflate");
    }
    
    zs.next_in = (Bytef*)data.data();
    zs.avail_in = static_cast<uInt>(data.size());
    
    int ret;
    char outbuffer[32768];
    std::vector<unsigned char> compressed;
    
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        
        ret = deflate(&zs, Z_FINISH);
        
        if (compressed.size() < zs.total_out) {
            compressed.insert(compressed.end(), 
                            outbuffer, 
                            outbuffer + (zs.total_out - compressed.size()));
        }
    } while (ret == Z_OK);
    
    deflateEnd(&zs);
    
    if (ret != Z_STREAM_END) {
        throw std::runtime_error("Failed to compress data");
    }
    
    return compressed;
}

// Decompress gzip data to string
std::string gzip_decompress(const std::vector<unsigned char>& compressed) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    
    if (inflateInit2(&zs, 15 + 16) != Z_OK) {
        throw std::runtime_error("Failed to initialize zlib inflate");
    }
    
    zs.next_in = (Bytef*)compressed.data();
    zs.avail_in = static_cast<uInt>(compressed.size());
    
    int ret;
    char outbuffer[32768];
    std::string decompressed;
    
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        
        ret = inflate(&zs, 0);
        
        if (decompressed.size() < zs.total_out) {
            decompressed.append(outbuffer, 
                              zs.total_out - decompressed.size());
        }
    } while (ret == Z_OK);
    
    inflateEnd(&zs);
    
    if (ret != Z_STREAM_END) {
        throw std::runtime_error("Failed to decompress data");
    }
    
    return decompressed;
}

// ============================================================================
// Network Utilities
// ============================================================================

// URL encode
std::string url_encode(const std::string& value) {
    static const char hex_chars[] = "0123456789ABCDEF";
    
    std::string encoded;
    encoded.reserve(value.length() * 3);
    
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            encoded += '%';
            encoded += hex_chars[(c >> 4) & 0xF];
            encoded += hex_chars[c & 0xF];
        }
    }
    
    return encoded;
}

// URL decode
std::string url_decode(const std::string& value) {
    std::string decoded;
    decoded.reserve(value.length());
    
    for (size_t i = 0; i < value.length(); ++i) {
        if (value[i] == '%' && i + 2 < value.length()) {
            std::string hex = value.substr(i + 1, 2);
            char decoded_char = static_cast<char>(std::stoi(hex, nullptr, 16));
            decoded += decoded_char;
            i += 2;
        } else if (value[i] == '+') {
            decoded += ' ';
        } else {
            decoded += value[i];
        }
    }
    
    return decoded;
}

// Get local IP address
std::string get_local_ip() {
    // This is a simplified version. In production, you might want to use
    // platform-specific APIs or a library like Boost.Asio
    
    try {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            struct hostent* host = gethostbyname(hostname);
            if (host != nullptr && host->h_addr_list[0] != nullptr) {
                struct in_addr addr;
                memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
                return std::string(inet_ntoa(addr));
            }
        }
    } catch (...) {
        // Fall through
    }
    
    return "127.0.0.1";
}

// Check if port is open
bool is_port_open(const std::string& host, int port, int timeout_ms) {
    // This would require socket programming
    // For simplicity, we'll provide a stub implementation
    // In production, use proper socket code or a library
    
    return false;
}

// ============================================================================
// Logging Utilities
// ============================================================================

// Thread-safe logger class
class Logger {
private:
    std::ofstream log_file_;
    std::mutex mutex_;
    LogSeverity min_severity_;
    bool console_output_;
    
public:
    Logger(const std::string& filename, 
           LogSeverity min_severity = LogSeverity::INFO,
           bool console_output = true)
        : min_severity_(min_severity), console_output_(console_output) {
        
        if (!filename.empty()) {
            log_file_.open(filename, std::ios::app);
        }
    }
    
    ~Logger() {
        if (log_file_.is_open()) {
            log_file_.close();
        }
    }
    
    void log(LogSeverity severity, const std::string& message) {
        if (static_cast<int>(severity) < static_cast<int>(min_severity_)) {
            return;
        }
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::string severity_str;
        switch (severity) {
            case LogSeverity::INFO: severity_str = "INFO"; break;
            case LogSeverity::WARNING: severity_str = "WARNING"; break;
            case LogSeverity::ERROR: severity_str = "ERROR"; break;
            case LogSeverity::CRITICAL: severity_str = "CRITICAL"; break;
            default: severity_str = "UNKNOWN"; break;
        }
        
        std::string timestamp = get_current_timestamp();
        std::string log_entry = "[" + timestamp + "] [" + severity_str + "] " + message;
        
        if (console_output_) {
            std::cout << log_entry << std::endl;
        }
        
        if (log_file_.is_open()) {
            log_file_ << log_entry << std::endl;
            log_file_.flush();
        }
    }
    
    void info(const std::string& message) {
        log(LogSeverity::INFO, message);
    }
    
    void warning(const std::string& message) {
        log(LogSeverity::WARNING, message);
    }
    
    void error(const std::string& message) {
        log(LogSeverity::ERROR, message);
    }
    
    void critical(const std::string& message) {
        log(LogSeverity::CRITICAL, message);
    }
};

// Global logger instance
static std::unique_ptr<Logger> global_logger;

// Initialize global logger
void init_logger(const std::string& filename, 
                LogSeverity min_severity, 
                bool console_output) {
    global_logger = std::make_unique<Logger>(filename, min_severity, console_output);
}

// Log functions using global logger
void log_info(const std::string& message) {
    if (global_logger) {
        global_logger->info(message);
    }
}

void log_warning(const std::string& message) {
    if (global_logger) {
        global_logger->warning(message);
    }
}

void log_error(const std::string& message) {
    if (global_logger) {
        global_logger->error(message);
    }
}

void log_critical(const std::string& message) {
    if (global_logger) {
        global_logger->critical(message);
    }
}

// ============================================================================
// Configuration Utilities
// ============================================================================

// Configuration manager class
class ConfigManager {
private:
    std::unordered_map<std::string, std::string> config_;
    std::string config_file_;
    std::mutex mutex_;
    
public:
    ConfigManager(const std::string& config_file = "")
        : config_file_(config_file) {
        
        if (!config_file.empty()) {
            load_from_file(config_file);
        }
    }
    
    void load_from_file(const std::string& filename) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open config file: " + filename);
        }
        
        config_.clear();
        std::string line;
        int line_num = 0;
        
        while (std::getline(file, line)) {
            line_num++;
            trim(line);
            
            // Skip empty lines and comments
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue;
            }
            
            size_t eq_pos = line.find('=');
            if (eq_pos == std::string::npos) {
                std::cerr << "Warning: Invalid config line " << line_num 
                         << ": " << line << std::endl;
                continue;
            }
            
            std::string key = trim_copy(line.substr(0, eq_pos));
            std::string value = trim_copy(line.substr(eq_pos + 1));
            
            // Remove quotes if present
            if (value.size() >= 2 && 
                ((value[0] == '"' && value.back() == '"') ||
                 (value[0] == '\'' && value.back() == '\''))) {
                value = value.substr(1, value.size() - 2);
            }
            
            config_[key] = value;
        }
        
        config_file_ = filename;
    }
    
    void save_to_file(const std::string& filename = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::string save_file = filename.empty() ? config_file_ : filename;
        if (save_file.empty()) {
            throw std::runtime_error("No config file specified");
        }
        
        std::ofstream file(save_file);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open config file for writing: " + save_file);
        }
        
        file << "# Log Summarizer Configuration\n";
        file << "# Generated: " << get_current_timestamp() << "\n\n";
        
        for (const auto& [key, value] : config_) {
            file << key << " = \"" << value << "\"\n";
        }
    }
    
    std::string get_string(const std::string& key, 
                          const std::string& default_value = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = config_.find(key);
        if (it != config_.end()) {
            return it->second;
        }
        
        return default_value;
    }
    
    int get_int(const std::string& key, int default_value = 0) const {
        std::string value = get_string(key);
        if (value.empty()) {
            return default_value;
        }
        
        try {
            return std::stoi(value);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    
    double get_double(const std::string& key, double default_value = 0.0) const {
        std::string value = get_string(key);
        if (value.empty()) {
            return default_value;
        }
        
        try {
            return std::stod(value);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    
    bool get_bool(const std::string& key, bool default_value = false) const {
        std::string value = get_string(key);
        if (value.empty()) {
            return default_value;
        }
        
        std::string lower_value = to_lower(value);
        return (lower_value == "true" || lower_value == "yes" || 
                lower_value == "1" || lower