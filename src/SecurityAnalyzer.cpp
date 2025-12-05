#include "SecurityAnalyzer.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <ctime>
#include <iostream>

// ============================================================================
// SecurityAnalyzer Implementation
// ============================================================================

SecurityAnalyzer::SecurityAnalyzer() {
    initialize_default_patterns();
    stats_ = {0, 0, 0, {}};
}

void SecurityAnalyzer::initialize_default_patterns() {
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    
    // Clear existing patterns
    patterns_.clear();
    
    // ==================== FAILED LOGIN PATTERNS ====================
    
    // SSH failed password
    patterns_.push_back({
        std::regex(R"(Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2)", std::regex::icase),
        "FailedLogin",
        6,
        {"SSH", "Authentication Failure"}
    });
    
    // Windows failed logon
    patterns_.push_back({
        std::regex(R"(Logon Failure.*Reason:\s*(?:Unknown user name|Invalid password))", std::regex::icase),
        "FailedLogin",
        5,
        {"Windows", "Logon Failure"}
    });
    
    // Invalid user attempt
    patterns_.push_back({
        std::regex(R"(Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+))", std::regex::icase),
        "FailedLogin",
        7,
        {"Invalid User", "Brute Force"}
    });
    
    // Authentication failure
    patterns_.push_back({
        std::regex(R"(authentication failure|auth fail|login failed)", std::regex::icase),
        "FailedLogin",
        4,
        {"Authentication Failure"}
    });
    
    // ==================== PRIVILEGE ESCALATION PATTERNS ====================
    
    // Sudo/su usage
    patterns_.push_back({
        std::regex(R"(sudo:.*COMMAND=.*(?:/bin/bash|/bin/sh|su -|su root))", std::regex::icase),
        "PrivilegeEscalation",
        8,
        {"sudo", "Privilege Elevation"}
    });
    
    // Windows privilege escalation
    patterns_.push_back({
        std::regex(R"(A privilege elevation was requested)", std::regex::icase),
        "PrivilegeEscalation",
        7,
        {"Windows", "UAC", "Privilege Elevation"}
    });
    
    // Setuid/setgid usage
    patterns_.push_back({
        std::regex(R"(setuid|setgid.*root)", std::regex::icase),
        "PrivilegeEscalation",
        9,
        {"setuid", "setgid", "Privilege Elevation"}
    });
    
    // ==================== BRUTE FORCE ATTACK PATTERNS ====================
    
    // Multiple failed logins from same IP
    patterns_.push_back({
        std::regex(R"(failed password|invalid user|authentication failure)", std::regex::icase),
        "BruteForce",
        8,
        {"Multiple Attempts", "Brute Force"}
    });
    
    // Account lockout
    patterns_.push_back({
        std::regex(R"(account locked out|too many failed attempts|account disabled)", std::regex::icase),
        "BruteForce",
        9,
        {"Account Lockout", "Brute Force"}
    });
    
    // ==================== PORT SCAN DETECTION ====================
    
    // Firewall/IDS port scan alerts
    patterns_.push_back({
        std::regex(R"(port scan|port scanning|port sweep)", std::regex::icase),
        "PortScan",
        5,
        {"Reconnaissance", "Port Scan"}
    });
    
    // Multiple connection attempts to different ports
    patterns_.push_back({
        std::regex(R"(connection attempt to port \d+)", std::regex::icase),
        "PortScan",
        6,
        {"Multiple Ports", "Reconnaissance"}
    });
    
    // ==================== MALWARE INDICATORS ====================
    
    // Known malicious file extensions
    patterns_.push_back({
        std::regex(R"(\.(exe|dll|vbs|js|ps1|bat|cmd)\s+(?:downloaded|executed|detected))", std::regex::icase),
        "Malware",
        8,
        {"Malicious File", "Execution"}
    });
    
    // Crypto mining/Malicious mining
    patterns_.push_back({
        std::regex(R"(cryptominer|xmrig|minerd|cpuminer)", std::regex::icase),
        "Malware",
        9,
        {"Cryptojacking", "Crypto Mining"}
    });
    
    // Ransomware indicators
    patterns_.push_back({
        std::regex(R"(ransomware|encrypted files|decryptor|bitcoin payment)", std::regex::icase),
        "Malware",
        10,
        {"Ransomware", "File Encryption"}
    });
    
    // ==================== NETWORK ATTACKS ====================
    
    // DDoS/Flood attacks
    patterns_.push_back({
        std::regex(R"(flood attack|ddos|syn flood|udp flood)", std::regex::icase),
        "DDoSAttack",
        9,
        {"DDoS", "Flood", "Network Attack"}
    });
    
    // SQL Injection attempts
    patterns_.push_back({
        std::regex(R"((union\s+select|drop\s+table|insert\s+into|update\s+.*set).*(\d+\.\d+\.\d+\.\d+))", std::regex::icase),
        "SQLInjection",
        8,
        {"SQL Injection", "Web Attack"}
    });
    
    // XSS attempts
    patterns_.push_back({
        std::regex(R"(<script>|javascript:|onerror=|onload=)", std::regex::icase),
        "XSSAttack",
        7,
        {"XSS", "Web Attack"}
    });
    
    // ==================== UNAUTHORIZED ACCESS ====================
    
    // Root/admin login
    patterns_.push_back({
        std::regex(R"(Accepted password for root|root logon|administrator logon)", std::regex::icase),
        "UnauthorizedAccess",
        9,
        {"Root Access", "Privileged Account"}
    });
    
    // Access to sensitive files
    patterns_.push_back({
        std::regex(R"(access to (?:/etc/passwd|/etc/shadow|/etc/sudoers|/root/))", std::regex::icase),
        "UnauthorizedAccess",
        8,
        {"Sensitive File Access"}
    });
    
    // ==================== SYSTEM COMPROMISE ====================
    
    // New user creation
    patterns_.push_back({
        std::regex(R"(new user.*added|useradd|net user.*/add)", std::regex::icase),
        "SystemCompromise",
        7,
        {"User Creation", "Persistence"}
    });
    
    // Scheduled task/cron job creation
    patterns_.push_back({
        std::regex(R"(crontab.*installed|scheduled task.*created|at job.*added)", std::regex::icase),
        "SystemCompromise",
        8,
        {"Persistence", "Scheduled Task"}
    });
    
    // ==================== DATA EXFILTRATION ====================
    
    // Large outbound transfers
    patterns_.push_back({
        std::regex(R"(large (?:outbound|upload).*\d+ (?:MB|GB|TB))", std::regex::icase),
        "DataExfiltration",
        9,
        {"Data Transfer", "Exfiltration"}
    });
    
    // Connection to known C2 servers
    patterns_.push_back({
        std::regex(R"(connection to (?:malicious|suspicious).*domain)", std::regex::icase),
        "DataExfiltration",
        8,
        {"C2 Communication", "Command & Control"}
    });
    
    // ==================== MISCELLANEOUS SECURITY EVENTS ====================
    
    // Firewall rule changes
    patterns_.push_back({
        std::regex(R"(firewall.*(?:changed|disabled|modified))", std::regex::icase),
        "SecurityPolicyChange",
        7,
        {"Firewall", "Policy Change"}
    });
    
    // Antivirus/IDS alerts
    patterns_.push_back({
        std::regex(R"(virus detected|malware detected|intrusion detected)", std::regex::icase),
        "AVAlert",
        6,
        {"Antivirus", "IDS Alert"}
    });
    
    // Service manipulation
    patterns_.push_back({
        std::regex(R"(service.*(?:stopped|started|disabled).*unauthorized)", std::regex::icase),
        "ServiceManipulation",
        8,
        {"Service Control", "Persistence"}
    });
}

std::vector<SecurityEvent> SecurityAnalyzer::analyze_logs(const std::vector<LogEntry>& logs) {
    std::vector<SecurityEvent> security_events;
    
    // Reset statistics
    stats_ = {static_cast<int>(logs.size()), 0, 0, {}};
    
    if (logs.empty()) {
        return security_events;
    }
    
    // Track for correlation analysis
    std::map<std::string, std::vector<LogEntry>> failed_logins_by_ip;
    std::map<std::string, std::vector<LogEntry>> failed_logins_by_user;
    std::set<std::string> suspicious_ips;
    
    // First pass: individual log analysis
    for (size_t i = 0; i < logs.size(); ++i) {
        const LogEntry& entry = logs[i];
        
        // Check against predefined patterns
        std::vector<SecurityEvent> pattern_events = check_patterns(entry);
        
        // Specialized detection methods
        SecurityEvent failed_login_event = detect_failed_login(entry);
        if (failed_login_event.risk_score > 0) {
            security_events.push_back(failed_login_event);
            
            // Track for correlation
            std::string ip = extract_ip_address(entry.message);
            std::string user = extract_username(entry.message);
            
            if (!ip.empty()) {
                failed_logins_by_ip[ip].push_back(entry);
                if (failed_logins_by_ip[ip].size() >= 5) {
                    suspicious_ips.insert(ip);
                }
            }
            
            if (!user.empty()) {
                failed_logins_by_user[user].push_back(entry);
            }
        }
        
        SecurityEvent priv_esc_event = detect_privilege_escalation(entry);
        if (priv_esc_event.risk_score > 0) {
            security_events.push_back(priv_esc_event);
        }
        
        SecurityEvent port_scan_event = detect_port_scan(entry);
        if (port_scan_event.risk_score > 0) {
            security_events.push_back(port_scan_event);
        }
        
        SecurityEvent malware_event = detect_malware_indicators(entry);
        if (malware_event.risk_score > 0) {
            security_events.push_back(malware_event);
        }
        
        // Add pattern-based events
        security_events.insert(security_events.end(), 
                             pattern_events.begin(), pattern_events.end());
    }
    
    // Second pass: correlation analysis
    for (size_t i = 0; i < logs.size(); ++i) {
        SecurityEvent brute_force_event = detect_brute_force(logs, i);
        if (brute_force_event.risk_score > 0) {
            security_events.push_back(brute_force_event);
        }
    }
    
    // Detect brute force from suspicious IPs
    for (const auto& ip : suspicious_ips) {
        if (failed_logins_by_ip[ip].size() >= 10) {
            SecurityEvent event;
            event.event_type = "BruteForceAttack";
            event.risk_score = 9;
            event.description = "Brute force attack detected from IP: " + ip + 
                              " (" + std::to_string(failed_logins_by_ip[ip].size()) + " attempts)";
            event.log_entry = failed_logins_by_ip[ip].front();
            event.indicators = {"Multiple Failed Logins", "Brute Force", "IP: " + ip};
            
            security_events.push_back(event);
            update_stats(event);
        }
    }
    
    // Remove duplicates (events with same type and similar timestamp)
    security_events = deduplicate_events(security_events);
    
    // Update statistics
    stats_.security_events = static_cast<int>(security_events.size());
    stats_.critical_events = std::count_if(security_events.begin(), security_events.end(),
        [](const SecurityEvent& e) { return e.risk_score >= 8; });
    
    return security_events;
}

std::vector<SecurityEvent> SecurityAnalyzer::check_patterns(const LogEntry& entry) {
    std::vector<SecurityEvent> events;
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    
    for (const auto& pattern : patterns_) {
        if (contains_pattern(entry.message, pattern.pattern)) {
            SecurityEvent event;
            event.event_type = pattern.event_type;
            event.risk_score = pattern.risk_score;
            event.log_entry = entry;
            event.indicators = pattern.indicators;
            
            // Extract additional details from message
            std::smatch match;
            if (std::regex_search(entry.message, match, pattern.pattern)) {
                std::stringstream desc;
                desc << pattern.event_type << " detected: ";
                
                // Add match groups to description
                for (size_t i = 1; i < match.size(); ++i) {
                    if (i > 1) desc << ", ";
                    desc << match[i].str();
                }
                
                // Extract IP addresses and usernames
                std::vector<std::string> extracted_indicators = extract_indicators(entry.message);
                event.indicators.insert(event.indicators.end(),
                                      extracted_indicators.begin(),
                                      extracted_indicators.end());
                
                event.description = desc.str();
            } else {
                event.description = pattern.event_type + " detected in log entry";
            }
            
            events.push_back(event);
            update_stats(event);
        }
    }
    
    return events;
}

SecurityEvent SecurityAnalyzer::detect_failed_login(const LogEntry& entry) const {
    SecurityEvent event;
    
    // SSH failed password patterns
    static const std::regex ssh_failed_pattern(
        R"(Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2)",
        std::regex::icase
    );
    
    // Windows failed logon patterns
    static const std::regex windows_failed_pattern(
        R"(Logon Failure.*Reason:\s*(?:Unknown user name|Invalid password))",
        std::regex::icase
    );
    
    // Invalid user patterns
    static const std::regex invalid_user_pattern(
        R"(Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+))",
        std::regex::icase
    );
    
    // Authentication failure patterns
    static const std::regex auth_failure_pattern(
        R"(authentication failure.*user=(\S+).*rhost=(\S+))",
        std::regex::icase
    );
    
    std::smatch match;
    
    if (std::regex_search(entry.message, match, ssh_failed_pattern)) {
        event.event_type = "FailedLogin";
        event.risk_score = 6;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        std::string ip = match[2].str();
        
        event.description = "SSH failed login attempt for user '" + user + 
                          "' from IP " + ip;
        event.indicators = {"SSH", "Failed Password", "User: " + user, "IP: " + ip};
        
    } else if (std::regex_search(entry.message, match, windows_failed_pattern)) {
        event.event_type = "FailedLogin";
        event.risk_score = 5;
        event.log_entry = entry;
        
        event.description = "Windows logon failure detected";
        event.indicators = {"Windows", "Logon Failure"};
        
        // Extract error code if present
        static const std::regex error_code_pattern(R"(Error Code:\s*(\d+))");
        std::smatch error_match;
        if (std::regex_search(entry.message, error_match, error_code_pattern)) {
            event.indicators.push_back("Error Code: " + error_match[1].str());
        }
        
    } else if (std::regex_search(entry.message, match, invalid_user_pattern)) {
        event.event_type = "FailedLogin";
        event.risk_score = 7; // Higher risk - invalid user suggests enumeration
        event.log_entry = entry;
        
        std::string user = match[1].str();
        std::string ip = match[2].str();
        
        event.description = "Invalid user login attempt '" + user + 
                          "' from IP " + ip;
        event.indicators = {"Invalid User", "User Enumeration", "IP: " + ip};
        
    } else if (std::regex_search(entry.message, match, auth_failure_pattern)) {
        event.event_type = "FailedLogin";
        event.risk_score = 5;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        std::string rhost = match[2].str();
        
        event.description = "Authentication failure for user '" + user + 
                          "' from " + rhost;
        event.indicators = {"Authentication Failure", "User: " + user, "Host: " + rhost};
    }
    
    return event;
}

SecurityEvent SecurityAnalyzer::detect_privilege_escalation(const LogEntry& entry) const {
    SecurityEvent event;
    
    // Sudo command execution patterns
    static const std::regex sudo_pattern(
        R"(sudo:\s+(\S+)\s*:\s*COMMAND=.*(?:/bin/(?:bash|sh)|su -|su root))",
        std::regex::icase
    );
    
    // su command usage
    static const std::regex su_pattern(
        R"(su:\s+(?:to\s+)?root.*by\s+(\S+))",
        std::regex::icase
    );
    
    // Windows UAC elevation
    static const std::regex uac_pattern(
        R"(A privilege elevation was requested by\s+(\S+))",
        std::regex::icase
    );
    
    // Setuid/setgid execution
    static const std::regex setuid_pattern(
        R"(setuid|setgid.*executed.*by\s+(\S+))",
        std::regex::icase
    );
    
    std::smatch match;
    
    if (std::regex_search(entry.message, match, sudo_pattern)) {
        event.event_type = "PrivilegeEscalation";
        event.risk_score = 8;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        
        event.description = "Privilege escalation via sudo by user '" + user + "'";
        event.indicators = {"sudo", "Privilege Elevation", "User: " + user};
        
        // Check for dangerous commands
        static const std::regex dangerous_cmd_pattern(
            R"(COMMAND=(/bin/(?:bash|sh)|/usr/bin/chmod\s+[0-7][0-7][0-7]\s+\S+|"
            R"/usr/bin/chown\s+root\s+\S+|/usr/bin/passwd))"
        );
        
        if (std::regex_search(entry.message, dangerous_cmd_pattern)) {
            event.risk_score = 9;
            event.indicators.push_back("Dangerous Command");
        }
        
    } else if (std::regex_search(entry.message, match, su_pattern)) {
        event.event_type = "PrivilegeEscalation";
        event.risk_score = 7;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        
        event.description = "Privilege escalation via su to root by user '" + user + "'";
        event.indicators = {"su", "Root Access", "User: " + user};
        
    } else if (std::regex_search(entry.message, match, uac_pattern)) {
        event.event_type = "PrivilegeEscalation";
        event.risk_score = 6;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        
        event.description = "Windows UAC privilege elevation requested by '" + user + "'";
        event.indicators = {"UAC", "Privilege Elevation", "User: " + user};
        
    } else if (std::regex_search(entry.message, match, setuid_pattern)) {
        event.event_type = "PrivilegeEscalation";
        event.risk_score = 9;
        event.log_entry = entry;
        
        std::string user = match[1].str();
        
        event.description = "Setuid/setgid program execution by user '" + user + "'";
        event.indicators = {"setuid/setgid", "Privilege Elevation", "User: " + user};
    }
    
    return event;
}

SecurityEvent SecurityAnalyzer::detect_brute_force(const std::vector<LogEntry>& logs, 
                                                  size_t current_index) const {
    SecurityEvent event;
    
    if (current_index < 5) {
        return event; // Need enough history
    }
    
    // Look for multiple failed logins within a short time window
    const LogEntry& current_entry = logs[current_index];
    
    // Check if current entry is a failed login
    if (!contains_pattern(current_entry.message, 
                         std::regex(R"(failed password|invalid user|authentication failure)",
                                   std::regex::icase))) {
        return event;
    }
    
    // Analyze previous entries within a time window (e.g., 5 minutes)
    std::time_t current_time = parse_timestamp(current_entry.timestamp);
    if (current_time == 0) {
        return event;
    }
    
    std::vector<LogEntry> recent_failures;
    std::set<std::string> source_ips;
    std::set<std::string> target_users;
    
    // Look back up to 100 entries or 5 minutes
    int lookback_count = 0;
    for (int i = static_cast<int>(current_index) - 1; i >= 0 && lookback_count < 100; --i, ++lookback_count) {
        const LogEntry& previous_entry = logs[i];
        
        // Check time difference
        std::time_t previous_time = parse_timestamp(previous_entry.timestamp);
        if (previous_time == 0) {
            continue;
        }
        
        double time_diff = std::difftime(current_time, previous_time);
        if (time_diff > 300) { // 5 minutes in seconds
            break;
        }
        
        // Check if it's a failed login
        if (contains_pattern(previous_entry.message,
                           std::regex(R"(failed password|invalid user|authentication failure)",
                                     std::regex::icase))) {
            recent_failures.push_back(previous_entry);
            
            // Extract IP and user
            std::string ip = extract_ip_address(previous_entry.message);
            std::string user = extract_username(previous_entry.message);
            
            if (!ip.empty()) source_ips.insert(ip);
            if (!user.empty()) target_users.insert(user);
        }
    }
    
    // Check for brute force patterns
    if (recent_failures.size() >= 5) {
        event.event_type = "BruteForceAttack";
        event.risk_score = std::min(10, 5 + static_cast<int>(recent_failures.size() / 2));
        event.log_entry = current_entry;
        
        std::stringstream desc;
        desc << "Potential brute force attack detected: " 
             << recent_failures.size() + 1 << " failed login attempts";
        
        if (!source_ips.empty()) {
            desc << " from " << source_ips.size() << " unique IP(s)";
        }
        
        if (!target_users.empty()) {
            desc << " targeting " << target_users.size() << " user(s)";
        }
        
        event.description = desc.str();
        event.indicators = {"Brute Force", "Multiple Failed Logins"};
        
        // Add specific indicators
        for (const auto& ip : source_ips) {
            event.indicators.push_back("IP: " + ip);
        }
        
        for (const auto& user : target_users) {
            event.indicators.push_back("Target User: " + user);
        }
    }
    
    return event;
}

SecurityEvent SecurityAnalyzer::detect_port_scan(const LogEntry& entry) const {
    SecurityEvent event;
    
    // Firewall/IDS port scan alerts
    static const std::regex port_scan_pattern(
        R"(port scan detected|port scanning activity|port sweep)",
        std::regex::icase
    );
    
    // Multiple rejected connections
    static const std::regex multiple_ports_pattern(
        R"(rejected connection.*port (\d+).*from (\d+\.\d+\.\d+\.\d+))",
        std::regex::icase
    );
    
    // Nmap/scan tool signatures
    static const std::regex nmap_pattern(
        R"(nmap|masscan|nessus|openvas|metasploit)",
        std::regex::icase
    );
    
    std::smatch match;
    
    if (std::regex_search(entry.message, match, port_scan_pattern)) {
        event.event_type = "PortScan";
        event.risk_score = 5;
        event.log_entry = entry;
        
        event.description = "Port scan activity detected";
        event.indicators = {"Reconnaissance", "Port Scan"};
        
    } else if (std::regex_search(entry.message, match, multiple_ports_pattern)) {
        // Check context for multiple ports from same IP
        event.event_type = "PortScan";
        event.risk_score = 6;
        event.log_entry = entry;
        
        std::string port = match[1].str();
        std::string ip = match[2].str();
        
        event.description = "Port scan attempt on port " + port + " from IP " + ip;
        event.indicators = {"Port Scan", "Port: " + port, "IP: " + ip};
        
    } else if (std::regex_search(entry.message, nmap_pattern)) {
        event.event_type = "PortScan";
        event.risk_score = 7;
        event.log_entry = entry;
        
        event.description = "Scanning tool signature detected";
        event.indicators = {"Scanning Tool", "Reconnaissance"};
    }
    
    return event;
}

SecurityEvent SecurityAnalyzer::detect_malware_indicators(const LogEntry& entry) const {
    SecurityEvent event;
    
    // Known malware signatures
    static const std::regex malware_pattern(
        R"(malware|virus|trojan|worm|ransomware|spyware|adware|botnet)",
        std::regex::icase
    );
    
    // Suspicious file extensions
    static const std::regex suspicious_file_pattern(
        R"(\.(exe|dll|vbs|js|ps1|bat|cmd|scr|pif)\s+(?:downloaded|executed|created))",
        std::regex::icase
    );
    
    // Crypto mining indicators
    static const std::regex cryptominer_pattern(
        R"(xmrig|minerd|cpuminer|ccminer|nicehash|cryptonight)",
        std::regex::icase
    );
    
    // Web shell indicators
    static const std::regex webshell_pattern(
        R"(webshell|php shell|c99|c100|r57|wso)",
        std::regex::icase
    );
    
    // Command and control communication
    static const std::regex c2_pattern(
        R"(c2 server|command and control|beaconing)",
        std::regex::icase
    );
    
    std::smatch match;
    
    if (std::regex_search(entry.message, match, malware_pattern)) {
        event.event_type = "Malware";
        event.risk_score = 8;
        event.log_entry = entry;
        
        event.description = "Malware-related activity detected";
        event.indicators = {"Malware", "Threat Detection"};
        
        // Extract malware name if present
        std::string lower_msg = entry.message;
        std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        
        if (lower_msg.find("ransomware") != std::string::npos) {
            event.risk_score = 10;
            event.indicators.push_back("Ransomware");
        } else if (lower_msg.find("botnet") != std::string::npos) {
            event.risk_score = 9;
            event.indicators.push_back("Botnet");
        }
        
    } else if (std::regex_search(entry.message, match, suspicious_file_pattern)) {
        event.event_type = "Malware";
        event.risk_score = 7;
        event.log_entry = entry;
        
        std::string file_ext = match[1].str();
        
        event.description = "Suspicious file (" + file_ext + ") activity detected";
        event.indicators = {"Suspicious File", "Extension: ." + file_ext};
        
    } else if (std::regex_search(entry.message, match, cryptominer_pattern)) {
        event.event_type = "Cryptojacking";
        event.risk_score = 8;
        event.log_entry = entry;
        
        std::string miner_name = match[0].str();
        
        event.description = "Cryptocurrency mining activity detected: " + miner_name;
        event.indicators = {"Cryptojacking", "Crypto Mining", "Miner: " + miner_name};
        
    } else if (std::regex_search(entry.message, match, webshell_pattern)) {
        event.event_type = "WebShell";
        event.risk_score = 9;
        event.log_entry = entry;
        
        event.description = "Web shell activity detected";
        event.indicators = {"Web Shell", "Backdoor", "Persistence"};
        
    } else if (std::regex_search(entry.message, match, c2_pattern)) {
        event.event_type = "C2Communication";
        event.risk_score = 9;
        event.log_entry = entry;
        
        event.description = "Command and control communication detected";
        event.indicators = {"C2", "Command & Control", "Lateral Movement"};
    }
    
    return event;
}

void SecurityAnalyzer::add_detection_pattern(
    const std::string& pattern_name,
    const std::regex& pattern,
    const std::string& event_type,
    int risk_score) {
    
    std::lock_guard<std::mutex> lock(patterns_mutex_);
    
    DetectionPattern new_pattern;
    new_pattern.pattern = pattern;
    new_pattern.event_type = event_type;
    new_pattern.risk_score = risk_score;
    new_pattern.indicators = {pattern_name};
    
    patterns_.push_back(new_pattern);
}

SecurityAnalyzer::AnalysisStats SecurityAnalyzer::get_statistics() const {
    return stats_;
}

bool SecurityAnalyzer::contains_pattern(const std::string& text, 
                                       const std::regex& pattern) const {
    return std::regex_search(text, pattern);
}

std::vector<std::string> SecurityAnalyzer::extract_indicators(const std::string& text) const {
    std::vector<std::string> indicators;
    
    // Extract IP addresses
    static const std::regex ip_pattern(
        R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    );
    
    std::sregex_iterator ip_it(text.begin(), text.end(), ip_pattern);
    std::sregex_iterator ip_end;
    
    while (ip_it != ip_end) {
        indicators.push_back("IP: " + (*ip_it)[0].str());
        ++ip_it;
    }
    
    // Extract usernames (common patterns)
    static const std::regex user_pattern(
        R"(user[=:\s]+(\w+)|for\s+(\w+)\s+from|by\s+(\w+)\s+)",
        std::regex::icase
    );
    
    std::sregex_iterator user_it(text.begin(), text.end(), user_pattern);
    std::sregex_iterator user_end;
    
    while (user_it != user_end) {
        for (size_t i = 1; i < (*user_it).size(); ++i) {
            if ((*user_it)[i].matched && !(*user_it)[i].str().empty()) {
                indicators.push_back("User: " + (*user_it)[i].str());
                break;
            }
        }
        ++user_it;
    }
    
    // Extract ports
    static const std::regex port_pattern(
        R"(port\s+(\d{1,5})\b)"
    );
    
    std::sregex_iterator port_it(text.begin(), text.end(), port_pattern);
    std::sregex_iterator port_end;
    
    while (port_it != port_end) {
        indicators.push_back("Port: " + (*port_it)[1].str());
        ++port_it;
    }
    
    // Extract domains/URLs
    static const std::regex url_pattern(
        R"(\b(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)\b)"
    );
    
    std::sregex_iterator url_it(text.begin(), text.end(), url_pattern);
    std::sregex_iterator url_end;
    
    while (url_it != url_end) {
        indicators.push_back("Domain: " + (*url_it)[1].str());
        ++url_it;
    }
    
    return indicators;
}

void SecurityAnalyzer::update_stats(const SecurityEvent& event) {
    stats_.event_counts[event.event_type]++;
    
    if (event.risk_score >= 8) {
        stats_.critical_events++;
    }
}

std::string SecurityAnalyzer::extract_ip_address(const std::string& text) const {
    static const std::regex ip_pattern(
        R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    );
    
    std::smatch match;
    if (std::regex_search(text, match, ip_pattern)) {
        return match[0].str();
    }
    
    return "";
}

std::string SecurityAnalyzer::extract_username(const std::string& text) const {
    // Common username patterns in log messages
    static const std::vector<std::regex> user_patterns = {
        std::regex(R"(user[=:\s]+(\w+))", std::regex::icase),
        std::regex(R"(for\s+(\w+)\s+from)", std::regex::icase),
        std::regex(R"(by\s+(\w+)\s+)", std::regex::icase),
        std::regex(R"(login\s+(\w+))", std::regex::icase),
        std::regex(R"(account\s+(\w+))", std::regex::icase)
    };
    
    for (const auto& pattern : user_patterns) {
        std::smatch match;
        if (std::regex_search(text, match, pattern)) {
            return match[1].str();
        }
    }
    
    return "";
}

std::time_t SecurityAnalyzer::parse_timestamp(const std::string& timestamp) const {
    if (timestamp.empty()) {
        return 0;
    }
    
    // Try multiple timestamp formats
    std::vector<std::string> formats = {
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%b %d %H:%M:%S",  // Syslog format (missing year)
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a %b %d %H:%M:%S %Y" 