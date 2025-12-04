# Log Summarizer Bot

A C++ application for analyzing security logs using local LLM (OLLAMA) integration.

## Features

- **Multi-format Support**: Parse syslog, Windows Event Logs, JSON, and more
- **Security Analysis**: Detect failed logins, privilege escalation, brute force attacks
- **LLM Integration**: Generate intelligent summaries using OLLAMA
- **Modular Design**: Easy to extend with new parsers and analyzers
- **Secure**: Input sanitization, error handling, safe memory management

## Prerequisites

### Dependencies
1. **OLLAMA**: [Install OLLAMA](https://ollama.ai/)
2. **C++ Compiler** with C++17 support
3. **CMake** 3.16+
4. **libcurl** and **jsoncpp**

### Install Dependencies

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libcurl4-openssl-dev libjsoncpp-dev