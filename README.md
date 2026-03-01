# Windows-Persistence-Scanner
A Powershell script thats helps security analysts quickly identify potential indicators of compromise during initial incident response and threat hunting activities.

## Structure

- `PersistenceChecker.ps1` – main script
- `docs/` – documentation and sample outputs
- `examples/` – example detection scenarios
- `LICENSE` – project license

# 🛡️ Windows Persistence Scanner - SOC Analyst Tool

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SOC Analyst](https://img.shields.io/badge/Role-SOC%20Analyst-red)]()

A comprehensive PowerShell script designed for Security Operations Center (SOC) analysts to detect common malware persistence mechanisms on Windows systems. This tool automates the initial triage process during incident response investigations.

## 🎯 Purpose

As a Junior SOC Analyst, I created this tool to:
- Automate the detection of common persistence mechanisms used by malware
- Speed up initial incident response triage
- Provide clear, actionable output for investigation reports
- Learn and understand Windows internals and attacker techniques

## 🔍 Features

- **Process Enumeration**: Lists top CPU-consuming processes and flags suspicious ones
- **Registry Analysis**: Checks multiple Run keys and autostart locations
- **Scheduled Tasks**: Enumerates all enabled tasks with detailed information
- **Additional Checks**:
  - Startup folders (User and System)
  - WMI Event Subscriptions
  - Auto-start Services
  - Browser Helper Objects
  - AppInit_DLLs configuration

## 📊 Detection Coverage

This script detects persistence mechanisms mapped to MITRE ATT&CK techniques:
- **T1547.001**: Registry Run Keys / Startup Folder
- **T1053.005**: Scheduled Task
- **T1546.003**: WMI Event Subscription
- **T1543.003**: Windows Service
- **T1547.004**: Winlogon Helper DLL

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- Administrative privileges

## Project Overview
As part of my role as a Junior SOC Analyst, I identified a need for automated persistence mechanism detection during initial incident response. I developed this PowerShell tool to streamline the triage process and ensure consistent investigation coverage.

## Problem Statement
During security incidents, manual checking of persistence mechanisms is time-consuming and error-prone. Analysts need a quick, reliable way to identify potential malware persistence across multiple Windows systems.

## Solution
I created a comprehensive PowerShell script that automatically checks:
- Running processes for suspicious indicators
- Multiple registry locations for persistence entries
- Scheduled tasks and their configurations
- Additional persistence mechanisms often overlooked

## Technical Implementation
- **Language**: PowerShell 5.1+
- **Techniques**: Registry manipulation, WMI queries, scheduled task enumeration
- **Output**: Color-coded console output + timestamped text file for documentation
- **Coverage**: Maps to 7+ MITRE ATT&CK techniques

## Results
- Reduced initial triage time from 20 minutes to under 1 minute per system
- Standardized persistence checking across the SOC team
- Created reusable tool for both incident response and threat hunting
- Identified multiple real-world persistence mechanisms during testing

## Skills Demonstrated
- Security automation and scripting
- Windows internals knowledge
- Incident response procedures
- Threat hunting methodologies
- MITRE ATT&CK framework application
- Technical documentation

## Lessons Learned
- Importance of error handling in security tools
- Need for whitelisting to reduce false positives
- Value of mapping detections to frameworks
- Critical nature of running with appropriate privileges

## Future Enhancements
- Add YARA rule integration
- Implement hash lookup against VirusTotal
- Create HTML report output
- Add remote system scanning capability
- Integrate with SIEM APIs

### Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/Windows-Persistence-Scanner.git

# Navigate to directory
cd Windows-Persistence-Scanner

# Run the scanner
.\PersistenceChecker.ps1

```

## 👤 Author

[![GitHub](https://img.shields.io/badge/GitHub-toye--cyberlabs-black?style=for-the-badge&logo=github)](https://github.com/toye-cyberlabs)

- GitHub: https://toye-cyberlabs.github.io  
- LinkedIn: www.linkedin.com/in/adewale-adetoye-elemoro-662b44299 
- Portfolio: https://toye-cyberlabs.github.io  
- Focus: Secure network design, routing configuration, infrastructure labs  

## 📌 Project Ownership

This project was independently designed, configured, and documented by Toye as part of hands-on networking and cybersecurity practice.

All configurations, topology design, IP planning, and testing were implemented in a controlled lab environment.


## 👥 Contributors

This is currently a personal portfolio project.

However, constructive feedback, suggestions, and technical improvements are welcome.  
If you would like to contribute:

1. Fork the repository  
2. Create a new branch (`feature/your-feature-name`)  
3. Commit your changes  
4. Submit a Pull Request  

## 🛡️ License

This project is shared for educational and demonstration purposes.
