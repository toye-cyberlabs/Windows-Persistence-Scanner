
---

## 📸 Screenshots to Include

1. **Script Execution**: PowerShell console showing the script running
2. **Sample Output**: Highlighted suspicious findings
3. **Report File**: The generated text file opened in notepad
4. **Detection Examples**: Side-by-side comparison of normal vs suspicious

---

## 🏆 Portfolio Entry Description

```markdown
# Windows Persistence Scanner - SOC Automation Project

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

