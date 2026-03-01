=== MALWARE PERSISTENCE SCANNER ===
Scan started at: 2024-01-15 14:30:22
Computer Name: DESKTOP-ABC123
User: ANALYST\jsmith

=== SECTION 1: RUNNING PROCESSES ===
Top 50 processes by CPU usage:

Id  ProcessName  CPU  Path
--  -----------  ---  ----
1234 svchost     45   C:\Windows\System32\svchost.exe
5678 powershell  12   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

SUSPICIOUS PROCESSES DETECTED:
PID  Name       Path
---  ----       ----
4321 powershell C:\Users\Public\svchost.exe
