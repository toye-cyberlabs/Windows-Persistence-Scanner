
---

## 📄 docs/PERSISTENCE_TECHNIQUES.md

```markdown
# Windows Persistence Techniques Covered

## 1. Registry Run Keys
Malware often uses registry keys to maintain persistence by ensuring execution at system startup or user logon.

### Keys Checked:
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`

## 2. Scheduled Tasks
Attackers create scheduled tasks to execute malicious code at specific times or events.

### What We Look For:
- Tasks with suspicious names (updater, installer, etc.)
- Tasks executing from unusual locations
- Tasks running encoded PowerShell commands
- Recently created/modified tasks

## 3. Startup Folders
Simple but effective - placing executables or shortcuts in startup folders.

### Locations:
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

## 4. WMI Event Subscriptions
Advanced persistence using Windows Management Instrumentation to trigger code execution on specific events.

### Event Types:
- System startup
- User logon
- Process creation
- File creation/modification

## 5. Services
Malware often installs as Windows services for high-integrity execution.

### Red Flags:
- Non-Microsoft services with auto-start
- Services pointing to executable in user directories
- Services with suspicious descriptions

## 6. AppInit_DLLs
DLLs loaded into every process that loads User32.dll.

### Security Impact:
- Can be used to inject code into all GUI processes
- Requires administrative privileges to configure
- Highly effective persistence mechanism

## 7. Browser Helper Objects
Internet Explorer extensions that load with the browser.

### Considerations:
- Legacy technique but still present
- Can be used for credential theft
- Often overlooked in investigations
