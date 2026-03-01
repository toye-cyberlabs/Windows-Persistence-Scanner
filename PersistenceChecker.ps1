<#
.SYNOPSIS
    Malware Persistence Checker - Windows Persistence Mechanism Scanner
.DESCRIPTION
    This script enumerates common persistence mechanisms used by malware including:
    - Running processes with suspicious characteristics
    - Registry Run keys and autostart locations
    - Scheduled tasks
    - Additional common persistence locations
.NOTES
    Author: Junior SOC Analyst
    Version: 1.0
    Run with administrative privileges for best results
#>

# Requires -RunAsAdministrator

# Set execution policy for the script session
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# Output file for results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "Persistence_Scan_$timestamp.txt"
$suspiciousProcesses = @()

# Function to write output to both console and file
function Write-OutputLog {
    param([string]$Message)
    Write-Host $Message
    Add-Content -Path $outputFile -Value $Message
}

Write-OutputLog "=== MALWARE PERSISTENCE SCANNER ==="
Write-OutputLog "Scan started at: $(Get-Date)"
Write-OutputLog "Computer Name: $env:COMPUTERNAME"
Write-OutputLog "User: $env:USERNAME"
Write-OutputLog ""

# 1. ENUMERATE RUNNING PROCESSES
Write-OutputLog "=== SECTION 1: RUNNING PROCESSES ==="

try {
    $processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 50
    Write-OutputLog "Top 50 processes by CPU usage:"
    $processes | Format-Table -Property Id, ProcessName, CPU, Path -AutoSize | Out-String -Width 4096 | Write-OutputLog
    
    # Check for suspicious processes
    $suspiciousNames = @("cmd", "powershell", "wscript", "cscript", "mshta", "regsvr32", "rundll32", "schtasks")
    $runningProcesses = Get-Process
    
    foreach ($proc in $runningProcesses) {
        if ($suspiciousNames -contains $proc.ProcessName.ToLower()) {
            try {
                $path = (Get-Process -Id $proc.Id -FileVersionInfo).FileName
                $suspiciousProcesses += [PSCustomObject]@{
                    PID = $proc.Id
                    Name = $proc.ProcessName
                    Path = $path
                }
            } catch {
                # Ignore if we can't get the path
            }
        }
    }
    
    if ($suspiciousProcesses.Count -gt 0) {
        Write-OutputLog "`nSUSPICIOUS PROCESSES DETECTED:"
        $suspiciousProcesses | Format-Table -AutoSize | Out-String -Width 4096 | Write-OutputLog
    }
} catch {
    Write-OutputLog "Error enumerating processes: $_"
}
Write-OutputLog ""

# 2. CHECK REGISTRY RUN KEYS
Write-OutputLog "=== SECTION 2: REGISTRY RUN KEYS ==="

$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    # Additional persistence locations
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
)

foreach ($path in $registryPaths) {
    try {
        if (Test-Path $path) {
            $values = Get-ItemProperty -Path $path -ErrorAction Stop
            Write-OutputLog "`nRegistry Path: $path"
            
            # Check if path has any values
            $hasValues = $false
            foreach ($property in $values.PSObject.Properties) {
                if ($property.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    Write-OutputLog "  $($property.Name) = $($property.Value)"
                    $hasValues = $true
                }
            }
            
            if (-not $hasValues) {
                Write-OutputLog "  No entries found"
            }
        }
    } catch {
        Write-OutputLog "Error accessing $path : $_"
    }
}
Write-OutputLog ""

# 3. CHECK SCHEDULED TASKS
Write-OutputLog "=== SECTION 3: SCHEDULED TASKS ==="

try {
    # Get all scheduled tasks
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.State -ne 'Disabled'}
    
    if ($tasks.Count -gt 0) {
        Write-OutputLog "Found $($tasks.Count) enabled scheduled tasks:"
        
        foreach ($task in $tasks) {
            Write-OutputLog "`nTask Name: $($task.TaskName)"
            Write-OutputLog "  Path: $($task.TaskPath)"
            Write-OutputLog "  State: $($task.State)"
            
            # Get task details including actions
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-OutputLog "  Last Run Time: $($taskInfo.LastRunTime)"
                    Write-OutputLog "  Last Result: $($taskInfo.LastTaskResult)"
                }
                
                # Get task actions
                $taskActions = $task.Actions
                if ($taskActions) {
                    Write-OutputLog "  Actions:"
                    foreach ($action in $taskActions) {
                        if ($action.Execute) {
                            Write-OutputLog "    Execute: $($action.Execute)"
                            if ($action.Arguments) {
                                Write-OutputLog "    Arguments: $($action.Arguments)"
                            }
                        }
                    }
                }
            } catch {
                Write-OutputLog "  Could not retrieve detailed task information"
            }
            
            # Flag potentially suspicious tasks
            if ($task.TaskName -match "update|updater|installer|svchost|crypto|miner|java|adobe|flash") {
                Write-OutputLog "  *** SUSPICIOUS: Task name contains potentially suspicious pattern ***"
            }
        }
    } else {
        Write-OutputLog "No enabled scheduled tasks found"
    }
} catch {
    Write-OutputLog "Error enumerating scheduled tasks: $_"
}
Write-OutputLog ""

# 4. ADDITIONAL PERSISTENCE CHECKS
Write-OutputLog "=== SECTION 4: ADDITIONAL PERSISTENCE MECHANISMS ==="

# Check Startup folders
Write-OutputLog "`n--- Startup Folders ---"
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Write-OutputLog "Folder: $folder"
        $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
        if ($items.Count -gt 0) {
            foreach ($item in $items) {
                Write-OutputLog "  File: $($item.Name) - Modified: $($item.LastWriteTime)"
            }
        } else {
            Write-OutputLog "  No files found"
        }
    }
}

# Check WMI Event Subscriptions (if PowerShell version supports it)
Write-OutputLog "`n--- WMI Event Subscriptions ---"
try {
    $wmiEvents = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    if ($wmiEvents) {
        Write-OutputLog "Found WMI Event Filters:"
        $wmiEvents | ForEach-Object {
            Write-OutputLog "  Name: $($_.Name)"
            Write-OutputLog "  Query: $($_.Query)"
        }
    } else {
        Write-OutputLog "No WMI Event Filters found"
    }
} catch {
    Write-OutputLog "Error checking WMI events (may require admin rights): $_"
}

# Check Services
Write-OutputLog "`n--- Non-Microsoft Services ---"
try {
    $services = Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running' -and $_.Name -notlike '*Microsoft*'}
    if ($services.Count -gt 0) {
        Write-OutputLog "Found $($services.Count) non-Microsoft auto-start services:"
        $services | Select-Object Name, DisplayName, Status | Format-Table -AutoSize | Out-String -Width 4096 | Write-OutputLog
    } else {
        Write-OutputLog "No non-Microsoft auto-start services found"
    }
} catch {
    Write-OutputLog "Error checking services: $_"
}

# Check Browser Helper Objects (if on system with IE/Edge)
Write-OutputLog "`n--- Browser Helper Objects ---"
try {
    $bhoPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    if (Test-Path $bhoPath) {
        $bho = Get-ChildItem -Path $bhoPath -ErrorAction SilentlyContinue
        if ($bho.Count -gt 0) {
            Write-OutputLog "Found Browser Helper Objects:"
            $bho | ForEach-Object {
                Write-OutputLog "  CLSID: $($_.PSChildName)"
            }
        } else {
            Write-OutputLog "No Browser Helper Objects found"
        }
    }
} catch {
    Write-OutputLog "Error checking Browser Helper Objects: $_"
}

# Check AppInit_DLLs
Write-OutputLog "`n--- AppInit_DLLs ---"
try {
    $appInitPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    if (Test-Path $appInitPath) {
        $appInit = Get-ItemProperty -Path $appInitPath -Name AppInit_DLLs -ErrorAction SilentlyContinue
        if ($appInit.AppInit_DLLs -and $appInit.AppInit_DLLs -ne "") {
            Write-OutputLog "AppInit_DLLs: $($appInit.AppInit_DLLs)"
            Write-OutputLog "  *** SUSPICIOUS: AppInit_DLLs is configured ***"
        } else {
            Write-OutputLog "No AppInit_DLLs configured"
        }
    }
} catch {
    Write-OutputLog "Error checking AppInit_DLLs: $_"
}

Write-OutputLog "`n=== SCAN COMPLETED ==="
Write-OutputLog "Scan completed at: $(Get-Date)"
Write-OutputLog "Results saved to: $outputFile"

# Display summary
Write-Host "`n" -ForegroundColor Green
Write-Host "SCAN SUMMARY:" -ForegroundColor Yellow
Write-Host "  - Processes analyzed: $($runningProcesses.Count)" -ForegroundColor Cyan
Write-Host "  - Registry run keys checked: $($registryPaths.Count)" -ForegroundColor Cyan
Write-Host "  - Scheduled tasks found: $($tasks.Count)" -ForegroundColor Cyan
if ($suspiciousProcesses.Count -gt 0) {
    Write-Host "  - WARNING: $($suspiciousProcesses.Count) potentially suspicious processes detected!" -ForegroundColor Red
} else {
    Write-Host "  - No suspicious processes detected" -ForegroundColor Green
}
Write-Host "`nFull results saved to: $outputFile" -ForegroundColor Green