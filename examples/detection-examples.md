## PowersShell

# Basic scan
.\PersistenceChecker.ps1

# Save output to custom location
.\PersistenceChecker.ps1 -OutputPath "C:\Reports\scan_$(Get-Date -Format 'yyyyMMdd').txt"

# Run with verbose logging
.\PersistenceChecker.ps1 -Verbose
