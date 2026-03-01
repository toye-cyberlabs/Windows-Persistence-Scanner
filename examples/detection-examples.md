# Real-World Detection Examples

## Example 1: Coin Miner Persistence

**Scheduled Task Detected:**

<img width="1366" height="768" alt="P18_6" src="https://github.com/user-attachments/assets/e6fc04b8-3645-4660-b68f-5eb1627c4884" />

Task Name: ChromeUpdateTask
Path: \Microsoft\Windows
Execute: C:\Users\Public\svchost.exe
Arguments: --miner --pool xmr.pool.com
State: Running


**Analysis:** 
- Masquerading as Chrome update
- Running from Public folder (unusual)
- Arguments indicate cryptocurrency mining

**Recommended Actions:**
1. Kill the process
2. Disable the scheduled task
3. Remove the executable
4. Check for additional miner components

---

## Example 2: Registry Run Key Backdoor

**Registry Entry Found:**
<img width="1358" height="768" alt="P18_5" src="https://github.com/user-attachments/assets/03494d7f-4cee-42e2-870c-9f2298125ad9" />

Path: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Name: WindowsDefender
Value: powershell -WindowStyle Hidden -Enc SQBFAFgAKABOAGUAd...

Recommended Actions:

1.Remove registry entry

2. Check network connections

3.  Analyze downloaded payload

4. Check for other encoded PowerShell artifacts



