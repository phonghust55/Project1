# Title: Chinese Rat
*Investigator:Phong Pham, Nguyen Vu*  
*Date:19/06/2025*

---

## 1. Executive Summary

This report presents a comprehensive analysis of a malicious executable file identified by the SHA256 hash `2ef41f1f4332bf7cc069dab392e4f160b81cd8b7b5b3b4c68dc5a04e4518e085`. The sample is a 64-bit GUI application that has been packed using UPX and exhibits a high entropy value, indicating potential obfuscation or packing.

Static and behavioral analysis revealed that the malware exhibits advanced system manipulation capabilities. These include browser hijacking, disabling critical system defenses, installing potentially unwanted programs (PUPs), and modifying key registry entries to maintain persistence and degrade user control. The malware requires administrative privileges to operate fully, suggesting it targets elevated user environments.

Detected by 53 out of 71 antivirus engines on VirusTotal, the malware demonstrates characteristics typical of trojans and adware droppers, with Chinese-language indicators and aggressive system modification behavior.

---

## 2. Identification

### 2.1 Filename
`2ef41f1f4332bf7cc069dab392e4f160b81cd8b7b5b3b4c68dc5a04e4518e085.exe`  
**File size:** 963584 bytes  
**Entropy:** 6.419  
**Type:** Executable, 64-bit, GUI

### 2.2 MAC Timestamps
**Mon Jun 21 14:47:58 2021 (UTC)**

### 2.3 Hashes
- **MD5:** 31b407850c3c20bed39117100dbcc552  
- **SHA1:** 31b407850c3c20bed39117100dbcc552  
- **SHA256:** 2ef41f1f4332bf7cc069dab392e4f160b81cd8b7b5b3b4c68dc5a04e4518e085

### 2.4 Signing Information (Certificates)
- Microsoft Linker 11.0  
- Windows Server 2003 R2  

**Characteristics:**
- ASLR: `0x004`
- DEP: `0x010`
- SEH: `0x0000`
- TSA: `0x800`

### 2.5 TrID - Packer Info

| Offset        | Size          | Entropy | Status     | Name                  |
|---------------|---------------|---------|------------|------------------------|
| 0x0000000000  | 0x0000001000  | 7.11218 | packed     | PE Header             |
| 0x0000000400  | 0x00064C00    | 7.94304 | packed     | Section(1)['UPX1']    |
| 0x00065000    | 0x00001E00    | 4.96703 | not packed | Section(2)['.rsrc']   |

### 2.6 Aliases
**Detection rate:** 53/71 on VirusTotal

| AV Engine     | Result                        |
|---------------|-------------------------------|
| Avast         | Win64:Evo-gen [Trj]           |
| AVG           | Win64:Evo-gen [Trj]           |
| Avira         | HEUR/AGEN.1322287             |
| BitDefender   | Trojan.Generic.32086707       |
| Bkav Pro      | W64.AIDetectMalware           |
| ClamAV        | Win.Malware.Beebone-10015477-0|

---

## 3. Capabilities

This script demonstrates invasive and intentional behaviors designed to deeply modify the system, disable security mechanisms, and take control over the user experience.

### 3.1 Browser Hijacking
- **Target:** Internet Explorer  
**Actions:**
- Changes Start and Default pages to `http://www.cbala.com/`
- Deletes existing search providers
- Locks search engine to `http://www.456020.com/`

### 3.2 Defense Evasion & Security Disabling
- **Firewall:** Disables for all profiles  
- **Windows Services Disabled:**
  - RemoteRegistry
  - WerSvc
  - WdiSystemHost
  - DPS
- **Security Alerts:** Suppressed via registry  
- **Self-deleting script:** `.cmd` removes itself after execution

### 3.3 Unwanted Software Installation (PUP/Adware)
- Executes: `1.exe`, `2_x64.exe`, `360.exe`  
- Creates desktop shortcut: `装机助理.exe`  
- Hides files in: `C:\Program Files\Tencent\QDesk`

### 3.4 System Tampering
- Deletes files from startup
- Registry edits:
  - Lowers UAC
  - Disables UI effects
  - Alters Notepad behavior
- Adds `OneDrive.exe` to `HKCU\...\Explorer\Run` (likely fake)

---

## 4. Dependencies

### 4.1 System Privileges
- Requires Administrator rights  
- Evident from `#RequireAdmin` in AutoIt script

### 4.2 Execution Environment
- OS: Windows 64-bit  
- Uses tools like `cmd.exe`, `takeown.exe`, `regedit.exe`

### 4.3 Bundled Components
- **Dropper:** `script.txt`  
- **Dependent files:** `yh_8.cmd`, `yh_8.REG`, `1.exe`, `2_x64.exe`, `装机助理.exe`  
- **Note:** Missing files may break infection chain

---

## 5. Static Analysis

### 5.1 Top-Level Components
- Main calls from `KERNEL32.dll`
- Suspicious API use (common in phishing malware)

### 5.2 Entry Point
- `00007FF76E15C9D4`

### 5.3 Embedded Strings

**File Paths & Registry Keys:**
- `C:\Windows\System32`
- `%TEMP%`
- `Software\Microsoft\Windows\CurrentVersion\Run`

**API Functions:**
- `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`  
- `CreateFileA`, `WriteFile`, `ReadFile`, `WinExec`

**CLI Tools:**
- `cmd.exe`, `powershell`, `reg add`, `schtasks /create`

### 5.4 Code-Related Observations
- (Reflection, Obfuscation, Encryption, Native code, etc)

### 5.5 File Contents
- **5.5.1 Package contents**
- **5.5.2 Files created/deployed on the system**

---

## 6. Supporting Data

### 6.1 Log Files
### 6.2 Network Traces
### 6.3 Screenshots
### 6.4 Other Data
- (Database dumps, config files, etc.)

---

## 7. Conclusion

The analyzed malware sample poses a significant threat due to its multi-faceted intrusion strategy, which combines system tampering, defense evasion, persistence mechanisms, and user experience manipulation. It disables core Windows security features, modifies registry settings, and executes additional payloads—some of which remain unidentified due to missing components.

Given the administrative privileges required and the aggressive tactics employed (such as self-deleting scripts, hijacking system behaviors, and silently deploying secondary executables), the malware likely targets end users with limited security awareness or systems with insufficient hardening.

Mitigation strategies should include endpoint detection and response (EDR) solutions capable of behavior-based detection, network monitoring for suspicious traffic (especially related to `cbala.com` and `456020.com`), and forensic imaging of affected systems. Immediate quarantine and offline analysis are recommended for any systems suspected to be compromised.

