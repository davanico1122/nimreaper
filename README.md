NIMREAPER - Destructive Ransomware

**WARNING:** This malware is designed to cause **permanent damage** to target systems. Use **only** in a controlled environment with **explicit permission**.

---

## Destructive Features

### Boot Sector Destruction

* Uses `diskpart` to wipe the MBR.
* Renders system unbootable.

### System File Corruption

* Damages random files in **System32** and **.NET Framework**.
* Overwrites file contents with random data.

### Recovery Elimination

* Deletes Volume Shadow Copies.
* Disables Windows Recovery Environment.
* Clears event logs.

### Process Termination

* Kills security and backup processes.
* Targets antivirus, backup tools, and security agents.

### Registry Encryption

* Exports and deletes critical registry keys.
* Disables system restore points.

### Network Propagation

* Spreads via SMB network shares.
* Executes payload on remote systems.

---

## Anti-Analysis Techniques

### VM/Sandbox Detection

* Checks uptime < 5 minutes.
* Detects hypervisor via registry.
* Scans for VM-specific processes.

### Debugger Detection

* Uses `CheckRemoteDebuggerPresent` API.
* Employs timing checks.

### Anti-Forensics

* Deletes event logs.
* Overwrites original executables.
* Delays execution in VM environments.

### BSOD Trigger

* Triggers Blue Screen of Death if debugger detected.
* Uses `NtRaiseHardError`.

---

## Data Encryption

* **Algorithm:** AES-256-GCM
* **Key Management:** Unique key per file.
* **Target Extensions:** 30+ types (documents, source code, databases).

**Example:**

```nim
nim
ctx.init(key, iv)
ctx.encrypt(plaintext, ciphertext)
ctx.getTag(tag)
```

---

## Persistence Mechanisms

### Registry Run Keys

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* Alias name: "WindowsUpdate"

### Startup Folders

* User Startup Folder
* All Users Startup Folder
* System32 Tasks

### Network Propagation

* Spreads via shared networks.
* Executes remotely via WMIC.

---

## Research Guidelines

### Compilation

```bash
nim c -d:release --opt:size --cpu=amd64 --passL:-static -d:strip --out:nimreaper.exe nimreaper.nim
```

### Safe Environment

* Use dedicated physical machines.
* Isolate from all physical networks.
* Hardware with no critical storage.
* Backup BIOS/UEFI.

### VM Quarantine

```bash
# Isolation script example
vboxmanage modifyvm "ResearchVM" --nictrace1 on --nictracefile1 trace.pcap
vboxmanage modifyvm "ResearchVM" --vrde off
```

### Indicators of Compromise

* Files with `.NIMREAPER` extension.
* Suspicious `svchost.exe` processes.
* Registry entry "WindowsUpdate".
* BSOD error code `0xC0000350`.

---

## Research Ethics

### Legal Consent

* Only use on your own systems.
* Maintain written consent documentation.

### Physical Isolation

* Use dedicated, offline systems.
* Disable network features in BIOS.

### Fail-Safe

* Implement `SAFE_MODE` flag for VM environments.
* No actual C2 connections.
* Dummy BTC address.

---

## Research Impact

### Security Testing

* Validate memory forensic detection techniques.
* Test EDR solution effectiveness.
* Analyze behavioral detection.

### Defense Development

```python
class BootSectorGuard:
    def monitor_mbr(self):
        if detect_unsigned_mbr_change():
            trigger_system_lockdown()
```

### Incident Response

* Framework for infected system recovery.
* Emergency decryption tools.
* Forensics guide for critical infrastructure.

---

**FINAL NOTE:** This code is for **security research only**. Misuse for illegal activity is strictly prohibited. Damage caused is **permanent** and can result in **total data loss**.
