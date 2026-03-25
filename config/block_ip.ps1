# Blokuje podane IP w Windows Firewall
# Uzycie: .\block_ip.ps1 -IP "1.2.3.4" -Reason "Port scan"

param(
    [Parameter(Mandatory=$true)]
    [string]$IP,
    [string]$Reason = "Blocked by SecuritySuite"
)

$ruleName = "SecuritySuite_Block_$($IP.Replace('.','_').Replace(':','_'))"

# Sprawdz czy regula juz istnieje
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[INFO] IP $IP juz zablokowane" -ForegroundColor Yellow
    exit 0
}

# Dodaj regule
New-NetFirewallRule `
    -DisplayName $ruleName `
    -Description "AutoBan: $Reason | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" `
    -Direction Inbound `
    -Action Block `
    -RemoteAddress $IP `
    -Profile Any `
    -Enabled True

if ($?) {
    Write-Host "[BANNED] $IP zablokowane | Powod: $Reason" -ForegroundColor Red
} else {
    Write-Host "[BLAD] Nie udalo sie zablokowac $IP" -ForegroundColor Red
    exit 1
}
