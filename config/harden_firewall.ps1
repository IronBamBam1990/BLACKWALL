# ============================================================
# FIREWALL HARDENING - Zabezpieczenie na poziomie wojskowym
# Uruchomic jako Administrator!
# ============================================================

Write-Host "============================================" -ForegroundColor Red
Write-Host "  SECURITY SUITE - FIREWALL HARDENING" -ForegroundColor Red
Write-Host "  Wymaga uprawnien Administratora!" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Red
Write-Host ""

# Sprawdz uprawnienia
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[BLAD] Uruchom jako Administrator!" -ForegroundColor Red
    exit 1
}

# --- 1. WLACZ FIREWALL DLA WSZYSTKICH PROFILI ---
Write-Host "[1/12] Wlaczam Firewall dla wszystkich profili..." -ForegroundColor Cyan
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 32767
Write-Host "  [OK] Firewall aktywny - domyslnie blokuje przychodzace" -ForegroundColor Green

# --- 2. BLOKUJ ICMP (PING) ---
Write-Host "[2/12] Blokuje ICMP (ping)..." -ForegroundColor Cyan
# Blokuj ICMPv4
New-NetFirewallRule -DisplayName "Block ICMPv4 In" -Direction Inbound -Protocol ICMPv4 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
# Blokuj ICMPv6
New-NetFirewallRule -DisplayName "Block ICMPv6 In" -Direction Inbound -Protocol ICMPv6 -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] Ping zablokowany - komputer niewidoczny w sieci" -ForegroundColor Green

# --- 3. BLOKUJ NetBIOS ---
Write-Host "[3/12] Blokuje NetBIOS..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block NetBIOS-NS In" -Direction Inbound -Protocol UDP -LocalPort 137 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block NetBIOS-DS In" -Direction Inbound -Protocol UDP -LocalPort 138 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block NetBIOS-SS In" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block NetBIOS Out" -Direction Outbound -Protocol UDP -RemotePort 137,138 -Action Block -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] NetBIOS zablokowany" -ForegroundColor Green

# --- 4. BLOKUJ LLMNR (Link-Local Multicast Name Resolution) ---
Write-Host "[4/12] Blokuje LLMNR..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block LLMNR In" -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block LLMNR Out" -Direction Outbound -Protocol UDP -RemotePort 5355 -Action Block -ErrorAction SilentlyContinue | Out-Null
# Wylacz LLMNR przez rejestr
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Write-Host "  [OK] LLMNR wylaczony" -ForegroundColor Green

# --- 5. BLOKUJ mDNS ---
Write-Host "[5/12] Blokuje mDNS..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block mDNS In" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block mDNS Out" -Direction Outbound -Protocol UDP -RemotePort 5353 -Action Block -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] mDNS zablokowany" -ForegroundColor Green

# --- 6. BLOKUJ UPnP (SSDP) ---
Write-Host "[6/12] Blokuje UPnP/SSDP..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block SSDP In" -Direction Inbound -Protocol UDP -LocalPort 1900 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block SSDP Out" -Direction Outbound -Protocol UDP -RemotePort 1900 -Action Block -ErrorAction SilentlyContinue | Out-Null
# Wylacz usluge SSDP
Stop-Service SSDPSRV -Force -ErrorAction SilentlyContinue
Set-Service SSDPSRV -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] UPnP/SSDP wylaczony" -ForegroundColor Green

# --- 7. BLOKUJ SMB (udzial sieciowy) ---
Write-Host "[7/12] Blokuje SMB..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block SMB In" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block SMB Out" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block -ErrorAction SilentlyContinue | Out-Null
# Wylacz SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
Write-Host "  [OK] SMB zablokowany" -ForegroundColor Green

# --- 8. BLOKUJ Remote Desktop z zewnatrz ---
Write-Host "[8/12] Zabezpieczam RDP..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block RDP Public" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Public -ErrorAction SilentlyContinue | Out-Null
# Wymusz NLA (Network Level Authentication) dla RDP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue
Write-Host "  [OK] RDP zabezpieczony - NLA wymagane" -ForegroundColor Green

# --- 9. BLOKUJ WinRM (Remote Management) ---
Write-Host "[9/12] Blokuje WinRM..." -ForegroundColor Cyan
New-NetFirewallRule -DisplayName "Block WinRM In" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Block -ErrorAction SilentlyContinue | Out-Null
Stop-Service WinRM -Force -ErrorAction SilentlyContinue
Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] WinRM wylaczony" -ForegroundColor Green

# --- 10. WLACZ LOGGING FIREWALLA ---
Write-Host "[10/12] Wlaczam szczegolowe logowanie..." -ForegroundColor Cyan
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Domain -LogFileName $logPath -LogBlocked True -LogAllowed True
Set-NetFirewallProfile -Profile Private -LogFileName $logPath -LogBlocked True -LogAllowed True
Set-NetFirewallProfile -Profile Public -LogFileName $logPath -LogBlocked True -LogAllowed True
Write-Host "  [OK] Logging wlaczony: $logPath" -ForegroundColor Green

# --- 11. WYLACZ IPv6 (jesli nie potrzebny) ---
Write-Host "[11/12] Wylaczam IPv6 na adapterach..." -ForegroundColor Cyan
Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | ForEach-Object {
    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
}
Write-Host "  [OK] IPv6 wylaczony" -ForegroundColor Green

# --- 12. DODATKOWE ZABEZPIECZENIA REJESTRU ---
Write-Host "[12/12] Dodatkowe zabezpieczenia..." -ForegroundColor Cyan

# Wylacz Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -ErrorAction SilentlyContinue

# Wylacz Remote Registry
Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue
Set-Service RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue

# Wylacz autorun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue

# Wlacz DEP (Data Execution Prevention) dla wszystkich procesow
bcdedit /set nx AlwaysOn 2>$null | Out-Null

Write-Host "  [OK] Dodatkowe zabezpieczenia zastosowane" -ForegroundColor Green

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  FIREWALL HARDENING ZAKONCZONE!" -ForegroundColor Green
Write-Host "  Komputer jest teraz zabezpieczony." -ForegroundColor Green
Write-Host "  Wymagany restart dla pelnego efektu." -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Green
