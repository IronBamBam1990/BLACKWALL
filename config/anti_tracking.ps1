# ============================================================
# ANTI-TRACKING & ANTI-IP-LEAK HARDENING
# Uruchomic jako Administrator!
# ============================================================

Write-Host "============================================" -ForegroundColor Magenta
Write-Host "  ANTI-TRACKING & PRIVACY HARDENING" -ForegroundColor Magenta
Write-Host "============================================" -ForegroundColor Magenta
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[BLAD] Uruchom jako Administrator!" -ForegroundColor Red
    exit 1
}

# --- 1. DNS over HTTPS (DoH) ---
Write-Host "[1/8] Konfiguruje DNS over HTTPS..." -ForegroundColor Cyan

# Cloudflare DoH (privacy-focused)
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $adapters) {
    # Ustaw DNS na Cloudflare (1.1.1.1) i Google (8.8.8.8) jako backup
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4" -ErrorAction SilentlyContinue

    # Wlacz DoH
    try {
        Set-DnsClientDohServerAddress -ServerAddress "1.1.1.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress "1.0.0.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
        Set-DnsClientDohServerAddress -ServerAddress "8.8.8.8" -DohTemplate "https://dns.google/dns-query" -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [WARN] DoH nie w pelni skonfigurowane - wymaga Windows 11" -ForegroundColor Yellow
    }
}
Write-Host "  [OK] DNS over HTTPS skonfigurowane" -ForegroundColor Green

# --- 2. WYLACZ WPAD (Web Proxy Auto-Discovery) ---
Write-Host "[2/8] Wylaczam WPAD..." -ForegroundColor Cyan
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 0 -ErrorAction SilentlyContinue
# Wylacz usluge WinHTTP Web Proxy Auto-Discovery
Stop-Service WinHttpAutoProxySvc -Force -ErrorAction SilentlyContinue
Set-Service WinHttpAutoProxySvc -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] WPAD wylaczony" -ForegroundColor Green

# --- 3. WYLACZ TELEMETRIE Windows ---
Write-Host "[3/8] Wylaczam telemetrie Windows..." -ForegroundColor Cyan
# Minimalna telemetria
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
# Wylacz Connected User Experience
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service dmwappushservice -Force -ErrorAction SilentlyContinue
Set-Service dmwappushservice -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "  [OK] Telemetria wylaczona" -ForegroundColor Green

# --- 4. WYLACZ WIFI SENSE ---
Write-Host "[4/8] Wylaczam WiFi Sense..." -ForegroundColor Cyan
New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -ErrorAction SilentlyContinue
Write-Host "  [OK] WiFi Sense wylaczony" -ForegroundColor Green

# --- 5. WYLACZ NETWORK LOCATION AWARENESS nadmiar ---
Write-Host "[5/8] Zabezpieczam Network Discovery..." -ForegroundColor Cyan
# Wylacz Network Discovery
netsh advfirewall firewall set rule group="Network Discovery" new enable=No 2>$null | Out-Null
# Wylacz File and Printer Sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No 2>$null | Out-Null
Write-Host "  [OK] Network Discovery wylaczony" -ForegroundColor Green

# --- 6. WYLACZ LOCATION TRACKING ---
Write-Host "[6/8] Wylaczam sledzenie lokalizacji..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Location tracking wylaczony" -ForegroundColor Green

# --- 7. WYLACZ ADVERTISING ID ---
Write-Host "[7/8] Wylaczam Advertising ID..." -ForegroundColor Cyan
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -ErrorAction SilentlyContinue
Write-Host "  [OK] Advertising ID wylaczony" -ForegroundColor Green

# --- 8. FLUSH DNS CACHE ---
Write-Host "[8/8] Czyszcze DNS cache..." -ForegroundColor Cyan
Clear-DnsClientCache
ipconfig /flushdns 2>$null | Out-Null
Write-Host "  [OK] DNS cache wyczyszczony" -ForegroundColor Green

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  ANTI-TRACKING HARDENING ZAKONCZONE!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
