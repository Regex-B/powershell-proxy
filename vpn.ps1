# Yönetici olarak çalışıp çalışmadığımızı kontrol et
function Test-Admin {
    try {
        $admin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        $admin.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch {
        $false
    }
}

# Yönetici yetkileriyle çalışmıyorsak, betiği yönetici olarak yeniden başlat
if (-not (Test-Admin)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -ArgumentList $arguments -Verb RunAs
    exit
}

# Konsol çıktısına renk eklemek için fonksiyonlar
function Write-Green {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Green
}

function Write-Red {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Red
}

function Write-Cyan {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Blue {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Blue
}
function Write-Yellow {
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Yellow
}
function Write-White{
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor White
}
function Write-Darkred{
    param (
        [string]$Message
    )
    Write-Host $Message -ForegroundColor Darkred
}
# Program başlığı ve arka plan rengini ayarlama
$host.ui.RawUI.BackgroundColor = "Black"
$host.ui.RawUI.ForegroundColor = "Green"
Clear-Host

Write-Cyan "=================================================================================================================================="
Write-Blue "                                                   Bozkurt Powerhell PROXY Aracı                                                  "
Write-Cyan "=================================================================================================================================="
Write-Red "==================================================================================================================================="
Write-Red "                                                       KULLANILABİLİR KOMUTLAR                                                     "
Write-Cyan "=================================================================================================================================="
Write-Red "                                                  ac : Proxy'yi aktif hale getirir.                                                "
Write-Red "                                                  kapa : Proxy'yi devre dışı bırakır.                                              "
Write-Red "                                                  degistir : Mevcut IP adresini değiştirir ve yeni bir proxy seçer.                "
Write-Red "                                                  say : Listedeki proxy sayısını gösterir.                                         "
Write-Red "                                                  exit : Proxy ile olan bağlantıyı keser ve betiği kapatır.                        "
Write-Cyan "=================================================================================================================================="
Write-Cyan "=================================================================================================================================="
Write-Darkred "                                                         Y A S A L U Y A R I !                                                 "
Write-White "                                  Betiği Lamerlik yapmak için kullanmayın. Kendinizi Hacker zannetmeyin.                         "
Write-Cyan "=================================================================================================================================="
Write-Cyan "=================================================================================================================================="

# Proxy IP'lerinin bulunduğu txt dosyasının yolu
$proxyFilePath = "C:\Users\bozku\Desktop\vpnb\proxy.txt"

# Test edilecek hedef web sitesi (bu, proxy'nin çalışıp çalışmadığını test eder)
$testUrl = "http://www.google.com"

# Son çalışan proxy'yi saklayan değişken
$lastWorkingProxy = $null

# Proxy'yi test eden fonksiyon
function Test-Proxy {
    param (
        [string]$proxy
    )

    try {
        # Proxy'yi parse et
        $proxyType, $proxyAddress = if ($proxy -match "^(http|socks4|socks5)://(.+)$") {
            $matches[1], $matches[2]
        } else {
            "http", $proxy
        }

        # WebClient oluştur
        $webClient = New-Object System.Net.WebClient
        
        # Proxy ayarlarını yapılandır
        $proxyUrl = if ($proxyType -eq "http") { "http://$proxyAddress" } else { $proxyAddress }
        $webClient.Proxy = New-Object System.Net.WebProxy($proxyUrl, $true)
        $webClient.DownloadString($testUrl) | Out-Null

        Write-Darkred "Proxy çalışıyor: $proxy"
        return $true
    } catch {
        Write-Red "Proxy başarısız: $proxy"
        Write-Red "Hata ayrıntıları: $_"
        return $false
    }
}

# Proxy ayarlarını yapılandıran fonksiyon
function Set-Proxy {
    param (
        [string]$proxyAddress
    )

    try {
        # Proxy ayarlarını yapılandır
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value $proxyAddress

        Write-green "Proxy ayarlandı: $proxyAddress"
    } catch {
        Write-Red "Proxy ayarlarında hata: $_"
    }
}

# Proxy ayarlarını kapatan fonksiyon
function Disable-Proxy {
    try {
        # Proxy'yi devre dışı bırak
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
        Write-Green "Proxy devre dışı bırakıldı."
    } catch {
        Write-Red "Proxy kapatmada hata: $_"
    }
}

# Proxy listesini güncelleyen fonksiyon
function Update-ProxyList {
    param (
        [string]$proxyToRemove
    )

    try {
        # TXT dosyasından proxy IP'lerini okuma
        if (Test-Path $proxyFilePath) {
            $proxyList = Get-Content -Path $proxyFilePath
        } else {
            Write-Red "Proxy dosyası bulunamadı: $proxyFilePath"
            exit
        }

        # Çalışmayan proxy'yi liste dosyasından çıkar
        $updatedProxyList = $proxyList | Where-Object { $_ -ne $proxyToRemove }
        $updatedProxyList | Set-Content -Path $proxyFilePath

        Write-Green "Proxy listesi güncellendi: $proxyToRemove çalışmadığı için listeden kaldırıldı."
    } catch {
        Write-Red "Proxy listesi güncellenirken hata: $_"
    }
}

# Mevcut proxy'yi değiştiren fonksiyon (rastgele proxy seçer ve çalışmayanları listeden siler)
function Change-Proxy {
    try {
        # TXT dosyasından proxy IP'lerini okuma
        if (Test-Path $proxyFilePath) {
            $proxyList = Get-Content -Path $proxyFilePath
        } else {
            Write-Red "Proxy dosyası bulunamadı: $proxyFilePath"
            exit
        }

        # Mevcut proxy'yi devre dışı bırak
        if ($lastWorkingProxy) {
            Write-Yellow "Mevcut proxy'nin listeden çıkarılması..."
            Disable-Proxy
            Update-ProxyList -proxyToRemove $lastWorkingProxy
            $lastWorkingProxy = $null
        }

        # Proxy listesini rastgele sıraya göre yeniden düzenleyen kısım.
        $randomizedProxyList = $proxyList | Get-Random -Count $proxyList.Count

        # Yeni bir çalışan proxy bulana kadar deneme
        $proxyChanged = $false
        foreach ($proxy in $randomizedProxyList) {
            if (Test-Proxy -proxy $proxy) {
                # Çalışan proxy'yi bulduktan sonra ayarla ve döngüden çık
                Set-Proxy -proxyAddress $proxy
                $global:lastWorkingProxy = $proxy
                $proxyChanged = $true
                break
            } else {
                # Çalışmayan proxy'yi listeden sil
                Update-ProxyList -proxyToRemove $proxy
                Get-ProxyCount -filePath $proxyFilePath
            }
        }

        if (-not $proxyChanged) {
            Write-Red "Çalışan bir proxy bulunamadı."
        }
    } catch {
        Write-Red "Proxy değiştirme sırasında hata: $_"
    }
}

# Proxy listesindeki toplam proxy sayısını döndüren fonksiyon
function Get-ProxyCount {
    param (
        [string]$filePath
    )

    try {
        if (Test-Path $filePath) {
            $proxyList = Get-Content -Path $filePath
            $proxyCount = $proxyList.Count
            Write-Cyan "Listedeki proxy sayısı: $proxyCount"
        } else {
            Write-Red "Proxy dosyası bulunamadı: $filePath"
        }
    } catch {
        Write-Red "Bir hata oluştu: $_"
    }
}

# Sürekli çalışma döngüsü
while ($true) {
    # Aç/Kapa/Değiştir işlemi için kullanıcıdan komut alan kısım.
    $action = Read-Host "Listedeki Komutlardan Birini Girin."

    try {
        if ($action -eq "ac") {
            # Proxy'yi etkinleştirme
            Get-ProxyCount -filePath $proxyFilePath
            Change-Proxy
        } elseif ($action -eq "kapa") {
            # Proxy ayarlarını kapatma
            Disable-Proxy
        } elseif ($action -eq "degistir") {
            # Mevcut proxy'yi değiştirme
            Disable-Proxy
            Change-Proxy
        } elseif ($action -eq "say") {
            # Listedeki proxy sayısını öğrenme
            Get-ProxyCount -filePath $proxyFilePath
        } elseif ($action -eq "exit") {
            # Çıkış komutu: Proxy'yi kapat ve programdan çık
            Disable-Proxy
            Write-Green "Programdan çıkılıyor..."
            break
        } else {
            Write-Red "Geçersiz komut. Listede kullanılabilir komutlar yazıyor.."
        }
    } catch {
        Write-Red "Bir hata oluştu: $_"
    }
}
