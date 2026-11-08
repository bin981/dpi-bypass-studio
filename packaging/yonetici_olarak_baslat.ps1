# Yönetici olarak başlatır. Ağ ayarını bu betik değiştirmez; uygulama ancak
# penceredeki Başlat düğmesinden sonra değiştirir.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    Write-Error "py başlatıcısı yok. Python 3.11 veya daha yenisini kurun."
}
Start-Process -FilePath "py.exe" -ArgumentList @("-3.11", "main.py") -WorkingDirectory $root -Verb RunAs
