@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0yonetici_olarak_baslat.ps1"
if errorlevel 1 (
  echo Baslatma basarisiz. Python 3.11+ ve py baslaticisi gerekli.
  exit /b 1
)
