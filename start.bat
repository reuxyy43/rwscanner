@echo off
title RwScanner Server
echo ====================================
echo    RwScanner - Sunucu Baslatiliyor
echo ====================================
echo.

cd /d "%~dp0server"

set "NODE=%APPDATA%\fnm\node-versions\v24.19.0\installation\node.exe"

if not exist "%NODE%" (
    echo [HATA] Node.js bulunamadi.
    pause
    exit /b 1
)

echo [1/2] Veritabani hazirlaniyor...
"%NODE%" src/database/seed.js

echo.
echo [2/2] Sunucu baslatiliyor...
echo.
echo    Ana Sayfa:     http://localhost:3000/landing
echo    Yetkili Panel: http://localhost:3000/panel
echo    Giris:         admin / admin123
echo.
echo    Durdurmak icin Ctrl+C
echo.

"%NODE%" src/index.js
pause
