@echo off
title RwScanner
cd /d "%~dp0client"

set "NODE=%APPDATA%\fnm\node-versions\v24.19.0\installation\node.exe"

if not exist "%NODE%" (
    echo [HATA] Node.js bulunamadi.
    pause
    exit /b 1
)

"%NODE%" src/app.js
pause
