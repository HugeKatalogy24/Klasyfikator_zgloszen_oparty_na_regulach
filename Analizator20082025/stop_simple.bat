@echo off
chcp 65001 >nul
title Zatrzymywanie Aplikacji

echo.
echo =====================================
echo  🛑 ZATRZYMYWANIE APLIKACJI
echo =====================================
echo.

REM Zatrzymaj Nginx
echo 🛡️ Zatrzymywanie Nginx...
taskkill /F /IM nginx.exe >nul 2>&1
if errorlevel 1 (
    echo    ⚠️  Nginx nie był uruchomiony
) else (
    echo    ✅ Nginx zatrzymany
)

REM Zatrzymaj Waitress/Python
echo ⚡ Zatrzymywanie Waitress...
taskkill /F /FI "WINDOWTITLE eq Waitress-Backend" >nul 2>&1
if errorlevel 1 (
    echo    ⚠️  Waitress nie był uruchomiony
) else (
    echo    ✅ Waitress zatrzymany
)

REM Dodatkowe czyszczenie procesów Python związanych z aplikacją
wmic process where "commandline like '%%wsgi_production.py%%'" delete >nul 2>&1

echo.
echo ✅ Aplikacja zatrzymana
echo.
pause
