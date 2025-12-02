@echo off
chcp 65001 >nul
title Analizator Problemów Jira - Start Produkcyjny (Enhanced Retry Logic)

echo.
echo ========================================
echo  🚀 URUCHAMIANIE APLIKACJI PRODUKCYJNEJ
echo     🔄 Z MECHANIZMEM RETRY (3 PRÓBY)
echo ========================================
echo.

REM Przejdź do katalogu aplikacji
cd /d "C:\AnalizatorProblemowJira\Analizator"

REM Sprawdź uprawnienia administratora
net session >nul 2>&1
if errorlevel 1 (
    echo ❌ BŁĄD: Wymagane uprawnienia administratora dla portu 443
    echo.
    echo    👆 Uruchom PowerShell jako Administrator i wykonaj:
    echo    📂 cd "C:\AnalizatorProblemowJira\Analizator"
    echo    🚀 .\start_simple.bat
    echo.
    pause
    exit /b 1
)

echo ✅ Uprawnienia administratora OK
echo.

REM Aktywuj środowisko Python
echo 🐍 Aktywacja środowiska Python...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ BŁĄD: Nie można aktywować środowiska Python
    pause
    exit /b 1
)
echo ✅ Środowisko Python aktywne

REM Uruchom Waitress (Backend) z retry logic
echo.
echo ⚡ Uruchamianie Waitress Backend (Port 8001)...

set WAITRESS_ATTEMPTS=0
set MAX_WAITRESS_ATTEMPTS=3

:waitress_retry
set /a WAITRESS_ATTEMPTS+=1
echo 📡 Próba uruchomienia Waitress %WAITRESS_ATTEMPTS%/%MAX_WAITRESS_ATTEMPTS%...

REM Zatrzymaj istniejące procesy Waitress jeśli istnieją
taskkill /F /FI "WINDOWTITLE eq Waitress-Backend" >nul 2>&1
wmic process where "commandline like '%%wsgi_production.py%%'" delete >nul 2>&1

REM Poczekaj chwilę na zwolnienie portu
timeout /t 2 >nul

start /min "Waitress-Backend" python wsgi_production.py

REM Poczekaj na uruchomienie Waitress
echo 🔄 Oczekiwanie na uruchomienie Waitress (10 sekund)...
timeout /t 10 >nul

REM Sprawdź czy Waitress działa
netstat -an | findstr ":8001" >nul 2>&1
if errorlevel 1 (
    echo ❌ Próba %WAITRESS_ATTEMPTS%: Waitress nie uruchomił się na porcie 8001
    if %WAITRESS_ATTEMPTS% LSS %MAX_WAITRESS_ATTEMPTS% (
        echo 🔄 Ponawiam próbę za 5 sekund...
        timeout /t 5 >nul
        goto waitress_retry
    ) else (
        echo ❌ BŁĄD KRYTYCZNY: Waitress nie uruchomił się po %MAX_WAITRESS_ATTEMPTS% próbach
        echo    📋 Sprawdź logs\wsgi.log
        echo    🔧 Możliwe przyczyny:
        echo       - Port 8001 jest zajęty przez inny proces
        echo       - Błąd w pliku wsgi_production.py
        echo       - Problemy z środowiskiem Python
        pause
        exit /b 1
    )
)
echo ✅ Waitress Backend uruchomiony pomyślnie (Port 8001)

REM Uruchom Nginx (Frontend SSL) z retry logic
echo.
echo 🛡️ Uruchamianie Nginx SSL Proxy (Port 443)...

set NGINX_ATTEMPTS=0
set MAX_NGINX_ATTEMPTS=3

:nginx_retry
set /a NGINX_ATTEMPTS+=1
echo 🔒 Próba uruchomienia Nginx %NGINX_ATTEMPTS%/%MAX_NGINX_ATTEMPTS%...

REM Zatrzymaj istniejące procesy Nginx jeśli istnieją
taskkill /F /IM nginx.exe >nul 2>&1

REM Poczekaj chwilę na zwolnienie portu
timeout /t 2 >nul

cd nginx
start /min "Nginx-SSL" nginx.exe -p "C:\AnalizatorProblemowJira\Analizator\nginx" -c conf\nginx_production.conf
cd ..

REM Poczekaj na uruchomienie Nginx
echo 🔄 Oczekiwanie na uruchomienie Nginx (8 sekund)...
timeout /t 8 >nul

REM Sprawdź czy Nginx działa
netstat -an | findstr ":443" >nul 2>&1
if errorlevel 1 (
    echo ❌ Próba %NGINX_ATTEMPTS%: Nginx nie uruchomił się na porcie 443
    if %NGINX_ATTEMPTS% LSS %MAX_NGINX_ATTEMPTS% (
        echo 🔄 Ponawiam próbę za 5 sekund...
        timeout /t 5 >nul
        goto nginx_retry
    ) else (
        echo ❌ BŁĄD KRYTYCZNY: Nginx nie uruchomił się po %MAX_NGINX_ATTEMPTS% próbach
        echo    📋 Sprawdź nginx\logs\error.log
        echo    🔧 Możliwe przyczyny:
        echo       - Port 443 jest zajęty przez inny proces (IIS, Apache)
        echo       - Błędna konfiguracja nginx_production.conf
        echo       - Problemy z certyfikatami SSL
        echo       - Brak uprawnień administratora
        echo.
        echo 🛑 Zatrzymuję Waitress z powodu błędu Nginx...
        taskkill /F /FI "WINDOWTITLE eq Waitress-Backend" >nul 2>&1
        wmic process where "commandline like '%%wsgi_production.py%%'" delete >nul 2>&1
        pause
        exit /b 1
    )
)
echo ✅ Nginx SSL Proxy uruchomiony pomyślnie (Port 443)

echo.
echo ================================================================================
echo  ✅ APLIKACJA URUCHOMIONA POMYŚLNIE!
echo ================================================================================
echo.
echo 🚀 Podsumowanie uruchomienia:
echo    ✅ Waitress Backend: DZIAŁA (Port 8001) - Próba %WAITRESS_ATTEMPTS%/%MAX_WAITRESS_ATTEMPTS%
echo    ✅ Nginx SSL Proxy: DZIAŁA (Port 443) - Próba %NGINX_ATTEMPTS%/%MAX_NGINX_ATTEMPTS%
echo.
echo 🌐 Strona dostępna pod adresem:
echo    https://analizator.pl.mcd.com
echo.
echo 🔧 Monitoring:
echo    Backend:  http://127.0.0.1:8001
echo    Frontend: https://analizator.pl.mcd.com
echo.
echo 📋 Logi:
echo    Waitress: logs\wsgi.log
echo    Nginx:    nginx\logs\error.log
echo.
echo 🛑 Aby zatrzymać aplikację, uruchom: stop_simple.bat
echo.
echo 📝 UWAGA dla Task Scheduler:
echo    ✅ Skrypt zawiera mechanizm retry (3 próby dla każdej usługi)
echo    ✅ Automatyczne czyszczenie konfliktujących procesów
echo    ✅ Szczegółowe logowanie błędów w przypadku problemów
echo.
pause
