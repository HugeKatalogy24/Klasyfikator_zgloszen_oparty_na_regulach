@echo off
chcp 65001 >nul
title Analizator Problemów Jira - DEVELOPMENT MODE (Bez SSL)

echo.
echo ========================================
echo  🚀 URUCHAMIANIE APLIKACJI - DEVELOPMENT
echo     🔧 Bez SSL, nginx, waitress
echo     📍 Tylko localhost:5000
echo ========================================
echo.

REM Przejdź do katalogu aplikacji
cd /d "%~dp0"

REM Sprawdź czy Python jest dostępny
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ BŁĄD: Python nie jest zainstalowany lub niedostępny w PATH
    echo.
    echo    💡 Zainstaluj Python 3.8+ i dodaj do PATH
    pause
    exit /b 1
)

REM Sprawdź czy plik .env istnieje
if not exist ".env" (
    echo ❌ BŁĄD: Plik .env nie istnieje
    echo.
    echo    💡 Skopiuj szablon konfiguracji do .env
    pause
    exit /b 1
)

REM Sprawdź czy FLASK_ENV jest ustawiony na development
findstr /i "FLASK_ENV=development" .env >nul
if errorlevel 1 (
    echo ⚠️  UWAGA: FLASK_ENV nie jest ustawiony na 'development' w .env
    echo.
    echo    💡 Ustaw FLASK_ENV=development w pliku .env
    echo.
)

echo 🔍 Sprawdzanie zależności...

REM Sprawdź czy requirements.txt istnieje
if not exist "requirements.txt" (
    echo ❌ BŁĄD: Plik requirements.txt nie istnieje
    pause
    exit /b 1
)

REM Instaluj zależności
echo 📦 Instalowanie/aktualizowanie zależności...
pip install -r requirements.txt
if errorlevel 1 (
    echo ❌ BŁĄD: Nie udało się zainstalować zależności
    pause
    exit /b 1
)

echo.
echo ✅ Wszystko gotowe!
echo.
echo 🌐 Aplikacja zostanie uruchomiona na: http://localhost:5001
echo 👤 Panel admina: http://localhost:5001/admin/login
echo 🔓 Tryb: Development (bez SSL)
echo.
echo ⏸️  Naciśnij Ctrl+C aby zatrzymać aplikację
echo.

REM Uruchom aplikację
python app.py

echo.
echo 📋 Aplikacja została zatrzymana
pause
