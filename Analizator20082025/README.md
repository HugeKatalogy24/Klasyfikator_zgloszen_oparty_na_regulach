# Analizator Problemów Jira

**🏢 Profesjonalna aplikacja webowa do analizy i klasyfikacji zgłoszeń McDonald's z systemu Jira**

Zaawansowany system wykorzystujący **Flask + SSL**, **inteligentną klasyfikację regułową**, **real-time progress tracking** i **export z hyperlinkami Excel**. Aplikacja zapewnia **enterprise-grade security** z modułową architekturą dla środowisk korporacyjnych.

## 🚀 Najnowsze aktualizacje

**✅ Wersja 3.2 - Sierpień 2025 - REAL-TIME PROGRESS & EXCEL HYPERLINKS:**
- **📊 Real-time progress tracking:** Dynamiczny pasek postępu z rzeczywistymi danymi z JIRA
- **⚡ AJAX-based interface:** Analiza bez przeładowania strony z live updates
- **🔗 Inteligentne hyperlinki Excel:** Automatyczne wykrywanie wersji językowej (HYPERLINK/HIPERŁĄCZE)
- **🌍 Multi-language Excel support:** Konfigurowalny język funkcji Excel (auto/pl/en) via EXCEL_LANGUAGE
- **⏱️ Precyzyjne estymacje:** Realistyczne czasy ładowania bazowane na rzeczywistej wydajności API
- **🎨 Enhanced UX:** Dopasowany design paska postępu do ciemnego motywu aplikacji
- **🔄 Background processing:** Wielowątkowa analiza z raportowaniem postępu w czasie rzeczywistym

**✅ Wersja 3.1 - Sierpień 2025 - BEZPIECZNE SZYFROWANIE SSL:**
- **🔐 Szyfrowanie hasła SSL:** Zaawansowane szyfrowanie AES-256 dla hasła certyfikatu SSL
- **🛡️ Zabezpieczenie PBKDF2:** 100,000 iteracji + SHA256 + unikalne salt dla każdego hasła
- **🔄 Automatyczna migracja:** Skrypt `migrate_ssl_password.py` do bezpiecznej migracji
- **🔑 Zarządzanie kluczami:** Bezpieczne przechowywanie kluczy szyfrowania w .env
- **📁 Backup i walidacja:** Automatyczne kopie zapasowe i testy poprawności migracji
- **🚫 Usunięcie plaintext:** Hasła SSL nie są już przechowywane w postaci czytelnej

**✅ Wersja 3.0 - Sierpień 2025 - MODUŁOWA REFAKTORYZACJA:**
- **🔧 Modułowa architektura:** Podział app.py (1710→75+340+1800 linii) i security.py (1909→302+296+403 linii) na logiczne moduły
- **📁 Lepsza organizacja:** 7 głównych modułów zamiast 2 monolitycznych plików
- **🛡️ Zachowane bezpieczeństwo:** 100% funkcjonalności zabezpieczeń zachowane w nowej strukturze modułowej  
- **⚡ Poprawa wydajności:** Zmniejszenie złożoności dzięki lepszej organizacji
- **🔍 Łatwiejsza konserwacja:** Separacja odpowiedzialności - konfiguracja, logika biznesowa, autoryzacja, walidacja
- **🔄 Pełna kompatybilność:** Zachowanie wszystkich endpointów, WSGI production i konfiguracji SSL

## 🏗️ Architektura aplikacji

**🔧 MODUŁOWA STRUKTURA ENTERPRISE:**

### **🌐 Główna aplikacja Flask (3 moduły):**
- **`app.py`** (75 linii) - Główny punkt wejścia i orchestracja aplikacji
- **`app_config.py`** (345 linii) - Konfiguracja Flask, SSL, logging, middleware i startup logic  
- **`app_core.py`** (1800+ linii) - Wszystkie routy, endpointy, logika biznesowa i API

### **🔒 System bezpieczeństwa (4 moduły):**
- **`security.py`** (339 linii) - Główna klasa SecurityManager i orchestracja komponentów
- **`security_auth.py`** (296 linii) - Autoryzacja, uwierzytelnianie, sesje i rate limiting
- **`security_validation.py`** (403 linii) - Walidacja danych, SSL i mechanizmy sanityzacji
- **`ssl_security.py`** (128 linii) - Bezpieczne szyfrowanie haseł SSL (AES-256 + PBKDF2)

### **⚙️ Komponenty biznesowe:**
- **`jira_api.py`** (816 linii) - Kompleksowa integracja z JIRA API + progress tracking
- **`classifier.py`** (217 linii) - Silnik klasyfikacji regułowej z zabezpieczeniami
- **`rules_manager.py`** (472 linii) - Bezpieczny menedżer reguł klasyfikacji JSON
- **`wsgi_production.py`** (106 linii) - Konfiguracja produkcyjna Waitress dla SSL
- **`classifier.py`** - Klasyfikator problemów z rozszerzoną walidacją kategorii
- **`jira_api.py`** - Integracja z API Jira z zachowaniem oryginalnych dat
- **`wsgi_production.py`** - Konfiguracja produkcyjna WSGI dla Waitress
- **`migrate_ssl_password.py`** - Migracja haseł SSL do postaci zaszyfrowanej
- **`rules.json`** - Reguły klasyfikacji w formacie JSON

**🎯 Korzyści z refaktoryzacji:**
- **📖 Lepsza czytelność:** Logiczne grupowanie funkcji według odpowiedzialności
- **🔧 Łatwiejsza konserwacja:** Modyfikacje w jednym obszarze nie wpływają na inne  
- **⚡ Wydajność:** Lepsze zarządzanie pamięcią przez modularne importy
- **🛡️ Bezpieczeństwo:** Izolacja mechanizmów bezpieczeństwa w dedykowanych modułach

## Szybki start

1. **Wymagania:** Python 3.8+, plik `.env` z konfiguracją, reverse proxy (Nginx) dla produkcji
2. **Instalacja:** `pip install -r requirements.txt`
3. **Konfiguracja:** Skonfiguruj plik `.env` zgodnie z szablonem poniżej
4. **Uruchomienie:** `python app.py` (domyślnie port 5000)
5. **Panel admina:** `/admin/login` (login: admin, hasło: w `.env` jako hash scrypt)
6. **Produkcja:** Używaj reverse proxy (Nginx) z SSL/TLS

## 🚀 Kluczowe funkcje

### **📊 Analiza i klasyfikacja**
- **Real-time progress tracking:** Dynamiczny pasek postępu z rzeczywistymi estymacjami czasowymi
- **AJAX-based interface:** Analiza bez przeładowania strony z live updates co sekundę
- **Inteligentna klasyfikacja:** 26+ reguł JSON dla automatycznej kategoryzacji zgłoszeń
- **Background processing:** Wielowątkowa analiza z raportowaniem postępu w czasie rzeczywistym
- **Precyzyjne estymacje:** Bazowane na rzeczywistej wydajności JIRA API (0.05s/zadanie)

### **🔗 Eksport i integracja Excel**
- **Inteligentne hyperlinki Excel:** Automatyczne wykrywanie wersji językowej (HYPERLINK/HIPERŁĄCZE)
- **Multi-language support:** Konfigurowalne via `EXCEL_LANGUAGE` (auto/pl/en)
- **Bezpieczny eksport CSV:** UTF-8 z BOM, sanityzacja przed formula injection
- **Rozszerzone kolumny:** Data, Godzina, Link do Jira, Typ żądania, IT Buddy, Telefon do
- **Zachowanie formatowania:** Myślniki w kluczach JIRA, prawdziwe daty/godziny

### **🔒 Enterprise Security**
- **Bezpieczne szyfrowanie SSL:** Hasła certyfikatów SSL zaszyfrowane AES-256 z PBKDF2
- **Modułowa architektura bezpieczeństwa:** Separacja autoryzacji, walidacji i SSL
- **CSRF protection:** Tokeny CSRF z walidacją i automatyczną rotacją
- **Rate limiting:** Flask-Limiter z konfigurowalnymi limitami per IP
- **Comprehensive logging:** Strukturalne logi bezpieczeństwa z rotacją

### **🌐 JIRA Integration**
- **Real-time data fetching:** Pobieranie danych z progress reporting i ETA calculation
- **Batch processing:** Efektywne przetwarzanie dużych zestawów danych
- **Error handling:** Robust obsługa błędów API z retry mechanism
- **Original timestamps:** Zachowanie oryginalnych godzin utworzenia z JIRA
- **Multi-project support:** Obsługa różnych projektów i typów zgłoszeń

### **⚙️ Panel administracyjny**
- **Secure admin interface:** Bezpieczne zarządzanie regułami z walidacją
- **JSON rules editor:** Intuicyjny interfejs do edycji reguł klasyfikacji
- **Automatic backups:** Kopie zapasowe przy każdej zmianie z timestampem
- **Rules validation:** Walidacja składni i logiki reguł przed zapisem
- **Audit logging:** Pełne logowanie zmian administratorskich

## 📁 Struktura plików

```
AnalizatorProblemowJira/
# === GŁÓWNE MODUŁY APLIKACJI ===
├── app.py                    # Główny punkt wejścia (75 linii)
├── app_config.py             # Konfiguracja Flask i SSL (345 linii)  
├── app_core.py               # Routy i logika biznesowa (1800+ linii)

# === SYSTEM BEZPIECZEŃSTWA ===
├── security.py               # SecurityManager - orchestracja (339 linii)
├── security_auth.py          # Autoryzacja i sesje (296 linii)
├── security_validation.py    # Walidacja i SSL (403 linii)
├── ssl_security.py           # Szyfrowanie haseł SSL (128 linii)

# === KOMPONENTY BIZNESOWE ===
├── rules_manager.py          # Menedżer reguł JSON (472 linii)
├── classifier.py             # Klasyfikator problemów (217 linii)
├── security_validation.py    # Walidacja danych i SSL (403 linii)
├── ssl_security.py          # Szyfrowanie haseł SSL (128 linii)

# === KOMPONENTY BIZNESOWE ===
├── jira_api.py              # Kompleksowa integracja JIRA API (816 linii)
├── classifier.py            # Silnik klasyfikacji regułowej (217 linii)
├── rules_manager.py         # Menedżer reguł JSON (472 linii)

# === KONFIGURACJA I PRODUKCJA ===
├── wsgi_production.py       # WSGI dla Waitress + SSL (106 linii)
├── migrate_ssl_password.py  # Migracja haseł SSL (126 linii)
├── generate_secret_key.py   # Generator klucza sesji Flask
├── rules.json              # 26+ reguł klasyfikacji (1224 linii)
├── requirements.txt        # Zależności Python (14 pakietów)
├── .env                    # Konfiguracja środowiska (99 linii)

# === FRONTEND ===
├── templates/              # Szablony HTML
│   ├── base.html          # Szablon bazowy z ciemnym motywem
│   ├── index.html         # Główna strona z real-time progress
│   ├── results.html       # Wyniki analizy z wykresami
│   ├── admin_login.html   # Panel logowania administratora
│   └── analysis_progress.html # Dedykowana strona postępu
├── static/                # Zasoby statyczne
│   ├── style_new.css     # CSS ciemnego motywu
│   ├── charts.js         # Wykresy Plotly.js
│   └── js/               # Dodatkowe skrypty JavaScript

# === DANE I LOGI ===
├── data/                  # Dane CSV z JIRA i eksporty
├── logs/                  # Logi aplikacji (app.log, security.log)
├── backups/              # Automatyczne kopie zapasowe reguł
├── cache/                # Cache aplikacji i preferencje użytkownika
├── ssl/                  # Certyfikaty SSL i klucze (production)

# === DEPLOYMENT ===
├── nginx/                # Konfiguracja Nginx dla reverse proxy
├── start_simple.bat     # Skrypt startowy dla Windows
├── stop_simple.bat      # Skrypt zatrzymywania dla Windows
```

## 📊 Eksport danych z hyperlinkami Excel

### **🔗 Inteligentne hyperlinki**
**Automatyczne wykrywanie języka Excel:**
- **Tryb automatyczny:** Wykrywanie na podstawie locale systemu + środowiska korporacyjnego
- **Wersja polska:** Używa funkcji `HIPERŁĄCZE` dla polskich ustawień Excel
- **Wersja angielska:** Używa funkcji `HYPERLINK` dla angielskich ustawień Excel

**Konfiguracja w .env:**
```bash
# Dostępne opcje: 'auto', 'pl', 'en'
EXCEL_LANGUAGE=auto
```

**Inteligentne wykrywanie:**
- Sprawdza rejestr Windows Office/Excel
- Analizuje zmienne środowiskowe Office
- Wykrywa środowiska korporacyjne (defaultuje na angielski)
- Zapisuje preferencje użytkownika dla przyszłych eksportów

### **📋 Kolumny eksportu CSV**
**Podstawowe dane zgłoszenia:**
- **Data utworzenia** - Rzeczywista data i czas z JIRA
- **Data** - Format DD.MM.YYYY dla lepszej czytelności  
- **Godzina** - Format HH:MM oddzielnie
- **Klucz** - Zachowane myślniki (SD-175062)
- **Tytuł** - Oryginalne formatowanie z myślnikami i plusami
- **Typ zgłoszenia** - Incydent, Problem, Żądanie zmiany
- **Status** - Aktualny status zgłoszenia

**Lokalizacja i kontakt:**
- **Numer restauracji** - Automatycznie wykryte numery
- **Nazwa restauracji** - Pełne nazwy lokalizacji
- **Telefon do** - Numery kontaktowe (jeśli dostępne)
- **IT Buddy** - Przypisany IT Buddy (jeśli dostępny)

**Klasyfikacja i analiza:**
- **Dopasowana Reguła** - Nazwa dopasowanej kategorii
- **Pewność klasyfikacji** - Wynik 0.0-1.0 zaokrąglony do 2 miejsc
- **Typ żądania** - Szczegółowa kategoryzacja typu żądania

**Integracja:**
- **Link do Jira** - Gotowe formuły Excel (HYPERLINK/HIPERŁĄCZE)

### **🛡️ Bezpieczeństwo eksportu**
**Sanityzacja danych:**
- Ochrona przed formula injection (usuwanie =, +, -, @ z początku)
- Zachowanie polskich znaków (ąćęłńóśźżĄĆĘŁŃÓŚŹŻ)
- Wsparcie dla przecinków w nazwach kategorii
- Kodowanie UTF-8 z BOM dla prawidłowego otwierania w Excel

**Przykład wygenerowanego hyperlinku:**
```csv
Link do Jira
=HIPERŁĄCZE("https://sdeskdro.atlassian.net/browse/SD-175062";"SD-175062")
=HYPERLINK("https://sdeskdro.atlassian.net/browse/SD-175061";"SD-175061")
```

## ⚙️ Konfiguracja środowiska

### **🔧 Plik .env - Konfiguracja główna**

```bash
# === FLASK CONFIGURATION ===
FLASK_SECRET_KEY=04a24f81c8d46959e0a1db6344cbc1cbe89d6258853dd6dcac56739ff4491b0e
FLASK_ENV=production
FLASK_DEBUG=False

# === JIRA API INTEGRATION ===
JIRA_DOMAIN=https://sdeskdro.atlassian.net
JIRA_EMAIL=dominik.rochaczewski@gmail.com
JIRA_TOKEN=ATATT3xFfGF0fTDT8qn94oMGRJiLUGep4USkAm7oaP60fu40yXu4fBb6EvlsexYHUeFoY63PXKb-zHFftsG_jszw-W7XaGDGOklZEvdNutEdG4Q9Lb8Equ-wx2SMmkc-umTWBAHI30x60QXpPgkOr0UifkQo2ge_2-NvCYci5hnPPMPwqDvtAQc=082E2772

# === ADMIN AUTHENTICATION ===
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=scrypt:32768:8:1$t9KFgndVjBNfGX8T$99f84687e67a8b94ae38bdf84446af4265c2a4ab346f5df63b6b6c5733df897f323e53344d49ab09858506e98be7925c17613cef94c7a221e9631cd5836b7188
ADMIN_SESSION_TIMEOUT=7200

# === EXCEL LANGUAGE SETTINGS ===
# Dostępne opcje: 'auto', 'pl', 'en'
EXCEL_LANGUAGE=auto

# === SECURITY CONFIGURATION ===
CSRF_SECRET_KEY=9b4e7f2a5c8d1e6b9f2c5a8e1b4d7f0c3a6e9b2f5c8a1e4b7d0f3a6c9e2b5a8f1
SESSION_COOKIE_SECURE=True
ENABLE_BRUTE_FORCE_PROTECTION=True
MAX_LOGIN_ATTEMPTS=5

# === SSL CONFIGURATION (Production) ===
SSL_CERT_PATH=ssl/pl.mcd.com.pem
SSL_KEY_PATH=ssl/pl.mcd.com.key
SSL_PASSWORD_ENCRYPTED=gAAAAABm...  # Zaszyfrowane hasło AES-256
```

## 🛡️ Bezpieczeństwo

### **🔐 Architektura bezpieczeństwa (4 moduły - 1162 linie)**

```
security/
├── security.py             # Orkiestracja bezpieczeństwa (339 linii)
├── security_auth.py        # Uwierzytelnianie użytkowników (296 linii) 
├── security_validation.py  # Walidacja danych wejściowych (403 linie)
└── ssl_security.py         # Szyfrowanie SSL/TLS (128 linii)
```

### **🔑 Funkcje bezpieczeństwa**

**1. Uwierzytelnianie i autoryzacja:**
- Bezpieczne hashowanie haseł (scrypt)
- Zarządzanie sesjami z timeoutem
- Ochrona przed brute-force (5 prób logowania)
- CSRF protection z unikalnym tokenem

**2. Szyfrowanie komunikacji:**
- SSL/TLS z certyfikatami domenowymi (pl.mcd.com)
- AES-256 dla haseł SSL
- Bezpieczne przechowywanie kluczy
- Perfect Forward Secrecy

**3. Walidacja danych:**
- XSS protection w eksporcie CSV
- Injection prevention 
- Sanityzacja danych wejściowych
- Rate limiting na endpointy

**4. Zabezpieczenia infrastruktury:**
- Content Security Policy (CSP)
- Secure headers (HSTS, X-Frame-Options)
- Session fixation protection
- Automatic logout po timeout

## 🚀 Wdrożenie

### **🏢 Środowisko produkcyjne**

**1. Wymagania systemowe:**
```bash
# Windows Server 2019+ / Linux Ubuntu 20.04+
Python 3.8+
Flask 2.3.3
SSL Certificate (pl.mcd.com)
JIRA API Token
```

**2. Instalacja produkcyjna:**
```powershell
# Klonowanie repozytorium
git clone [repo-url] AnalizatorJira
cd AnalizatorJira

# Instalacja zależności  
pip install -r requirements.txt

# Konfiguracja SSL
copy ssl\pl.mcd.com.pem ssl\
copy ssl\pl.mcd.com.key ssl\

# Generowanie kluczy bezpieczeństwa
python generate_secret_key.py

# Migracja hasła SSL (jeśli wymagana)
python migrate_ssl_password.py

# Start produkcyjny
python wsgi_production.py
```

**3. Monitorowanie:**
- Logi aplikacji: `logs/app.log`
- Logi bezpieczeństwa: `logs/security.log`
- Metryki wydajności: real-time progress tracking
- Backup automatyczny: `backups/` (rules.json)

### **🔧 Konfiguracja zaawansowana**

**Nginx Reverse Proxy:**
```nginx
server {
    listen 443 ssl;
    server_name pl.mcd.com;
    
    ssl_certificate ssl/pl.mcd.com.pem;
    ssl_certificate_key ssl/pl.mcd.com.key;
    
    location / {
        proxy_pass https://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🐛 Rozwiązywanie problemów

### **⚠️ Częste problemy i rozwiązania**

**1. Problem z hyperlinkami w Excel:**
```bash
Symptom: Excel pokazuje HIPERŁĄCZE zamiast HYPERLINK
Diagnoza: Nieprawidłowa konfiguracja języka Excel
Rozwiązanie: 
  - Ustaw EXCEL_LANGUAGE=auto w .env
  - Lub wymuś język: EXCEL_LANGUAGE=en (dla ang. Excel)
```

**2. Błąd połączenia z JIRA:**
```bash
Symptom: HTTP 401/403 przy pobieraniu ticketów
Diagnoza: Nieprawidłowy token lub uprawnienia
Rozwiązanie:
  - Sprawdź JIRA_TOKEN w .env
  - Wygeneruj nowy token w JIRA Settings
  - Sprawdź uprawnienia konta (Browse Projects)
```

**3. Błąd SSL/TLS:**
```bash
Symptom: Nie można załadować certyfikatu
Diagnoza: Błędna ścieżka lub hasło SSL
Rozwiązanie:
  - Sprawdź SSL_CERT_PATH i SSL_KEY_PATH
  - Odszyfruj hasło: python migrate_ssl_password.py
```

**4. Problem z regułami klasyfikacji:**
```bash
Symptom: Błędna kategoryzacja ticketów
Diagnoza: Nieprawidłowe reguły w rules.json
Rozwiązanie:
  - Przywróć backup: backups/rules.json_backup_[data].json
  - Waliduj JSON: python -m json.tool rules.json
```

### **📊 Diagnostyka systemu**

**Sprawdzenie statusu:**
```powershell
# Test połączenia JIRA
python -c "from jira_api import JiraAPI; print(JiraAPI().test_connection())"

# Walidacja SSL
python -c "from ssl_security import verify_ssl_setup; verify_ssl_setup()"

# Test bezpieczeństwa
python -c "from security import SecurityOrchestrator; print('OK')"
```

## 🔧 Konserwacja

### **📅 Zadania konserwacyjne**

**Cotygodniowe:**
- Backup rules.json (automatyczny)
- Przegląd logów bezpieczeństwa
- Aktualizacja haseł dostępu

**Comiesięczne:**
- Rotacja tokenów JIRA
- Sprawdzenie certyfikatów SSL
- Analiza wydajności

**Coroczne:**
- Odnowienie certyfikatów SSL
- Audit bezpieczeństwa
- Aktualizacja dependencies

### **📁 Struktura backupów**

```
backups/
├── rules.json_backup_YYYYMMDD_HHMMSS.json
├── admin.css.backup.YYYYMMDD_HHMMSS  
└── generate_admin_password.py
```

**Przywracanie z backup:**
```powershell
# Przywróć najnowszy backup rules.json
copy "backups\rules.json_backup_20250806_154738.json" "rules.json"

# Restart aplikacji
python app.py
```

---

## 📞 Kontakt i wsparcie

**🏢 Support Contact**
- **Email:** dominik.rochaczewski@gmail.com
- **JIRA:** [sdeskdro.atlassian.net](https://sdeskdro.atlassian.net)

**📚 Dokumentacja techniczna:**
- **Architektura:** 7 modułów, 3049 linii kodu
- **Bezpieczeństwo:** 4-warstwowa ochrona
- **Integracja:** JIRA API v3, Excel automation
- **Wersja:** 2025.08 (Production Ready)

---

*Analizator Problemów JIRA - Kompleksowe narzędzie do klasyfikacji i eksportu zgłoszeń z integracją Excel i zaawansowanym systemem bezpieczeństwa.*

**Aplikacja implementuje zaawansowany system bezpieczeństwa w modułowej architekturze:**

### 🛡️ Inteligentna sanityzacja danych CSV
- **Zachowanie kluczy JIRA:** Myślniki w kluczach (SD-175062) są prawidłowo zachowywane
- **Poprawne formatowanie dat:** Daty w formacie `2025-07-23 14:30:00` z rzeczywistymi godzinami
- **Wsparcie dla polskich znaków:** Pełne zachowanie ąćęłńóśźżĄĆĘŁŃÓŚŹŻ w eksporcie
- **Inteligentne myślniki:** Zachowanie myślników w tytułach (POS01 - nie działa) i datach
- **Bezpieczne plusy:** Zachowanie plusów w tytułach (C++ aplikacja) z ochroną przed formula injection
- **Obsługa przecinków:** Przecinki dozwolone w nazwach kategorii (POS, CSO - zawieszenie)
- **Formula injection protection:** Automatyczne usuwanie `=`, `+`, `-`, `@` z początku komórek
- **Inteligentne dwukropki:** Zachowanie dwukropków w czasach (14:30:00) z filtrowaniem niebezpiecznych

### � Szyfrowanie haseł SSL (ssl_security.py)
- **Algorytm AES-256:** Hasła certyfikatów SSL zaszyfrowane za pomocą Fernet (AES-256)
- **Wyprowadzanie kluczy:** PBKDF2 z 100,000 iteracji + SHA256 + unikalne salt
- **Bezpieczne przechowywanie:** Klucze szyfrowania oddzielnie od zaszyfrowanych danych
- **Automatyczna migracja:** Skrypt `migrate_ssl_password.py` do bezpiecznej migracji
- **Fallback mechanism:** Automatyczne przełączanie między zaszyfrowaną a niezaszyfrowaną wersją
- **Walidacja integralności:** Testy poprawności szyfrowania podczas migracji
- **Backup automatyczny:** Kopie zapasowe .env przed migracją

### �🔒 Zabezpieczenia aplikacji (security_auth.py)
- **Uwierzytelnianie:** Hash scrypt hasła administratora w `.env`
- **Klucz sesji:** Stały bezpieczny klucz z `.env` (wymagany w produkcji)
- **CSRF Protection:** Tokeny CSRF dla wszystkich operacji administracyjnych
- **Flask-Limiter:** Profesjonalny rate limiting z obsługą proxy headers
- **Timeout sesji:** Automatyczne wylogowanie po bezczynności
- **Rotacja sesji:** Bezpieczne odnawianie sesji administracyjnych

### 🔍 Walidacja i SSL (security_validation.py)
- **Walidacja hostów:** Dostęp tylko z autoryzowanych sieci (`165.225.0.0/16`, localhost)
- **Konfiguracja:** `ALLOWED_HOSTS` i `ENABLE_HOST_VALIDATION` w zmiennych środowiskowych
- **Sesje:** Cookies z `Secure`, `HttpOnly`, `SameSite=Strict`
- **SSL Management:** Automatyczna walidacja certyfikatów i uprawnień plików
- **Input validation:** Kompleksowa walidacja wszystkich danych wejściowych

### 📋 Rozszerzona walidacja kategorii
- **Dozwolone znaki:** Litery (a-z, A-Z), cyfry (0-9), spacje, myślniki (-), slash (/), przecinki (,)
- **Polskie znaki:** Pełne wsparcie dla ąćęłńóśźżĄĆĘŁŃÓŚŹŻ
- **Inteligentna walidacja:** Rozpoznawanie kontekstu dla myślników (klucze JIRA, daty, tytuły)
- **Blokowanie niebezpiecznych znaków:** Automatyczne filtrowanie `=`, `+` na początku, `@`, `|` itp.
- **Walidacja długości:** Ograniczenie długości nazw kategorii (max 100 znaków)
- **Testowanie kompletne:** Zestaw testów walidacji dla wszystkich przypadków użycia

### 🔍 Monitorowanie i logowanie
- **Logi bezpieczeństwa:** Szczegółowe logowanie wszystkich zdarzeń
- **Rotacja logów:** Automatyczna rotacja i kompresja archiwów
- **Pełny traceback:** Wszystkie wyjątki logowane z pełnym śladem stosu
- **Exception logging:** `app_logger.exception()` i `sec_logger.exception()` w całej aplikacji
- **Monitoring prób:** Śledzenie nieautoryzowanych dostępów
- **Flask-Limiter:** Monitoring rate limiting z obsługą sieci korporacyjnych

## Eksport danych

**Inteligentne formatowanie wyników CSV:**
- **Kolumny:** Data utworzenia, Klucz, Tytuł, Typ zgłoszenia, Numer/Nazwa restauracji, Kategoria, Pewność klasyfikacji
- **Poprawne daty:** Format `2025-07-23 14:30:00` z rzeczywistymi godzinami z JIRA (nie zawsze 02:00)
- **Klucze JIRA:** Zachowane myślniki w kluczach (`SD-175062` zamiast `SD 175062`)
- **Tytuły z formatowaniem:** Zachowane myślniki i plusy w tytułach (`POS01 - nie działa`, `C++ problem`)
- **Bezpieczeństwo:** Ochrona przed formula injection (usuwanie `=`, `+`, `-`, `@` z początku)
- **Polskie znaki:** Pełne zachowanie ąćęłńóśźżĄĆĘŁŃÓŚŹŻ w eksporcie CSV
- **Przecinki:** Wsparcie dla przecinków w nazwach kategorii (`POS, CSO - zawieszenie`)
- **Enkodowanie:** UTF-8 z BOM dla prawidłowego otwierania w Excel
- **Lokalizacja:** Pliki CSV zapisywane w katalogu `data/`

### 🔗 Inteligentne hyperlinki Excel

**Automatyczne wykrywanie języka:**
- **Tryb automatyczny:** Wykrywanie na podstawie locale systemu (`EXCEL_LANGUAGE=auto`)
- **Wersja polska:** Używa funkcji `HIPERŁĄCZE` dla polskich ustawień Excel (`EXCEL_LANGUAGE=pl`)
- **Wersja angielska:** Używa funkcji `HYPERLINK` dla angielskich ustawień Excel (`EXCEL_LANGUAGE=en`)

**Konfiguracja w .env:**
```bash
# Dostępne opcje: 'auto', 'pl', 'en'
EXCEL_LANGUAGE=auto
```

**Przykład wygenerowanej kolumny:**
```csv
jira_link
=HIPERŁĄCZE("https://sdeskdro.atlassian.net/browse/SD-175062";"SD-175062")
=HIPERŁĄCZE("https://sdeskdro.atlassian.net/browse/SD-175061";"SD-175061")
```

**Jak używać:**
1. Otwórz wyeksportowany plik CSV w Excel
2. Kolumna `jira_link` zawiera gotowe formuły Excel
3. Kliknij na link aby otworzyć zadanie w JIRA
4. Formuła automatycznie dopasowuje się do wersji językowej Excel

**Przykład wynikowego CSV:**
```csv
Data utworzenia;Klucz;Tytuł;Typ zgłoszenia;Numer restauracji;Nazwa restauracji;Kategoria;Pewność klasyfikacji
2025-07-23 23:58:34;SD-175062;Mystore Zawiesił się;Incydent;353;Kobylka;MyStore - błędy;0.8
2025-07-23 14:30:00;SD-175061;POS01 - nie działa;Incydent;254;Szczecin 6 Galaxy;Terminal - problemy;0.9
```

## Zarządzanie regułami

**Panel administracyjny (`/admin/login`):**
- **Dodawanie reguł:** Nowe reguły klasyfikacji przez interfejs webowy
- **Edytowanie:** Modyfikacja istniejących reguł z walidacją
- **Usuwanie:** Bezpieczne usuwanie reguł z potwierdzeniem
- **Podgląd:** Podgląd aktualnych reguł i ich struktury
- **Backup:** Automatyczne kopie zapasowe przy każdej zmianie
- **Validacja:** Weryfikacja poprawności reguł przed zapisem

**Format reguł JSON:**
```json
{
  "classification_rules": {
    "nazwa_reguly": {
      "keywords": ["słowo1", "słowo2"],
      "category": "kategoria",
      "confidence": 0.9,
      "description": "Opis reguły"
    }
  }
}
```

## Konfiguracja środowiska

**Generowanie klucza sesji:**
```bash
# Wygeneruj bezpieczny klucz sesji
python -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32))"
# Skopiuj wygenerowany klucz do .env
```

## 🔐 Konfiguracja bezpiecznego SSL

**Migracja hasła SSL do postaci zaszyfrowanej:**
```bash
# Uruchom skrypt migracji (z niezaszyfrowanym hasłem w .env)
python migrate_ssl_password.py

# Skrypt automatycznie:
# 1. Tworzy kopię zapasową .env
# 2. Generuje bezpieczne klucze szyfrowania
# 3. Szyfruje hasło SSL algorytmem AES-256
# 4. Wyświetla nowe zmienne do .env
```

**Wymagane zmienne środowiskowe dla SSL (.env):**
```env
# Podstawowa konfiguracja SSL
SSL_CERT_PATH=ssl/pl.mcd.com.pem
SSL_KEY_PATH=ssl/pl.mcd.com_decrypted.key
SSL_ENABLED=True
SSL_PORT=443

# ZASZYFROWANE HASŁO SSL - wygenerowane przez migrate_ssl_password.py
SSL_MASTER_KEY=Lnq5b_7N35x7XdaL9Fusd4XY6HskmQyGEZn_1VchLwM=
SSL_ENCRYPTION_SALT=XghhE7vNQuXawYmR38ZEWQ==
SSL_CERT_PASSWORD_ENCRYPTED=Z0FBQUFBQm9rbEl3ME1YSzNPWUxCSF9w...

# Monitoring SSL
SSL_EXPIRY_WARNING_DAYS=30
SSL_EXPIRY_CRITICAL_DAYS=7
SSL_CERT_MONITORING=True
SSL_BACKUP_ENABLED=True
```

**🔒 Bezpieczeństwo kluczy szyfrowania:**
- **Backup kluczy:** Zapisz `SSL_MASTER_KEY` i `SSL_ENCRYPTION_SALT` w bezpiecznym miejscu
- **Nie udostępniaj:** Klucze szyfrowania są równie ważne jak oryginalne hasło
- **Rotacja:** Regularnie zmieniaj hasła certyfikatów i migruj ponownie

## Uruchomienie w środowisku produkcyjnym

### 🚀 Wymagania produkcyjne

**WSGI Deployment (wsgi_production.py):**
```bash
# Uruchomienie przez Waitress (zalecane dla produkcji)
waitress-serve --host=127.0.0.1 --port=8001 wsgi_production:application

# Lub bezpośrednio przez WSGI
python wsgi_production.py
```

**Reverse Proxy (Nginx):**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8001;  # Port dla Waitress
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Rate limiting na poziomie Nginx
        limit_req zone=api burst=10 nodelay;
    }
}

# Rate limiting zone
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
}
```

**Systemd Service:**
```ini
[Unit]
Description=WolumenProblemow Flask App
After=network.target

[Service]
Type=simple
User=your-app-user
WorkingDirectory=/path/to/app
Environment=PATH=/path/to/venv/bin
ExecStart=/path/to/venv/bin/python wsgi_production.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Logowanie

**Lokalizacja logów:**
- `logs/app.log` - Logi głównej aplikacji
- `logs/security.log` - Logi bezpieczeństwa  
- `logs/application.log` - Logi ogólne
- `logs/errors.log` - Logi błędów

**Konfiguracja:**
- Automatyczna rotacja plików logów
- Kompresja starych archiwów
- Formatowanie z timestamp i poziomem
- Separate loggery for different components

## Testowanie i diagnostyka

**Testy bezpieczeństwa:**
- `python test_host_validation.py` - Testowanie walidacji hostów
- `python test_host_config.py` - Testowanie konfiguracji bezpieczeństwa
- Sprawdzanie logów w katalogu `logs/` w przypadku problemów

**Testy modułowości:**
```bash
# Test importów wszystkich modułów
python -c "import app; print('✅ App modules OK')"
python -c "import security; print('✅ Security modules OK')"
python -c "import wsgi_production; print('✅ WSGI production OK')"
```

**Diagnostyka:**
- Monitoring przez logi aplikacji
- Sprawdzanie backupów reguł w `backups/`
- Weryfikacja plików CSV w `data/`
- Testowanie dostępu do panelu admina

## Rollback i kopie zapasowe

**🔄 Możliwość pełnego rollback:**
```bash
# Powrót do oryginalnej wersji (przed refaktoryzacją)
cp app_original.py app.py
cp security_original.py security.py
# Usuń nowe moduły jeśli potrzeba
rm -f app_config.py app_core.py security_auth.py security_validation.py
```

**📁 Lokalizacja kopii zapasowych:**
- `app_original.py` - Oryginalny app.py (1710 linii)
- `security_original.py` - Oryginalny security.py (1909 linii)
- `app.py.backup` - Dodatkowa kopia zapasowa
- `security.py.backup` - Dodatkowa kopia zapasowa

## Zalecenia bezpieczeństwa

**Zalecenia bezpieczeństwa dla produkcji:**
- ❌ **Nigdy** nie ustawiaj `ALLOWED_HOSTS=*` ani `0.0.0.0`
- ❌ **Nigdy** nie uruchamiaj bez reverse proxy (Nginx/Apache) w produkcji
- ✅ **Zawsze** używaj HTTPS w produkcji (`SESSION_COOKIE_SECURE=True`)
- ✅ **Zawsze** ustaw stały `FLASK_SECRET_KEY` w produkcji
- ✅ **Regularnie** sprawdzaj logi bezpieczeństwa w `logs/`
- ✅ **Utrzymuj** aktualne hasło admina i prawidłowe zakresy IP
- ✅ **Monitoruj** dostęp do panelu administracyjnego
- ✅ **Sprawdzaj** kopie zapasowe reguł w `backups/`
- ✅ **Używaj** SSL/TLS z prawidłowymi certyfikatami
- ✅ **Konfiguruj** Flask-Limiter z odpowiednimi limitami dla środowiska
- ✅ **Implementuj** HTTP Security Headers w Nginx
- ✅ **Ustaw** Fail2ban dla ochrony przed brute-force
- ✅ **Konfiguruj** automatyczny logrotate dla aplikacji
- ✅ **Używaj** Waitress WSGI server w produkcji zamiast Flask dev server

**Najlepsze praktyki:**
- Regularne backup całej aplikacji i bazy danych
- Monitoring logów bezpieczeństwa z pełnym traceback
- Aktualizacja zależności Python (security updates)
- Testowanie reguł klasyfikacji w środowisku dev
- Weryfikacja dostępu do sieci firmowej przez ALLOWED_HOSTS
- Monitoring performance Flask-Limiter w środowisku produkcyjnym
- Konfiguracja alertów dla błędów krytycznych z logów
- Testowanie modułowej struktury po aktualizacjach

## Zależności

**Główne biblioteki (requirements.txt):**
```
flask==3.0.0                # Framework webowy
flask-limiter==3.5.0        # Profesjonalny rate limiting
pandas==2.1.4               # Manipulacja danymi
requests==2.31.0            # HTTP requests dla Jira API
python-dotenv==1.0.0        # Zarządzanie zmiennymi środowiskowymi
flask-wtf==1.1.1           # CSRF protection
werkzeug==3.0.1            # Utilities dla Flask
bcrypt==4.0.1              # Hashing haseł
scikit-learn==1.3.2        # Machine learning utilities
numpy==1.26.2              # Numeryczne operacje
plotly==5.17.0             # Wykresy (future feature)
waitress==2.1.2            # WSGI server dla produkcji
cryptography==41.0.0       # SSL certificate handling
```

## Wsparcie techniczne

**W przypadku problemów:**
1. **Sprawdź logi:** `logs/app.log`, `logs/security.log`, `logs/errors.log`
2. **Weryfikuj konfigurację:** Sprawdź zmienne w pliku `.env`
3. **Testuj połączenie:** Sprawdź dostęp do Jira API
4. **Sprawdź backupy:** Zweryfikuj kopie zapasowe reguł w `backups/`
5. **Monitoruj sesje:** Sprawdź logi bezpieczeństwa dla błędów uwierzytelniania
6. **Testuj moduły:** Sprawdź czy wszystkie moduły importują się poprawnie

**Troubleshooting modułowej struktury:**
- Błędy importów: Sprawdź czy wszystkie nowe pliki są obecne
- Problemy z security: Sprawdź moduły `security_auth.py` i `security_validation.py`
- Błędy konfiguracji: Sprawdź `app_config.py` 
- Problemy z routami: Sprawdź `app_core.py`
- WSGI errors: Sprawdź `wsgi_production.py`

**Troubleshooting klasyczny:**
- Błędy Jira API: Sprawdź token i uprawnienia
- Problemy z regułami: Sprawdź format JSON i walidację
- Błędy sesji: Sprawdź konfigurację cookies i HTTPS
- Problemy z hostem: Sprawdź `ALLOWED_HOSTS` i sieć firmową

**Emergency rollback:**
- W przypadku problemów z nową strukturą użyj kopii zapasowych
- `cp app_original.py app.py && cp security_original.py security.py`
- Restart aplikacji z oryginalną strukturą