# 📊 System Klasyfikacji i Analizy Zgłoszeń

**Aplikacja webowa do automatycznej klasyfikacji i analizy zgłoszeń z systemu Jira**

## 📋 Spis treści

- [Opis](#opis)
- [Funkcjonalności](#funkcjonalności)
- [Instalacja](#instalacja)
- [Konfiguracja](#konfiguracja)
- [Uruchomienie](#uruchomienie)
- [Bezpieczeństwo](#bezpieczeństwo)
- [API](#api)

## Opis

System służy do automatycznej klasyfikacji zgłoszeń serwisowych z systemu Jira na podstawie konfigurowalnych reguł. Umożliwia:

- Pobieranie zgłoszeń z Jira API
- Klasyfikację na podstawie reguł (regex, słowa kluczowe)
- Generowanie raportów i statystyk
- Eksport danych do formatów CSV/XLSX
- Panel administracyjny do zarządzania regułami

## Funkcjonalności

### 🎯 Główne funkcje

- **Analiza zgłoszeń** - pobieranie i klasyfikacja zgłoszeń z Jira
- **Real-time progress** - dynamiczny pasek postępu z rzeczywistymi danymi
- **System reguł** - konfigurowalne reguły klasyfikacji z priorytetami
- **Dashboard** - wizualizacja statystyk i trendów
- **Panel admina** - zarządzanie regułami i konfiguracją
- **Eksport danych** - generowanie raportów CSV/XLSX z hyperlinkami

### 🔒 Bezpieczeństwo

- Uwierzytelnianie przez hasło admin
- Ochrona CSRF dla formularzy
- Rate limiting dla API
- Walidacja hostów (ALLOWED_HOSTS)
- Szyfrowanie haseł SSL (AES-256)
- Secure session cookies

## Instalacja

### Wymagania systemowe

- Python 3.8+
- pip (menedżer pakietów)
- Dostęp do Jira API

### Kroki instalacji

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/your-username/your-repo.git
cd your-repo

# 2. Utwórz środowisko wirtualne
python -m venv .venv

# 3. Aktywuj środowisko
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 4. Zainstaluj zależności
pip install -r requirements.txt
```

## Konfiguracja

### Plik .env

Utwórz plik `.env` w głównym katalogu projektu:

```env
# === JIRA API ===
JIRA_EMAIL=your-email@example.com
JIRA_TOKEN=your-jira-api-token
JIRA_DOMAIN=https://your-company.atlassian.net

# === FLASK ===
FLASK_SECRET_KEY=your-secret-key-here
FLASK_DEBUG=False
FLASK_ENV=production

# === BEZPIECZEŃSTWO ===
ADMIN_PASSWORD_HASH=your-bcrypt-hash
CSRF_SECRET_KEY=your-csrf-secret-key

# === ALLOWED HOSTS ===
ALLOWED_HOSTS=localhost,127.0.0.1

# === SSL (opcjonalne) ===
SSL_ENABLED=False
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem
```

### Generowanie kluczy

```bash
# Wygeneruj bezpieczny klucz sesji Flask
python -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_hex(32))"

# Wygeneruj hash hasła admin
python generate_secret_key.py
```

### Migracja hasła SSL (opcjonalne)

```bash
# Uruchom skrypt migracji dla szyfrowania hasła SSL
python migrate_ssl_password.py
```

## Uruchomienie

### Tryb deweloperski

```bash
# Uruchom serwer deweloperski
python start_dev.py

# Lub przez skrypt batch (Windows)
start_development.bat
```

### Tryb produkcyjny

```bash
# Uruchomienie przez Waitress (zalecane)
waitress-serve --host=127.0.0.1 --port=8001 wsgi_production:application

# Lub przez WSGI
python wsgi_production.py
```

### Dostęp do aplikacji

- **Główna strona:** `http://localhost:5000/`
- **Panel admina:** `http://localhost:5000/admin`
- **Dashboard:** `http://localhost:5000/dashboard`

## Bezpieczeństwo

### Zalecenia produkcyjne

- ✅ Używaj HTTPS w produkcji
- ✅ Ustaw prawidłowe `ALLOWED_HOSTS`
- ✅ Regularnie aktualizuj zależności
- ✅ Monitoruj logi bezpieczeństwa
- ✅ Używaj silnych haseł
- ✅ Konfiguruj reverse proxy (Nginx)
- ✅ Włącz rate limiting
- ✅ Używaj SSL/TLS z prawidłowymi certyfikatami

### Logi

Logi znajdują się w katalogu `logs/`:
- `app.log` - logi aplikacji
- `security.log` - logi bezpieczeństwa
- `errors.log` - logi błędów

## API

### Endpointy

| Endpoint | Metoda | Opis |
|----------|--------|------|
| `/api/analyze` | POST | Uruchomienie analizy |
| `/api/analysis-progress/<id>` | GET | Status analizy |
| `/api/rules` | GET | Lista reguł (wymaga auth) |
| `/api/rules` | POST | Aktualizacja reguł (wymaga auth) |

### Jira API

Aplikacja korzysta z Jira REST API v3. Wymagane uprawnienia:
- Odczyt projektów
- Odczyt zgłoszeń
- Wyszukiwanie JQL

## Struktura projektu

```
├── app.py                  # Główny plik aplikacji
├── app_core.py             # Logika routów Flask
├── app_config.py           # Konfiguracja aplikacji
├── jira_api.py             # Integracja z Jira API
├── classifier.py           # Silnik klasyfikacji
├── rules_manager.py        # Zarządzanie regułami
├── security.py             # Moduł bezpieczeństwa
├── security_auth.py        # Uwierzytelnianie
├── security_validation.py  # Walidacja
├── ssl_security.py         # Obsługa SSL
├── wsgi_production.py      # WSGI dla produkcji
├── requirements.txt        # Zależności Python
├── rules.json              # Reguły klasyfikacji
├── templates/              # Szablony HTML
├── static/                 # Pliki statyczne (CSS, JS)
├── logs/                   # Logi aplikacji
├── data/                   # Dane wyjściowe
└── backups/                # Kopie zapasowe
```

## Zależności

Główne biblioteki (pełna lista w `requirements.txt`):

- Flask - framework webowy
- Flask-Limiter - rate limiting
- pandas - manipulacja danymi
- requests - HTTP requests
- python-dotenv - zmienne środowiskowe
- flask-wtf - ochrona CSRF
- bcrypt - hashing haseł
- waitress - WSGI server
- cryptography - obsługa SSL

## Troubleshooting

### Częste problemy

1. **Błąd połączenia z Jira** - sprawdź token i uprawnienia
2. **Błędy importów** - sprawdź czy wszystkie pliki są obecne
3. **Problemy z sesją** - sprawdź konfigurację cookies i HTTPS
4. **Błędy walidacji hosta** - sprawdź `ALLOWED_HOSTS`

### Diagnostyka

```bash
# Test importów
python -c "import app; print('✅ App OK')"

# Sprawdzenie logów
# Windows:
Get-Content logs/app.log -Tail 50
# Linux:
tail -f logs/app.log
```

## Licencja

Projekt prywatny - wszystkie prawa zastrzeżone.

---

*Dokumentacja zaktualizowana: 2025*
