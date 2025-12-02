#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Konfiguracja i inicjalizacja aplikacji Flask
Wydzielone z app.py dla lepszej organizacji kodu
"""

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
import logging
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from jira_api import JiraAPI
from classifier import ProblemClassifier
from security import SecurityManager

# Konfiguracja profesjonalnego logowania
from logging.handlers import RotatingFileHandler

def setup_logging():
    """Konfiguruje profesjonalne logowanie aplikacji"""
    # Utworzenie katalogu logów
    os.makedirs('logs', exist_ok=True)
    
    # Konfiguracja głównego loggera aplikacji
    app_logger = logging.getLogger('app')
    
    # Ustaw poziom logowania na podstawie środowiska
    flask_env = os.getenv('FLASK_ENV', 'development').lower()
    if flask_env == 'production':
        # W produkcji używaj WARNING aby uniknąć logowania wrażliwych danych
        log_level = logging.WARNING
        app_logger.warning("Aplikacja uruchomiona w trybie produkcyjnym - poziom logowania: WARNING")
    else:
        # W developmencie używaj INFO dla pełnego debugowania
        log_level = logging.INFO
        
    app_logger.setLevel(log_level)
    
    # Formatter dla logów - bezpieczny dla polskich znaków
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler do pliku z rotacją - z kodowaniem UTF-8
    file_handler = RotatingFileHandler(
        'logs/app.log', 
        maxBytes=10*1024*1024, 
        backupCount=5, 
        encoding='utf-8'  # Wymusza UTF-8 dla polskich znaków
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Handler do konsoli (stdout) - z bezpiecznym kodowaniem
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    
    # Ustaw kodowanie dla console handler na Windows
    if sys.platform == 'win32':
        try:
            # Spróbuj ustawić UTF-8 dla konsoli Windows
            import codecs
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except (AttributeError, OSError):
            # Fallback dla starszych wersji Python lub systemów
            console_handler = logging.StreamHandler(
                codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
            )
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
    
    # Dodanie handlerów do loggera
    app_logger.addHandler(file_handler)
    app_logger.addHandler(console_handler)
    
    # Usunięcie domyślnego basic config
    logging.getLogger().handlers.clear()
    
    return app_logger

def get_limiter_key():
    """Pobiera klucz dla limitera - obsługuje proxy headers"""
    from flask import request
    
    # Sprawdź nagłówki proxy
    forwarded_ips = request.headers.get('X-Forwarded-For')
    if forwarded_ips:
        return forwarded_ips.split(',')[0].strip()
    
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    return request.remote_addr or 'unknown'

def create_app():
    """Tworzy i konfiguruje aplikację Flask"""
    # Ładowanie zmiennych środowiskowych
    load_dotenv(override=True)
    
    # Konfiguracja logowania
    app_logger = setup_logging()
    logger = logging.getLogger(__name__)
    
    # Tworzenie aplikacji Flask
    app = Flask(__name__)
    
    # Konfiguracja Flask-Limiter z storage z .env
    storage_url = os.getenv('RATE_LIMIT_STORAGE_URL', 'memory://')
    limiter = Limiter(
        app=app,
        key_func=get_limiter_key,
        storage_uri=storage_url,
        default_limits=[
            os.getenv('DEFAULT_RATE_LIMIT', '100') + ' per hour',
            '1000 per day'
        ],
        strategy="moving-window"
    )
    
    # Inicjalizacja security manager
    security = SecurityManager()
    app.secret_key = security.get_secret_key()
    
    # KRYTYCZNE: Sprawdzenie wymagań SSL dla produkcji
    ssl_check = security.validate_ssl_production_requirements()
    if not ssl_check['can_start']:
        app_logger.critical("BŁĄD KRYTYCZNY SSL:")
        app_logger.critical(ssl_check['reason'])
        app_logger.critical("Aplikacja zostanie zatrzymana!")
        raise RuntimeError(f"SSL SECURITY ERROR: {ssl_check['reason']}")
    else:
        app_logger.info(f"SSL Status: {ssl_check['reason']}")
    
    # Sprawdzenie wygaśnięcia certyfikatu SSL (tylko jeśli certyfikat istnieje)
    cert_status = security.check_certificate_expiry()
    if cert_status['status'] == 'expired':
        app_logger.critical(f"CERTYFIKAT SSL WYGASŁ: {cert_status['message']}")
    elif cert_status['status'] == 'critical':
        app_logger.critical(f"CERTYFIKAT SSL: {cert_status['message']}")
    elif cert_status['status'] == 'warning':
        app_logger.warning(f"CERTYFIKAT SSL: {cert_status['message']}")
    elif cert_status['status'] == 'valid':
        app_logger.info(f"CERTYFIKAT SSL: {cert_status['message']}")
    elif cert_status['status'] == 'missing':
        app_logger.info(f"CERTYFIKAT SSL: {cert_status['message']}")
    elif cert_status['status'] == 'error':
        app_logger.warning(f"CERTYFIKAT SSL: {cert_status['message']}")
    
    # Ustawienie bezpiecznych uprawnień plików SSL
    ssl_perms = security.secure_ssl_file_permissions()
    if ssl_perms:
        app_logger.info("Uprawnienia plików SSL zostały zabezpieczone")
    else:
        app_logger.warning("Nie udało się zabezpieczyć uprawnień plików SSL")
    
    # Konfiguracja podstawowych ustawień Flask
    configure_flask_settings(app)
    
    # Inicjalizacja komponentów bezpieczeństwa
    security = SecurityManager(app)
    
    # KRYTYCZNE: Wymuś ustawienie hasła administratora
    admin_password_hash = os.getenv('ADMIN_PASSWORD_HASH')
    if not admin_password_hash:
        app_logger.critical("BŁĄD KRYTYCZNY: ADMIN_PASSWORD_HASH nie został ustawiony w pliku .env!")
        app_logger.critical("Aplikacja nie może działać bez bezpiecznego hasła administratora.")
        app_logger.critical("Ustaw ADMIN_PASSWORD_HASH w pliku .env i uruchom aplikację ponownie.")
        raise RuntimeError(
            "KRYTYCZNY BŁĄD BEZPIECZEŃSTWA: Brak hasła administratora w konfiguracji. "
            "Ustaw ADMIN_PASSWORD_HASH w pliku .env przed uruchomieniem aplikacji."
        )
    
    # Inicjalizacja komponentów
    try:
        jira_api = JiraAPI()
        classifier = ProblemClassifier()
        app_logger.info("Komponenty aplikacji zainicjalizowane pomyślnie")
    except Exception as e:
        app_logger.exception(f"Błąd inicjalizacji komponentów aplikacji: {e}")
        sys.exit(1)
    
    # Zwróć aplikację i komponenty
    return app, security, limiter, jira_api, classifier, app_logger

def configure_flask_settings(app):
    """Konfiguruje podstawowe ustawienia Flask"""
    from flask import request, redirect
    
    # Bezpieczna konfiguracja
    app.secret_key = os.getenv('FLASK_SECRET_KEY')
    if not app.secret_key:
        logger = logging.getLogger(__name__)
        logger.warning("FLASK_SECRET_KEY nie został ustawiony. Generuję losowy klucz sesji.")
        app.secret_key = secrets.token_hex(32)  # Generuje 64-znakowy hex string (32 bajty)
        logger.info("Wygenerowano losowy klucz sesji dla bieżącej sesji aplikacji.")
    
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    
    # JSON encoding for Polish characters
    app.config['JSON_AS_ASCII'] = False  # Allow non-ASCII characters in JSON
    app.config['JSON_SORT_KEYS'] = False  # Preserve key order
    
    # Enhanced Session Security - dopasowane do konfiguracji proxy
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
    app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('ADMIN_SESSION_TIMEOUT', 7200)))
    
    # Security headers
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    
    # Konfiguracja HTTPS i SSL - przed requestem
    @app.before_request
    def force_https():
        """Wymusza przekierowanie na HTTPS jeśli włączone w konfiguracji"""
        force_https_enabled = os.getenv('FORCE_HTTPS_REDIRECT', 'False').lower() == 'true'
        
        # Sprawdź nagłówki proxy - jeśli już jesteśmy za HTTPS proxy, nie przekierowuj
        if request.headers.get('X-Forwarded-Proto') == 'https':
            return
        
        if force_https_enabled and not request.is_secure:
            # Nie przekierowuj dla localhost w developmencie
            if request.host.startswith('localhost') or request.host.startswith('127.0.0.1'):
                return
                
            # Dla proxy, użyj oryginalnego hosta z nagłówka
            forwarded_host = request.headers.get('X-Forwarded-Host', request.host)
            forwarded_port = request.headers.get('X-Forwarded-Port', '443')
            
            # Przekieruj na HTTPS z odpowiednim portem
            if forwarded_port == '443':
                url = f"https://{forwarded_host}{request.path}"
            else:
                url = f"https://{forwarded_host}:{forwarded_port}{request.path}"
                
            if request.query_string:
                url += f"?{request.query_string.decode()}"
                
            logger = logging.getLogger(__name__)
            logger.info(f"Przekierowanie HTTP->HTTPS: {request.url} -> {url}")
            return redirect(url, code=301)
    
    @app.after_request
    def set_security_headers(response):
        """Ustawia nagłówki bezpieczeństwa - dopasowane do proxy HTTP"""
        # Podstawowe nagłówki bezpieczeństwa
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # HSTS tylko gdy HTTPS jest wymagane
        https_only = os.getenv('HTTPS_ONLY', 'False').lower() == 'true'
        if https_only and (request.is_secure or os.getenv('FORCE_HTTPS_REDIRECT', 'False').lower() == 'true'):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # Cache control dla wrażliwych stron
        if request.endpoint in ['admin_login', 'get_rules', 'add_rule', 'edit_rule', 'export_csv']:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response

def configure_ssl_production():
    """Konfiguruje SSL dla trybu produkcyjnego"""
    # Konfiguracja SSL/HTTPS z zabezpieczeniami produkcyjnymi
    ssl_enabled = os.getenv('SSL_ENABLED', 'False').lower() == 'true'
    ssl_cert_path = os.getenv('SSL_CERT_PATH', 'ssl/pl.mcd.com.pem')
    ssl_key_path = os.getenv('SSL_KEY_PATH', 'ssl/pl.mcd.com.key')
    
    # Bezpieczne pobieranie hasła SSL
    from security import SecurityManager
    security_manager = SecurityManager()
    ssl_cert_password = security_manager.get_secure_env_value('SSL_CERT_PASSWORD')
    
    ssl_port = int(os.getenv('SSL_PORT', '443'))
    
    # Bezpieczna konfiguracja SSL Context
    ssl_context = None
    if ssl_enabled:
        if os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
            try:
                import ssl
                
                # Utwórz bezpieczny kontekst SSL
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                
                # Ładowanie certyfikatu z hasłem jeśli jest wymagane
                if ssl_cert_password:
                    ssl_context.load_cert_chain(ssl_cert_path, ssl_key_path, ssl_cert_password)
                    logger = logging.getLogger(__name__)
                    logger.info("SSL: Używam hasła do certyfikatu z bezpiecznego magazynu")
                else:
                    ssl_context.load_cert_chain(ssl_cert_path, ssl_key_path)
                    logger = logging.getLogger(__name__)
                    logger.info("SSL: Ładuję certyfikat bez hasła")
                
                # Konfiguracja bezpieczeństwa SSL
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
                ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3  # Maximum TLS 1.3
                
                # Bezpieczne cipher suites
                cipher_suite = os.getenv('SSL_CIPHER_SUITE', 
                    'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS')
                ssl_context.set_ciphers(cipher_suite)
                
                # Dodatkowe opcje bezpieczeństwa
                ssl_context.options |= ssl.OP_NO_SSLv2
                ssl_context.options |= ssl.OP_NO_SSLv3
                ssl_context.options |= ssl.OP_NO_TLSv1
                ssl_context.options |= ssl.OP_NO_TLSv1_1
                ssl_context.options |= ssl.OP_SINGLE_DH_USE
                ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
                
                logger = logging.getLogger(__name__)
                logger.info(f"SSL bezpiecznie skonfigurowany - certyfikat: {ssl_cert_path}")
                logger.info("SSL Security: TLS 1.2+, bezpieczne cipher suites")
                
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Błąd konfiguracji SSL Context: {e}")
                ssl_context = None
                
        elif os.path.exists(ssl_cert_path):
            logger = logging.getLogger(__name__)
            logger.warning(f"Znaleziono certyfikat SSL {ssl_cert_path}, ale brakuje klucza prywatnego {ssl_key_path}")
            logger.warning("SSL zostanie wyłączony. Aby włączyć HTTPS, dodaj plik klucza prywatnego.")
            ssl_context = None
        else:
            logger = logging.getLogger(__name__)
            logger.warning("Pliki SSL nie zostały znalezione. Aplikacja uruchomi się bez HTTPS.")
            ssl_context = None
    
    return ssl_context, ssl_port