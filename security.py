#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecurityManager - centralne zarządzanie bezpieczeństwem aplikacji.
"""

import os
import secrets
import logging
from datetime import datetime
from flask import request, session, g
from security_auth import AuthenticationManager
from security_validation import ValidationManager

# Stała walidacji kategorii
try:
    from classifier import ALLOWED_CATEGORY_CHARS
except ImportError:
    import string
    ALLOWED_CATEGORY_CHARS = string.ascii_letters + string.digits + "_- /," + "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ"

# Logger z obsługą UTF-8 dla Windows
sec_logger = logging.getLogger('security')
sec_logger.setLevel(logging.INFO)

import sys
if sys.platform == 'win32':
    try:
        console_handler = logging.StreamHandler(sys.stdout)
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, OSError):
        import codecs
        console_handler = logging.StreamHandler(
            codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
        )
else:
    console_handler = logging.StreamHandler()

console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
sec_logger.addHandler(console_handler)

class SecurityManager:
    """Centralne zarządzanie bezpieczeństwem aplikacji."""
    
    def __init__(self, app=None):
        self.app = app
        self.auth_manager = AuthenticationManager()
        self.validation_manager = ValidationManager()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Konfiguracja zabezpieczeń Flask."""
        self.app = app
        
        # Konfiguracja sesji
        app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
        app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
        app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
        app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('PERMANENT_SESSION_LIFETIME', 28800))
        
        # Limit rozmiaru uploadów
        app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
        
        # Nagłówki bezpieczeństwa
        @app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # CSP z nonce
            nonce = None
            try:
                nonce = getattr(g, 'csp_nonce', None)
            except Exception:
                pass
            
            if nonce:
                response.headers['Content-Security-Policy'] = (
                    f"default-src 'self'; "
                    f"script-src 'self' 'nonce-{nonce}' https://cdn.plot.ly; "
                    f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    f"img-src 'self' data:; "
                    f"font-src 'self' https://fonts.gstatic.com; "
                    f"connect-src 'self'; "
                    f"form-action 'self'; "
                    f"frame-ancestors 'none'; "
                    f"object-src 'none'; "
                    f"base-uri 'self'; "
                    f"upgrade-insecure-requests; "
                    f"block-all-mixed-content"
                )
            else:
                # Fallback CSP - gdy nonce nie jest dostępne
                response.headers['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://cdn.plot.ly; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "img-src 'self' data:; "
                    "font-src 'self' https://fonts.gstatic.com; "
                    "connect-src 'self'; "
                    "form-action 'self'; "
                    "frame-ancestors 'none'; "
                    "object-src 'none'; "
                    "base-uri 'self'; "
                    "upgrade-insecure-requests; "
                    "block-all-mixed-content"
                )
            
            # Cache Control dla bezpieczeństwa
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            # HSTS dla HTTPS (lub gdy wymuszony)
            if request.is_secure or os.getenv('FORCE_HTTPS_REDIRECT', 'False').lower() == 'true':
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                
                # Enhanced CSP - wymagaj jawnego ustawienia w .env
                csp_report_only_env = os.getenv('CONTENT_SECURITY_POLICY_REPORT_ONLY')
                if csp_report_only_env is None:
                    raise RuntimeError(
                        "KRYTYCZNY BŁĄD KONFIGURACJI: CONTENT_SECURITY_POLICY_REPORT_ONLY musi być jawnie "
                        "ustawiony w pliku .env (True lub False). Brak domyślnej wartości ze względów bezpieczeństwa."
                    )
                
                csp_report_only = csp_report_only_env.lower() == 'true'
                csp_header = 'Content-Security-Policy-Report-Only' if csp_report_only else 'Content-Security-Policy'
                
                response.headers[csp_header] = (
                    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; "
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.plot.ly https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com; "
                    "img-src 'self' data: https: blob:; "
                    "connect-src 'self'; "
                    "form-action 'self'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'self'; "
                    "object-src 'none'"
                )
                
                # Cache control for sensitive pages
                if request.endpoint in ['admin_login', 'get_rules', 'add_rule', 'edit_rule']:
                    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                    response.headers['Pragma'] = 'no-cache'
                    response.headers['Expires'] = '0'
            
            return response
        
        # Enhanced request validation
        @app.before_request
        def validate_request():
            # Generowanie nonce dla każdego żądania
            g.csp_nonce = self.validation_manager.generate_csp_nonce()
            
            # Walidacja parametrów URL (query string)
            if request.args and len(request.args) > 0:
                query_validation = self.validation_manager.validate_query_parameters(request.args)
                if not query_validation['valid']:
                    # Loguj błędne parametry, ale nie blokuj żądania (delikatna walidacja)
                    for error in query_validation['errors']:
                        sec_logger.warning(f"Suspicious query parameter: {error}")
                    # Możemy dodać flash message dla administratora
                    if session.get('admin_authenticated'):
                        from flask import flash
                        flash(f"Wykryto podejrzane parametry URL: {', '.join(query_validation['errors'])}", 'warning')
            
            # Host header validation - wymagaj jawnego ustawienia w .env
            host_validation_env = os.getenv('ENABLE_HOST_VALIDATION')
            if host_validation_env is None:
                raise RuntimeError(
                    "KRYTYCZNY BŁĄD KONFIGURACJI: ENABLE_HOST_VALIDATION musi być jawnie "
                    "ustawiony w pliku .env (True lub False). Brak domyślnej wartości ze względów bezpieczeństwa."
                )
                
            host_validation_enabled = host_validation_env.lower() == 'true'
            
            # W trybie development wyłącz walidację hostów dla localhost
            flask_env = os.getenv('FLASK_ENV', 'development').lower()
            if flask_env == 'development' and (not request.host or 
                request.host.startswith('localhost') or request.host.startswith('127.0.0.1')):
                # Pomiń walidację hostów dla lokalnego developmentu
                pass
            elif host_validation_enabled:
                allowed_hosts = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
                allowed_hosts = [host.strip() for host in allowed_hosts if host.strip()]
                
                request_host = request.host.split(':')[0] if request.host else None
                if request_host and not self.validation_manager.is_host_allowed(request_host, allowed_hosts):
                    self.auth_manager.log_security_event('invalid_host', self.auth_manager.get_client_ip(), f"Host: {request.host}")
                    from flask import abort
                    abort(400, "Invalid host header")
            
            # Walidacja aktywności sesji
            result = self.auth_manager.validate_session_activity()
            if result:
                return result  # Redirect w przypadku wylogowania
    
    # ===== DELEGACJA DO KOMPONENTÓW =====
    
    # Autoryzacja i uwierzytelnianie
    def get_client_ip(self):
        return self.auth_manager.get_client_ip()
    
    def log_security_event(self, event_type, client_ip, details=""):
        return self.auth_manager.log_security_event(event_type, client_ip, details)
    
    def generate_csrf_token(self):
        return self.auth_manager.generate_csrf_token()
    
    def validate_csrf_token(self, token):
        return self.auth_manager.validate_csrf_token(token)
    
    def require_csrf(self, f):
        return self.auth_manager.require_csrf(f)
    
    def rate_limit(self, max_requests=5, window=60):
        return self.auth_manager.rate_limit(max_requests, window)
    
    def is_admin_authenticated(self):
        return self.auth_manager.is_admin_authenticated()
    
    def require_admin(self, f):
        return self.auth_manager.require_admin(f)
    
    def authenticate_admin(self, username, password):
        return self.auth_manager.authenticate_admin(username, password)
    
    def logout_admin(self):
        return self.auth_manager.logout_admin()
    
    # Walidacja i SSL
    def generate_csp_nonce(self):
        return self.validation_manager.generate_csp_nonce()
    
    def validate_text_input(self, text, field_name="Pole", min_length=0, max_length=1000, allow_html=False):
        return self.validation_manager.validate_text_input(text, field_name, min_length, max_length, allow_html)
    
    def validate_file_path(self, file_path, allowed_dirs):
        return self.validation_manager.validate_file_path(file_path, allowed_dirs)
    
    def sanitize_and_validate_form_data(self, form_data):
        return self.validation_manager.sanitize_and_validate_form_data(form_data)
    
    def validate_date_range(self, start_date_str, end_date_str, max_days=365):
        return self.validation_manager.validate_date_range(start_date_str, end_date_str, max_days)
    
    def validate_query_parameters(self, args):
        return self.validation_manager.validate_query_parameters(args)
    
    def sanitize_csv_dataframe(self, df):
        return self.validation_manager.sanitize_csv_dataframe(df)
    
    def validate_rule_data(self, rule_name, keywords_str, combinations_str, forbidden_str, min_score_str):
        return self.validation_manager.validate_rule_data(rule_name, keywords_str, combinations_str, forbidden_str, min_score_str)
    
    def is_host_allowed(self, request_host, allowed_hosts):
        return self.validation_manager.is_host_allowed(request_host, allowed_hosts)
    
    def validate_ssl_production_requirements(self):
        return self.validation_manager.validate_ssl_production_requirements()
    
    def check_certificate_expiry(self):
        return self.validation_manager.check_certificate_expiry()
    
    def secure_ssl_file_permissions(self):
        return self.validation_manager.secure_ssl_file_permissions()
    
    # ===== KLUCZOWE METODY ZACHOWANE =====
    
    def get_secret_key(self):
        """Pobiera bezpieczny klucz sesji Flask"""
        secret_key = os.getenv('FLASK_SECRET_KEY')
        
        if secret_key:
            return secret_key
        
        # Generuj tymczasowy klucz dla sesji development
        flask_env = os.getenv('FLASK_ENV', 'development').lower()
        if flask_env == 'development':
            temp_key = secrets.token_hex(32)
            sec_logger.warning("FLASK_SECRET_KEY nie został ustawiony. Generuję tymczasowy klucz dla sesji development.")
            sec_logger.warning("W produkcji MUSISZ ustawić FLASK_SECRET_KEY w pliku .env!")
            return temp_key
        else:
            # W produkcji wymagaj jawnego ustawienia klucza
            raise RuntimeError(
                "KRYTYCZNY BŁĄD BEZPIECZEŃSTWA: FLASK_SECRET_KEY nie został ustawiony w pliku .env. "
                "Jest to wymagane w środowisku produkcyjnym!"
            )
    
    def get_secure_env_value(self, env_var_name):
        """
        Pobiera bezpieczną wartość ze zmiennej środowiskowej
        Obsługuje zarówno zaszyfrowane jak i niezaszyfrowane wartości
        """
        try:
            # Sprawdź zaszyfrowaną wersję
            encrypted_var = f"{env_var_name}_ENCRYPTED"
            encrypted_value = os.getenv(encrypted_var)
            
            if encrypted_value:
                try:
                    # Dla hasła SSL używamy dedykowanego menedżera
                    if env_var_name == 'SSL_CERT_PASSWORD':
                        from ssl_security import ssl_security_manager
                        return ssl_security_manager.decrypt_ssl_password(encrypted_value)
                    
                    # Dla innych wartości (np. JIRA_TOKEN, ADMIN_PASSWORD_HASH)
                    # możemy dodać ogólny system szyfrowania w przyszłości
                    sec_logger.warning(f"Zaszyfrowana wersja {encrypted_var} nie jest jeszcze obsługiwana")
                    
                except Exception as decrypt_error:
                    sec_logger.warning(f"Nie można odszyfrować {encrypted_var}: {decrypt_error}")
            
            # Fallback na niezaszyfrowaną wersję
            plain_value = os.getenv(env_var_name)
            if plain_value:
                if env_var_name in ['SSL_CERT_PASSWORD', 'JIRA_TOKEN']:
                    sec_logger.warning(f"BEZPIECZEŃSTWO: Używam niezaszyfrowanej wartości {env_var_name}. Zaszyfruj ją!")
                return plain_value
            
            return None
            
        except Exception as e:
            sec_logger.error(f"Błąd pobierania bezpiecznej wartości {env_var_name}: {e}")
            return None

# Globalna instancja
security_manager = SecurityManager()