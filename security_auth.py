#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł autoryzacji i zarządzania sesjami
Wydzielony z security.py dla lepszej organizacji kodu
"""

import os
import secrets
import functools
import time
import logging
from flask import session, request, abort, flash, redirect, url_for, jsonify
from werkzeug.security import check_password_hash

# Konfiguracja loggera dla autoryzacji
auth_logger = logging.getLogger('security_auth')
auth_logger.setLevel(logging.INFO)

class AuthenticationManager:
    """Klasa zarządzająca uwierzytelnianiem i autoryzacją"""
    
    def __init__(self):
        self.failed_attempts = {}  # IP -> (count, last_attempt) dla rate limiting
        self.admin_sessions = {}   # session_id -> (user, expiry)
    
    def get_client_ip(self):
        """Pobiera rzeczywisty IP klienta obsługując proxy headers"""
        # Sprawdź nagłówki proxy w kolejności ważności
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # X-Forwarded-For może zawierać listę IP oddzielonych przecinkami
            # Pierwsze IP to pierwotny klient
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fallback na standardowy remote_addr
        return request.remote_addr or 'unknown'
    
    def log_security_event(self, event_type, client_ip, details=""):
        """Loguje zdarzenia bezpieczeństwa"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] SECURITY EVENT: {event_type} | IP: {client_ip}"
        if details:
            log_message += f" | Details: {details}"
        
        # Loguj na podstawie typu zdarzenia
        if event_type in ['admin_login_failed', 'csrf_violation', 'rate_limit_exceeded', 'admin_login_rate_limit_exceeded']:
            auth_logger.warning(log_message)
        elif event_type in ['admin_login_success', 'admin_logout']:
            auth_logger.info(log_message)
        else:
            auth_logger.info(log_message)
    
    def generate_csrf_token(self):
        """Generuje token CSRF"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def validate_csrf_token(self, token):
        """Waliduje token CSRF z dodatkowym debugowaniem"""
        session_token = session.get('csrf_token')
        
        if not token:
            auth_logger.debug("CSRF validation failed: no token provided")
            return False
            
        if not session_token:
            auth_logger.debug("CSRF validation failed: no session token")
            return False
            
        tokens_match = token == session_token
        if not tokens_match:
            auth_logger.debug(f"CSRF validation failed: tokens don't match. Form: {token[:20]}..., Session: {session_token[:20]}...")
        else:
            auth_logger.debug("CSRF validation successful")
            
        return tokens_match
    
    def require_csrf(self, f):
        """Dekorator wymagający ważnego tokenu CSRF"""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'POST':
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not self.validate_csrf_token(token):
                    self.log_security_event('csrf_violation', self.get_client_ip())
                    abort(403, "CSRF token mismatch")
            return f(*args, **kwargs)
        return decorated
    
    def rate_limit(self, max_requests=5, window=60):
        """Dekorator rate limiting z obsługą specjalnych limitów dla admin_login"""
        def decorator(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                client_ip = self.get_client_ip()
                current_time = time.time()
                
                # Specjalne limity dla admin_login - bardziej restrykcyjne
                if f.__name__ == 'admin_login':
                    # 10 prób logowania na 15 minut (900 sekund)
                    admin_max_requests = 10
                    admin_window = 900
                    
                    # Czyść stare wpisy dla admin_login
                    admin_key = f"admin_login_{client_ip}"
                    self.failed_attempts = {
                        key: (count, timestamp) for key, (count, timestamp) 
                        in self.failed_attempts.items() 
                        if current_time - timestamp < (admin_window if key.startswith('admin_login_') else window)
                    }
                    
                    # Sprawdź limit dla admin_login
                    if admin_key in self.failed_attempts:
                        count, first_attempt = self.failed_attempts[admin_key]
                        if count >= admin_max_requests:
                            remaining_time = int(admin_window - (current_time - first_attempt))
                            self.log_security_event('admin_login_rate_limit_exceeded', client_ip, 
                                                  f"Exceeded {admin_max_requests} login attempts")
                            auth_logger.warning(f"Admin login rate limit exceeded for IP {client_ip}. "
                                             f"Blocking for {remaining_time} more seconds.")
                            abort(429, f"Too many login attempts. Try again in {remaining_time} seconds.")
                    
                    # Zwiększ licznik dla admin_login tylko dla POST (rzeczywiste próby logowania)
                    if request.method == 'POST':
                        if admin_key in self.failed_attempts:
                            count, first_attempt = self.failed_attempts[admin_key]
                            self.failed_attempts[admin_key] = (count + 1, first_attempt)
                        else:
                            self.failed_attempts[admin_key] = (1, current_time)
                    
                    return f(*args, **kwargs)
                
                # Standardowy rate limiting dla innych endpointów
                # Czyść stare wpisy
                self.failed_attempts = {
                    key: (count, timestamp) for key, (count, timestamp) 
                    in self.failed_attempts.items() 
                    if current_time - timestamp < window
                }
                
                # Sprawdź limit
                if client_ip in self.failed_attempts:
                    count, _ = self.failed_attempts[client_ip]
                    if count >= max_requests:
                        self.log_security_event('rate_limit_exceeded', client_ip)
                        abort(429, "Too many requests")
                
                # Zwiększ licznik
                if client_ip in self.failed_attempts:
                    count, _ = self.failed_attempts[client_ip]
                    self.failed_attempts[client_ip] = (count + 1, current_time)
                else:
                    self.failed_attempts[client_ip] = (1, current_time)
                
                return f(*args, **kwargs)
            return decorated
        return decorator
    
    def is_admin_authenticated(self):
        """Sprawdza czy użytkownik jest uwierzytelnionym administratorem"""
        if not session.get('admin_authenticated'):
            return False
        
        # Sprawdź czas logowania
        login_time = session.get('admin_login_time', 0)
        session_timeout = int(os.getenv('ADMIN_SESSION_TIMEOUT', 7200))  # 2 godziny domyślnie
        
        if time.time() - login_time > session_timeout:
            self.logout_admin()
            return False
        
        return True
    
    def require_admin(self, f):
        """Dekorator wymagający uprawnień administratora z obsługą JSON responses"""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not self.is_admin_authenticated():
                # Sprawdź czy to request JSON/AJAX lub endpoint zwracający JSON
                is_json_request = (
                    request.is_json or 
                    request.headers.get('Content-Type') == 'application/json' or
                    request.headers.get('Accept', '').startswith('application/json') or
                    'get-rules' in request.endpoint or
                    f.__name__ in ['get_rules']
                )
                
                if is_json_request:
                    return jsonify({
                        'success': False,
                        'error': 'Dostęp ograniczony. Wymagane uwierzytelnienie administratora.',
                        'redirect': url_for('admin_login')
                    }), 401
                
                # Dla zwykłych requestów HTML
                flash('Dostęp ograniczony. Wymagane uwierzytelnienie administratora.', 'error')
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated
    
    def authenticate_admin(self, username, password):
        """Uwierzytelnia administratora z rotacją sesji i bezpiecznym logowaniem"""
        try:
            # Wyczyść ograniczenia rate limiting dla tego IP po udanym logowaniu (zostanie wykonane na końcu)
            client_ip = self.get_client_ip()
            
            expected_username = os.getenv('ADMIN_USERNAME', 'admin')
            expected_password_hash = os.getenv('ADMIN_PASSWORD_HASH')
            
            if not expected_password_hash:
                # KRYTYCZNE: Brak hasła administratora w .env
                auth_logger.critical("ADMIN_PASSWORD_HASH nie został ustawiony w .env")
                auth_logger.critical("Aplikacja nie może działać bez silnego hasła administratora")
                self.log_security_event('admin_login_critical_error', client_ip, "Missing ADMIN_PASSWORD_HASH")
                return False
            
            # Sprawdź czy username się zgadza - BEZ logowania wprowadzonej wartości
            if username != expected_username:
                # BEZPIECZNE logowanie - nie loguj wprowadzonej nazwy użytkownika
                self.log_security_event('admin_login_failed', client_ip, "Invalid username provided")
                auth_logger.warning(f"Admin login failed for IP {client_ip}: invalid username")
                return False
            
            # Sprawdź hasło - BEZ logowania hasła
            try:
                password_valid = check_password_hash(expected_password_hash, password)
            except Exception as hash_error:
                auth_logger.error(f"Błąd weryfikacji hasła dla IP {client_ip}: {hash_error}")
                self.log_security_event('admin_login_error', client_ip, f"Hash verification failed")
                return False
            
            if password_valid:
                # ROTACJA SESJI: Wyczyść starą sesję przed utworzeniem nowej
                session.clear()
                
                # Utwórz bezpieczną nową sesję
                session['admin_authenticated'] = True
                session['admin_login_time'] = time.time()
                session['admin_session_id'] = secrets.token_hex(32)
                session['last_activity'] = time.time()
                session['last_session_rotation'] = time.time()
                session.permanent = True  # Włącz permanent session lifetime
                
                # Wyczyść wszystkie ograniczenia rate limiting po udanym logowaniu
                admin_key = f"admin_login_{client_ip}"
                if admin_key in self.failed_attempts:
                    del self.failed_attempts[admin_key]
                if client_ip in self.failed_attempts:
                    del self.failed_attempts[client_ip]
                
                # BEZPIECZNE logowanie sukcesu - tylko username (już zweryfikowany)
                self.log_security_event('admin_login_success', client_ip, f"User: {username}")
                auth_logger.info(f"Admin login successful for IP {client_ip}, user: {username}")
                return True
            else:
                # BEZPIECZNE logowanie błędu - bez szczegółów hasła
                self.log_security_event('admin_login_failed', client_ip, "Invalid credentials")
                auth_logger.warning(f"Admin login failed for IP {client_ip}: invalid password")
                return False
                
        except Exception as e:
            auth_logger.exception(f"Unexpected error during admin authentication for IP {client_ip}: {e}")
            self.log_security_event('admin_login_error', client_ip, f"Unexpected error: {str(e)}")
            return False
    
    def logout_admin(self):
        """Wylogowuje administratora z bezpiecznym czyszczeniem sesji"""
        try:
            client_ip = self.get_client_ip()
            username = session.get('admin_username', 'unknown')
            
            # Loguj wylogowanie
            self.log_security_event('admin_logout', client_ip, f"User: {username}")
            auth_logger.info(f"Admin logout for IP {client_ip}, user: {username}")
            
            # Wyczyść całą sesję
            session.clear()
            
        except Exception as e:
            auth_logger.exception(f"Error during admin logout: {e}")
    
    def validate_session_activity(self):
        """Waliduje aktywność sesji i rotuje sesje"""
        if session.get('admin_authenticated') and os.getenv('AUTO_LOGOUT_INACTIVE', 'True').lower() == 'true':
            # Pomiń sprawdzanie nieaktywności dla endpointu logowania
            if request.endpoint != 'admin_login':
                last_activity = session.get('last_activity', 0)
                inactive_timeout = int(os.getenv('INACTIVE_LOGOUT_TIME', 1800))
                if time.time() - last_activity > inactive_timeout:
                    self.logout_admin()
                    flash('Sesja wygasła z powodu braku aktywności.', 'warning')
                    return redirect(url_for('admin_login'))
            session['last_activity'] = time.time()
        
        # Session rotation for admin
        if session.get('admin_authenticated'):
            last_rotation = session.get('last_session_rotation', 0)
            if time.time() - last_rotation > 1800:  # 30 minutes
                session.permanent = True
                session['last_session_rotation'] = time.time()
                self.log_security_event('admin_session_rotation', self.get_client_ip())
        
        return None  # Continue with request

# Globalna instancja dla kompatybilności
auth_manager = AuthenticationManager()