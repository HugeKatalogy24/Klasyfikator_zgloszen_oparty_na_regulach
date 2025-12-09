#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Moduł autoryzacji i zarządzania sesjami.
"""

import os
import secrets
import functools
import time
import logging
from flask import session, request, abort, flash, redirect, url_for, jsonify
from werkzeug.security import check_password_hash

auth_logger = logging.getLogger('security_auth')
auth_logger.setLevel(logging.INFO)

class AuthenticationManager:
    """Zarządzanie uwierzytelnianiem i autoryzacją."""
    
    def __init__(self):
        self.failed_attempts = {}  # IP -> (count, last_attempt)
        self.admin_sessions = {}   # session_id -> (user, expiry)
    
    def get_client_ip(self):
        """Pobiera IP klienta (obsługuje proxy)."""
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        return request.remote_addr or 'unknown'
    
    def log_security_event(self, event_type, client_ip, details=""):
        """Logowanie zdarzeń bezpieczeństwa."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] SECURITY EVENT: {event_type} | IP: {client_ip}"
        if details:
            log_message += f" | Details: {details}"
        
        if event_type in ['admin_login_failed', 'csrf_violation', 'rate_limit_exceeded', 'admin_login_rate_limit_exceeded']:
            auth_logger.warning(log_message)
        elif event_type in ['admin_login_success', 'admin_logout']:
            auth_logger.info(log_message)
        else:
            auth_logger.info(log_message)
    
    def generate_csrf_token(self):
        """Generuje token CSRF."""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return session['csrf_token']
    
    def validate_csrf_token(self, token):
        """Waliduje token CSRF."""
        session_token = session.get('csrf_token')
        
        if not token:
            auth_logger.debug("CSRF: brak tokenu")
            return False
            
        if not session_token:
            auth_logger.debug("CSRF: brak tokenu sesji")
            return False
            
        tokens_match = token == session_token
        if not tokens_match:
            auth_logger.debug(f"CSRF: niezgodność tokenów")
        else:
            auth_logger.debug("CSRF validation successful")
            
        return tokens_match
    
    def require_csrf(self, f):
        """Dekorator wymuszający walidację CSRF."""
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
        """Dekorator limitujący liczbę żądań."""
        def decorator(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                client_ip = self.get_client_ip()
                current_time = time.time()
                
                # Restrykcyjne limity dla logowania admina
                if f.__name__ == 'admin_login':
                    admin_max_requests = 10
                    admin_window = 900  # 15 minut
                    
                    admin_key = f"admin_login_{client_ip}"
                    self.failed_attempts = {
                        key: (count, timestamp) for key, (count, timestamp) 
                        in self.failed_attempts.items() 
                        if current_time - timestamp < (admin_window if key.startswith('admin_login_') else window)
                    }
                    
                    if admin_key in self.failed_attempts:
                        count, first_attempt = self.failed_attempts[admin_key]
                        if count >= admin_max_requests:
                            remaining_time = int(admin_window - (current_time - first_attempt))
                            self.log_security_event('admin_login_rate_limit_exceeded', client_ip, 
                                                  f"Exceeded {admin_max_requests} login attempts")
                            auth_logger.warning(f"Admin login rate limit exceeded for IP {client_ip}. "
                                             f"Blocking for {remaining_time} more seconds.")
                            abort(429, f"Too many login attempts. Try again in {remaining_time} seconds.")
                    
                    if request.method == 'POST':
                        if admin_key in self.failed_attempts:
                            count, first_attempt = self.failed_attempts[admin_key]
                            self.failed_attempts[admin_key] = (count + 1, first_attempt)
                        else:
                            self.failed_attempts[admin_key] = (1, current_time)
                    
                    return f(*args, **kwargs)
                
                # Standardowy rate limiting
                self.failed_attempts = {
                    key: (count, timestamp) for key, (count, timestamp) 
                    in self.failed_attempts.items() 
                    if current_time - timestamp < window
                }
                
                if client_ip in self.failed_attempts:
                    count, _ = self.failed_attempts[client_ip]
                    if count >= max_requests:
                        self.log_security_event('rate_limit_exceeded', client_ip)
                        abort(429, "Too many requests")
                
                if client_ip in self.failed_attempts:
                    count, _ = self.failed_attempts[client_ip]
                    self.failed_attempts[client_ip] = (count + 1, current_time)
                else:
                    self.failed_attempts[client_ip] = (1, current_time)
                
                return f(*args, **kwargs)
            return decorated
        return decorator
    
    def is_admin_authenticated(self):
        """Sprawdza czy użytkownik jest zalogowany jako admin."""
        if not session.get('admin_authenticated'):
            return False
        
        login_time = session.get('admin_login_time', 0)
        session_timeout = int(os.getenv('ADMIN_SESSION_TIMEOUT', 7200))  # 2h domyślnie
        
        if time.time() - login_time > session_timeout:
            self.logout_admin()
            return False
        
        return True
    
    def require_admin(self, f):
        """Dekorator wymuszający uprawnienia administratora."""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not self.is_admin_authenticated():
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
        """Uwierzytelnia administratora."""
        try:
            client_ip = self.get_client_ip()
            
            expected_username = os.getenv('ADMIN_USERNAME', 'admin')
            expected_password_hash = os.getenv('ADMIN_PASSWORD_HASH')
            
            if not expected_password_hash:
                auth_logger.critical("ADMIN_PASSWORD_HASH nie został ustawiony w .env")
                auth_logger.critical("Aplikacja nie może działać bez silnego hasła administratora")
                self.log_security_event('admin_login_critical_error', client_ip, "Missing ADMIN_PASSWORD_HASH")
                return False
            
            if username != expected_username:
                self.log_security_event('admin_login_failed', client_ip, "Invalid username provided")
                auth_logger.warning(f"Admin login failed for IP {client_ip}: invalid username")
                return False
            
            try:
                password_valid = check_password_hash(expected_password_hash, password)
            except Exception as hash_error:
                auth_logger.error(f"Błąd weryfikacji hasła dla IP {client_ip}: {hash_error}")
                self.log_security_event('admin_login_error', client_ip, f"Hash verification failed")
                return False
            
            if password_valid:
                # Rotacja sesji
                session.clear()
                
                session['admin_authenticated'] = True
                session['admin_login_time'] = time.time()
                session['admin_session_id'] = secrets.token_hex(32)
                session['last_activity'] = time.time()
                session['last_session_rotation'] = time.time()
                session.permanent = True
                
                # Wyczyść rate limiting po sukcesie
                admin_key = f"admin_login_{client_ip}"
                if admin_key in self.failed_attempts:
                    del self.failed_attempts[admin_key]
                if client_ip in self.failed_attempts:
                    del self.failed_attempts[client_ip]
                
                self.log_security_event('admin_login_success', client_ip, f"User: {username}")
                auth_logger.info(f"Admin login successful for IP {client_ip}, user: {username}")
                return True
            else:
                self.log_security_event('admin_login_failed', client_ip, "Invalid credentials")
                auth_logger.warning(f"Admin login failed for IP {client_ip}: invalid password")
                return False
                
        except Exception as e:
            auth_logger.exception(f"Unexpected error during admin authentication for IP {client_ip}: {e}")
            self.log_security_event('admin_login_error', client_ip, f"Unexpected error: {str(e)}")
            return False
    
    def logout_admin(self):
        """Wylogowuje administratora."""
        try:
            client_ip = self.get_client_ip()
            username = session.get('admin_username', 'unknown')
            
            self.log_security_event('admin_logout', client_ip, f"User: {username}")
            auth_logger.info(f"Admin logout for IP {client_ip}, user: {username}")
            
            session.clear()
            
        except Exception as e:
            auth_logger.exception(f"Error during admin logout: {e}")
    
    def validate_session_activity(self):
        """Waliduje aktywność sesji i rotuje klucze."""
        if session.get('admin_authenticated') and os.getenv('AUTO_LOGOUT_INACTIVE', 'True').lower() == 'true':
            if request.endpoint != 'admin_login':
                last_activity = session.get('last_activity', 0)
                inactive_timeout = int(os.getenv('INACTIVE_LOGOUT_TIME', 1800))
                if time.time() - last_activity > inactive_timeout:
                    self.logout_admin()
                    flash('Sesja wygasła z powodu braku aktywności.', 'warning')
                    return redirect(url_for('admin_login'))
            session['last_activity'] = time.time()
        
        # Rotacja sesji co 30 minut
        if session.get('admin_authenticated'):
            last_rotation = session.get('last_session_rotation', 0)
            if time.time() - last_rotation > 1800:
                session.permanent = True
                session['last_session_rotation'] = time.time()
                self.log_security_event('admin_session_rotation', self.get_client_ip())
        
        return None

# Globalna instancja dla kompatybilności
auth_manager = AuthenticationManager()