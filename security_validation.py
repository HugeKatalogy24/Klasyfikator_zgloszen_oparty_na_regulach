#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Moduł walidacji danych wejściowych i zarządzania SSL.
"""

import os
import re
import logging
import secrets
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd

val_logger = logging.getLogger('security_validation')
val_logger.setLevel(logging.INFO)

class ValidationManager:
    """Zarządzanie walidacją danych i bezpieczeństwem."""
    
    def __init__(self):
        pass
    
    def generate_csp_nonce(self):
        """Generuje nonce dla CSP."""
        return secrets.token_urlsafe(16)
    
    def validate_text_input(self, text, field_name="Pole", min_length=0, max_length=1000, allow_html=False):
        """Waliduje dane tekstowe z konfigurowalnymi parametrami."""
        errors = []
        
        # Sprawdź czy tekst jest podany
        if not text and min_length > 0:
            errors.append(f"{field_name} jest wymagane")
            return {'valid': False, 'errors': errors, 'text': ''}
        
        # Konwertuj na string jeśli to nie jest
        if not isinstance(text, str):
            text = str(text)
        
        # Sprawdź długość
        if len(text) < min_length:
            errors.append(f"{field_name} musi mieć co najmniej {min_length} znaków")
        
        if len(text) > max_length:
            errors.append(f"{field_name} nie może być dłuższe niż {max_length} znaków")
        
        # Sprawdź na potencjalne zagrożenia bezpieczeństwa
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'<iframe[^>]*>',
            r'<embed[^>]*>',
            r'<object[^>]*>',
        ]
        
        if not allow_html:
            for pattern in dangerous_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    errors.append(f"{field_name} zawiera niedozwolone elementy")
                    break
        
        # Usuń potencjalnie niebezpieczne znaki (zachowaj polskie znaki)
        # Dozwolone: litery (łącznie z polskimi), cyfry, podstawowa interpunkcja, spacje
        safe_text = re.sub(r'[^\w\s\-.,:/()[\]{}+=*&%$#@!?;áćęłńóśźżĄĆĘŁŃÓŚŹŻ]', '', text)
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'text': safe_text.strip()
        }
    
    def validate_file_path(self, file_path, allowed_dirs):
        """Waliduje ścieżkę pliku (ochrona przed path traversal)."""
        try:
            normalized_path = os.path.normpath(file_path)
            
            if '..' in normalized_path:
                val_logger.warning(f"Path traversal attempt detected: {file_path}")
                return False
            
            abs_file_path = os.path.abspath(normalized_path)
            
            for allowed_dir in allowed_dirs:
                abs_allowed_dir = os.path.abspath(allowed_dir)
                if abs_file_path.startswith(abs_allowed_dir):
                    return True
            
            val_logger.warning(f"File path outside allowed directories: {file_path}")
            return False
            
        except Exception as e:
            val_logger.error(f"Error validating file path {file_path}: {e}")
            return False
    
    def sanitize_and_validate_form_data(self, form_data):
        """Sanityzuje i waliduje dane formularza."""
        sanitized_data = {}
        errors = []
        
        for key, value in form_data.items():
            if not re.match(r'^[a-zA-Z0-9_\-]+$', key):
                errors.append(f"Nieprawidłowa nazwa pola: {key}")
                continue
            
            if isinstance(value, str):
                if len(value) > 10000:
                    errors.append(f"Wartość pola {key} zbyt długa")
                    continue
                
                sanitized_value = value.strip()
                sanitized_value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized_value)
                
                sanitized_data[key] = sanitized_value
            else:
                sanitized_data[key] = str(value).strip()
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'data': sanitized_data
        }
    
    def validate_date_range(self, start_date_str, end_date_str, max_days=365):
        """Waliduje zakres dat."""
        errors = []
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            
            if start_date > end_date:
                errors.append("Data początkowa nie może być późniejsza niż data końcowa")
            
            date_diff = (end_date - start_date).days
            if date_diff > max_days:
                errors.append(f"Zakres dat nie może być większy niż {max_days} dni")
            
            today = datetime.now().date()
            if end_date > today:
                errors.append("Data końcowa nie może być z przyszłości")
            
            oldest_allowed = today - timedelta(days=365*2)  # Max 2 lata wstecz
            if start_date < oldest_allowed:
                errors.append("Data początkowa nie może być starsza niż 2 lata")
            
        except ValueError:
            errors.append("Nieprawidłowy format daty. Użyj formatu YYYY-MM-DD")
        
        return errors
    
    def validate_query_parameters(self, args):
        """Waliduje parametry URL query string."""
        errors = []
        suspicious_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}',  # Double URL encoding
            r'\.\./|\.\.\\\\',  # Path traversal
            r'union\s+select',  # SQL injection
            r'script\s*:',  # Script protocol
        ]
        
        for key, value in args.items():
            if len(key) > 100:
                errors.append(f"Zbyt długa nazwa parametru: {key[:20]}...")
            
            if len(str(value)) > 1000:
                errors.append(f"Zbyt długa wartość parametru {key}: {str(value)[:20]}...")
            
            combined_param = f"{key}={value}"
            for pattern in suspicious_patterns:
                if re.search(pattern, combined_param, re.IGNORECASE):
                    errors.append(f"Podejrzany parametr: {key}")
                    break
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
    
    def sanitize_csv_dataframe(self, df):
        """Sanityzuje DataFrame przed eksportem CSV."""
        df_clean = df.copy()
        
        # Sanityzacja kolumn tekstowych
        for col in df_clean.select_dtypes(include=['object']).columns:
            df_clean[col] = df_clean[col].astype(str).apply(
                lambda x: re.sub(r'^[@+\-]', '', str(x))  # Usunięcie znaków formuł
            ).apply(
                lambda x: re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', str(x))
            ).apply(
                lambda x: x.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
            )
        
        return df_clean
    
    def validate_rule_data(self, rule_name, keywords_str, combinations_str, forbidden_str, min_score_str):
        """Waliduje dane reguły klasyfikacji."""
        errors = []
        
        # Nazwa reguły
        name_validation = self.validate_text_input(rule_name, "Nazwa reguły", min_length=1, max_length=100)
        if not name_validation['valid']:
            errors.extend(name_validation['errors'])
        
        # Słowa kluczowe
        if not keywords_str or not keywords_str.strip():
            errors.append("Słowa kluczowe są wymagane")
        else:
            keywords_validation = self.validate_text_input(keywords_str, "Słowa kluczowe", min_length=1, max_length=1000)
            if not keywords_validation['valid']:
                errors.extend(keywords_validation['errors'])
        
        # Min score
        try:
            min_score = int(min_score_str)
            if min_score < 1 or min_score > 20:
                errors.append("Minimalny wynik musi być między 1 a 20")
        except (ValueError, TypeError):
            errors.append("Minimalny wynik musi być liczbą całkowitą")
        
        # Kombinacje (opcjonalne)
        if combinations_str and combinations_str.strip():
            combinations_validation = self.validate_text_input(combinations_str, "Kombinacje wymagane", max_length=2000)
            if not combinations_validation['valid']:
                errors.extend(combinations_validation['errors'])
        
        # Słowa zabronione (opcjonalne)
        if forbidden_str and forbidden_str.strip():
            forbidden_validation = self.validate_text_input(forbidden_str, "Słowa zabronione", max_length=1000)
            if not forbidden_validation['valid']:
                errors.extend(forbidden_validation['errors'])
        
        return errors
    
    def is_host_allowed(self, request_host, allowed_hosts):
        """Sprawdza czy host jest dozwolony."""
        return request_host in allowed_hosts
    
    def validate_ssl_production_requirements(self):
        """Waliduje wymagania SSL dla produkcji."""
        flask_env = os.getenv('FLASK_ENV', 'development').lower()
        
        if flask_env != 'production':
            return {
                'can_start': True,
                'reason': f'Tryb {flask_env} - sprawdzenie SSL pominięte'
            }
        
        cert_path = os.getenv('SSL_CERT_PATH', 'ssl/pl.mcd.com.crt')
        key_path = os.getenv('SSL_KEY_PATH', 'ssl/pl.mcd.com.key')
        
        if not os.path.exists(cert_path):
            return {
                'can_start': False,
                'reason': f'BŁĄD KRYTYCZNY: Brak certyfikatu SSL: {cert_path}'
            }
        
        if not os.path.exists(key_path):
            return {
                'can_start': False,
                'reason': f'BŁĄD KRYTYCZNY: Brak klucza prywatnego SSL: {key_path}'
            }
        
        return {
            'can_start': True,
            'reason': 'SSL prawidłowo skonfigurowany'
        }
    
    def check_certificate_expiry(self):
        """Sprawdza datę wygaśnięcia certyfikatu SSL."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            cert_path = os.getenv('SSL_CERT_PATH', 'ssl/pl.mcd.com.crt')
            
            if not os.path.exists(cert_path):
                return {'status': 'missing', 'message': f'Certyfikat nie istnieje: {cert_path}'}
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            expiry_date = cert.not_valid_after
            current_date = datetime.now()
            
            days_until_expiry = (expiry_date - current_date).days
            warning_days = int(os.getenv('SSL_EXPIRY_WARNING_DAYS', '30'))
            critical_days = int(os.getenv('SSL_EXPIRY_CRITICAL_DAYS', '7'))
            
            if days_until_expiry < 0:
                return {
                    'status': 'expired',
                    'message': f'Certyfikat wygasł {abs(days_until_expiry)} dni temu!',
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry
                }
            elif days_until_expiry <= critical_days:
                return {
                    'status': 'critical',
                    'message': f'KRYTYCZNE: Certyfikat wygaśnie za {days_until_expiry} dni!',
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry
                }
            elif days_until_expiry <= warning_days:
                return {
                    'status': 'warning',
                    'message': f'OSTRZEŻENIE: Certyfikat wygaśnie za {days_until_expiry} dni',
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry
                }
            else:
                return {
                    'status': 'valid',
                    'message': f'Certyfikat ważny przez {days_until_expiry} dni',
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry
                }
                
        except Exception as e:
            val_logger.exception(f"Błąd sprawdzania wygaśnięcia certyfikatu: {e}")
            return {'status': 'error', 'message': f'Błąd sprawdzania certyfikatu: {str(e)}'}
    
    def secure_ssl_file_permissions(self):
        """Ustawia bezpieczne uprawnienia dla plików SSL (Unix)."""
        try:
            cert_path = os.getenv('SSL_CERT_PATH', 'ssl/pl.mcd.com.crt')
            key_path = os.getenv('SSL_KEY_PATH', 'ssl/pl.mcd.com.key')
            
            success = True
            
            if os.path.exists(cert_path):
                try:
                    os.chmod(cert_path, 0o644)
                    val_logger.info(f"Ustawiono uprawnienia 644 dla certyfikatu: {cert_path}")
                except OSError as e:
                    val_logger.warning(f"Nie można ustawić uprawnień dla certyfikatu: {e}")
                    success = False
            
            if os.path.exists(key_path):
                try:
                    os.chmod(key_path, 0o600)
                    val_logger.info(f"Ustawiono uprawnienia 600 dla klucza: {key_path}")
                except OSError as e:
                    val_logger.warning(f"Nie można ustawić uprawnień dla klucza: {e}")
                    success = False
            
            return success
            
        except Exception as e:
            val_logger.exception(f"Błąd ustawiania uprawnień SSL: {e}")
            return False

# Globalna instancja dla kompatybilności
validation_manager = ValidationManager()
