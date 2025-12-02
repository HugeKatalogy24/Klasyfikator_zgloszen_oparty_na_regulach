#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Naprawiony moduł bezpieczeństwa SSL - szyfrowanie i zarządzanie hasłami SSL
"""

import os
import base64
import secrets
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Konfiguracja loggera
ssl_security_logger = logging.getLogger('ssl_security')
ssl_security_logger.setLevel(logging.INFO)

class SSLSecurityManager:
    """Klasa zarządzająca bezpieczeństwem haseł SSL"""
    
    def __init__(self):
        self.master_key_env = 'SSL_MASTER_KEY'
        self.salt_env = 'SSL_ENCRYPTION_SALT'
    
    def _derive_key(self, master_key_b64, salt_b64):
        """Wyprowadza klucz szyfrowania z klucza głównego i salt"""
        try:
            master_key_bytes = base64.urlsafe_b64decode(master_key_b64.encode())
            salt_bytes = base64.urlsafe_b64decode(salt_b64.encode())
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,  # Bezpieczna liczba iteracji
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(master_key_bytes))
            return key
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd wyprowadzania klucza: {e}")
            raise ValueError(f"Nie można wyprowadzić klucza szyfrowania: {e}")
    
    def encrypt_ssl_password_with_keys(self, plain_password, master_key_b64, salt_b64):
        """Szyfruje hasło SSL z podanymi kluczami"""
        try:
            if not plain_password:
                raise ValueError("Hasło nie może być puste")
            
            derived_key = self._derive_key(master_key_b64, salt_b64)
            fernet = Fernet(derived_key)
            
            encrypted_password = fernet.encrypt(plain_password.encode())
            # UWAGA: fernet.encrypt już zwraca bytes, nie kodujemy dodatkowo w base64
            encrypted_b64 = base64.urlsafe_b64encode(encrypted_password).decode()
            
            ssl_security_logger.info("Hasło SSL zostało zaszyfrowane pomyślnie")
            return encrypted_b64
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd szyfrowania hasła SSL: {e}")
            raise
    
    def decrypt_ssl_password_with_keys(self, encrypted_password_b64, master_key_b64, salt_b64):
        """Odszyfrowuje hasło SSL z podanymi kluczami"""
        try:
            if not encrypted_password_b64:
                return None
            
            derived_key = self._derive_key(master_key_b64, salt_b64)
            fernet = Fernet(derived_key)
            
            # Dekoduj dane - Fernet.decrypt() oczekuje bytes
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_password_b64.encode())
            
            # Odszyfruj bezpośrednio
            decrypted_password = fernet.decrypt(encrypted_bytes).decode()
            
            ssl_security_logger.info("Hasło SSL zostało odszyfrowane pomyślnie")
            return decrypted_password
            
            ssl_security_logger.info("Hasło SSL zostało odszyfrowane pomyślnie")
            return decrypted_password
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd odszyfrowywania hasła SSL: {e}")
            raise
    
    def encrypt_ssl_password(self, plain_password):
        """Szyfruje hasło SSL - generuje nowe klucze jeśli nie istnieją"""
        try:
            # Sprawdź czy klucze już istnieją
            master_key = os.getenv(self.master_key_env)
            salt = os.getenv(self.salt_env)
            
            if not master_key:
                master_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
                ssl_security_logger.warning(f"Wygenerowano nowy klucz główny SSL: {master_key}")
            
            if not salt:
                salt_bytes = secrets.token_bytes(16)
                salt = base64.urlsafe_b64encode(salt_bytes).decode()
                ssl_security_logger.warning(f"Wygenerowano nowy salt SSL: {salt}")
            
            encrypted = self.encrypt_ssl_password_with_keys(plain_password, master_key, salt)
            
            return {
                'master_key': master_key,
                'salt': salt,
                'encrypted': encrypted
            }
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd szyfrowania hasła SSL: {e}")
            raise
    
    def decrypt_ssl_password(self, encrypted_password):
        """Odszyfrowuje hasło SSL używając kluczy z środowiska"""
        try:
            master_key = os.getenv(self.master_key_env)
            salt = os.getenv(self.salt_env)
            
            if not master_key or not salt:
                raise ValueError(f"Brak klucza głównego lub salt w zmiennych środowiskowych")
            
            return self.decrypt_ssl_password_with_keys(encrypted_password, master_key, salt)
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd odszyfrowywania hasła SSL: {e}")
            raise
    
    def get_ssl_password(self):
        """Pobiera hasło SSL - najpierw próbuje zaszyfrowaną wersję, potem plain text"""
        try:
            # Sprawdź zaszyfrowaną wersję
            encrypted_password = os.getenv('SSL_CERT_PASSWORD_ENCRYPTED')
            if encrypted_password:
                try:
                    return self.decrypt_ssl_password(encrypted_password)
                except Exception as decrypt_error:
                    ssl_security_logger.warning(f"Nie można odszyfrować hasła SSL: {decrypt_error}")
                    ssl_security_logger.warning("Próbuję użyć niezaszyfrowanej wersji jako fallback")
            
            # Fallback na niezaszyfrowaną wersję (do usunięcia po migracji)
            plain_password = os.getenv('SSL_CERT_PASSWORD')
            if plain_password:
                ssl_security_logger.warning("BEZPIECZEŃSTWO: Używam niezaszyfrowanego hasła SSL. Zaszyfruj je jak najszybciej!")
                return plain_password
            
            return None
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd pobierania hasła SSL: {e}")
            return None
    
    def migrate_ssl_password(self):
        """Migruje niezaszyfrowane hasło SSL do wersji zaszyfrowanej"""
        try:
            plain_password = os.getenv('SSL_CERT_PASSWORD')
            if not plain_password:
                ssl_security_logger.info("Brak hasła SSL do migracji")
                return False
            
            # Zaszyfruj hasło
            result = self.encrypt_ssl_password(plain_password)
            
            print("\n=== MIGRACJA HASŁA SSL ===")
            print("1. Dodaj te linie do pliku .env:")
            print(f"SSL_MASTER_KEY={result['master_key']}")
            print(f"SSL_ENCRYPTION_SALT={result['salt']}")
            print(f"SSL_CERT_PASSWORD_ENCRYPTED={result['encrypted']}")
            print("\n2. Usuń lub zakomentuj starą linię:")
            print(f"# SSL_CERT_PASSWORD={plain_password}")
            print("\n3. Uruchom aplikację ponownie")
            print("\nUWAGA: Zapisz klucze w bezpiecznym miejscu jako backup!")
            
            ssl_security_logger.info("Migracja hasła SSL przygotowana")
            return True
            
        except Exception as e:
            ssl_security_logger.error(f"Błąd migracji hasła SSL: {e}")
            return False

# Globalna instancja
ssl_security_manager = SSLSecurityManager()

def test_encryption_complete():
    """Kompletny test szyfrowania i odszyfrowywania"""
    print("=== TEST KOMPLETNEGO PROCESU SZYFROWANIA ===")
    
    manager = SSLSecurityManager()
    test_password = "64dkjjsiT90niSD428923dsvz54bwAR13JAaza8dSJNMASdf2ajkqj23m"
    
    try:
        # 1. Zaszyfruj hasło
        result = manager.encrypt_ssl_password(test_password)
        print(f"✅ Szyfrowanie udane")
        print(f"Master key: {result['master_key']}")
        print(f"Salt: {result['salt']}")
        print(f"Encrypted: {result['encrypted'][:50]}...")
        
        # 2. Odszyfruj używając tych samych kluczy
        decrypted = manager.decrypt_ssl_password_with_keys(
            result['encrypted'], 
            result['master_key'], 
            result['salt']
        )
        
        if decrypted == test_password:
            print(f"✅ Odszyfrowywanie udane: {decrypted[:20]}...")
            print("\n=== WARTOŚCI DO .env ===")
            print(f"SSL_MASTER_KEY={result['master_key']}")
            print(f"SSL_ENCRYPTION_SALT={result['salt']}")
            print(f"SSL_CERT_PASSWORD_ENCRYPTED={result['encrypted']}")
        else:
            print(f"❌ Odszyfrowywanie nieudane: {decrypted[:20]}...")
            
    except Exception as e:
        print(f"❌ Błąd: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_encryption_complete()
