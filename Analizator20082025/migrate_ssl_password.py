#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt migracji hasła SSL do wersji zaszyfrowanej
Uruchom: python migrate_ssl_password.py
"""

import os
import sys
from dotenv import load_dotenv

# Dodaj ścieżkę aplikacji
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Załaduj zmienne środowiskowe
load_dotenv()

# Import naszego modułu SSL Security
from ssl_security import ssl_security_manager

def main():
    """Główna funkcja migracji"""
    print("=== MIGRACJA HASŁA SSL DO WERSJI ZASZYFROWANEJ ===\n")
    
    # Sprawdź czy hasło SSL istnieje
    current_password = os.getenv('SSL_CERT_PASSWORD')
    if not current_password:
        print("❌ Brak hasła SSL w pliku .env (SSL_CERT_PASSWORD)")
        print("Nie ma nic do migracji.")
        return False
    
    # Sprawdź czy już istnieje zaszyfrowana wersja
    encrypted_password = os.getenv('SSL_CERT_PASSWORD_ENCRYPTED')
    if encrypted_password:
        print("⚠️  Zaszyfrowana wersja hasła już istnieje!")
        print("Sprawdź czy konfiguracja jest prawidłowa.")
        
        # Test odszyfrowywania
        try:
            decrypted = ssl_security_manager.get_ssl_password()
            if decrypted == current_password:
                print("✅ Zaszyfrowane hasło jest prawidłowe")
                print("\nMożesz teraz usunąć niezaszyfrowaną wersję:")
                print("# SSL_CERT_PASSWORD=...")
                return True
            else:
                print("❌ Zaszyfrowane hasło nie pasuje do aktualnego!")
                print("Sprawdź konfigurację kluczy szyfrowania.")
                return False
        except Exception as e:
            print(f"❌ Błąd testowania zaszyfrowanego hasła: {e}")
            return False
    
    print(f"🔍 Znaleziono niezaszyfrowane hasło SSL (długość: {len(current_password)} znaków)")
    
    # Wykonaj migrację
    try:
        success = ssl_security_manager.migrate_ssl_password()
        if success:
            print("\n✅ Migracja zakończona pomyślnie!")
            print("\n🔒 NASTĘPNE KROKI:")
            print("1. Skopiuj wygenerowane linie do pliku .env")
            print("2. Uruchom aplikację i sprawdź czy działa")
            print("3. Jeśli wszystko działa, usuń starą linię SSL_CERT_PASSWORD")
            print("4. Zapisz klucze szyfrowania w bezpiecznym miejscu jako backup")
            
            # Test czy nowa konfiguracja działa
            print("\n🧪 Test nowej konfiguracji...")
            try:
                # Symuluj nowe środowisko
                test_password = ssl_security_manager.get_ssl_password()
                if test_password:
                    print("✅ Test pozytywny - nowa konfiguracja działa")
                else:
                    print("⚠️  Test negatywny - sprawdź konfigurację")
            except Exception as test_error:
                print(f"⚠️  Błąd testu: {test_error}")
            
            return True
        else:
            print("❌ Migracja nie powiodła się")
            return False
            
    except Exception as e:
        print(f"❌ Błąd migracji: {e}")
        return False

def backup_env_file():
    """Tworzy kopię zapasową pliku .env"""
    try:
        import shutil
        from datetime import datetime
        
        env_file = ".env"
        if os.path.exists(env_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f".env.backup_{timestamp}"
            shutil.copy2(env_file, backup_file)
            print(f"📁 Utworzono kopię zapasową: {backup_file}")
            return True
        else:
            print("⚠️  Plik .env nie istnieje")
            return False
    except Exception as e:
        print(f"❌ Błąd tworzenia kopii zapasowej: {e}")
        return False

if __name__ == "__main__":
    print("🛡️  Rozpoczynam migrację hasła SSL...")
    
    # Utwórz kopię zapasową
    print("\n📋 Tworzenie kopii zapasowej pliku .env...")
    backup_env_file()
    
    # Wykonaj migrację
    print("\n🔐 Migracja hasła...")
    success = main()
    
    if success:
        print("\n🎉 Migracja zakończona pomyślnie!")
        print("Pamiętaj o zapisaniu kluczy szyfrowania w bezpiecznym miejscu!")
    else:
        print("\n💥 Migracja nie powiodła się. Sprawdź błędy powyżej.")
        sys.exit(1)
