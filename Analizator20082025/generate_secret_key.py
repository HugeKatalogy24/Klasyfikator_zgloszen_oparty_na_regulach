#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt do generowania bezpiecznego klucza sesji Flask

Użycie:
    python generate_secret_key.py
    
Wygeneruje bezpieczny 64-znakowy klucz hex, który można użyć jako FLASK_SECRET_KEY
"""

import secrets

def generate_flask_secret_key():
    """Generuje bezpieczny klucz sesji Flask"""
    # Generuj 32 bajty (256 bitów) losowych danych
    key = secrets.token_hex(32)
    return key

if __name__ == "__main__":
    print("=== Generator klucza sesji Flask ===")
    print()
    
    # Generuj klucz
    secret_key = generate_flask_secret_key()
    
    print(f"Wygenerowany klucz sesji:")
    print(f"FLASK_SECRET_KEY={secret_key}")
    print()
    
    print("Instrukcje:")
    print("1. Skopiuj powyższy klucz do pliku .env")
    print("2. Dodaj linię: FLASK_SECRET_KEY=<wygenerowany_klucz>")
    print("3. Uruchom ponownie aplikację")
    print()
    
    print("⚠️  WAŻNE:")
    print("- Zachowaj ten klucz w bezpiecznym miejscu")
    print("- Nie udostępniaj go publicznie")
    print("- Zmiana klucza spowoduje wylogowanie wszystkich użytkowników")
    print("- Używaj różnych kluczy dla różnych środowisk (dev/prod)")
