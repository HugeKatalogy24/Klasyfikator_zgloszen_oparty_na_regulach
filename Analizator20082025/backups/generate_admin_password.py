#!/usr/bin/env python3
"""
Skrypt do generowania hasła administratora dla aplikacji
Użyj tego skryptu do wygenerowania bezpiecznego hashu hasła
"""

import getpass
from werkzeug.security import generate_password_hash

def main():
    print("🔐 Generator hasła administratora")
    print("=" * 40)
    
    # Pobierz hasło od użytkownika
    password = getpass.getpass("Wprowadź hasło administratora: ")
    
    if len(password) < 8:
        print("❌ Hasło musi mieć co najmniej 8 znaków!")
        return
    
    # Wygeneruj hash
    password_hash = generate_password_hash(password)
    
    print("\n✅ Hash hasła został wygenerowany!")
    print("=" * 40)
    print("Dodaj następującą linię do pliku .env:")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    print("\n⚠️  UWAGA: Przechowuj ten hash bezpiecznie i nie udostępniaj go!")
    print("💡 Zaleca się używanie silnych haseł z cyframi, literami i symbolami.")

if __name__ == "__main__":
    main()
