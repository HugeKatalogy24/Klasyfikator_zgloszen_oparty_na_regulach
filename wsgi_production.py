#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TODO: Production only - disabled for localhost thesis presentation
=== PLIK PRODUKCYJNY - WYŁĄCZONY ===

Ten plik zawiera konfigurację produkcyjną z Waitress dla domeny analizator.pl.mcd.com
Dla prezentacji pracy inżynierskiej używamy tylko trybu development (python app.py)

WSGI Entry Point dla aplikacji Analizator Problemów Jira - PRODUKCJA SSL
Konfiguracja produkcyjna z Waitress dla domeny analizator.pl.mcd.com
"""

# === CAŁY KOD PRODUKCYJNY ZAKOMENTOWANY ===
# Aby przywrócić funkcjonalność produkcyjną, odkomentuj poniższy kod

# import os
# import sys
# import logging
# from pathlib import Path
# 
# # Dodaj katalog aplikacji do ścieżki Python
# app_dir = Path(__file__).parent
# sys.path.insert(0, str(app_dir))
# 
# # Ustaw zmienne środowiskowe dla produkcji SSL
# os.environ['FLASK_ENV'] = 'production'
# os.environ['FLASK_DEBUG'] = 'False'
# 
# # Konfiguracja logowania dla WSGI
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     handlers=[
#         logging.FileHandler(r'C:\AnalizatorProblemowJira\Analizator\logs\wsgi.log', encoding='utf-8'),
#         logging.StreamHandler(sys.stdout)
#     ]
# )
# 
# logger = logging.getLogger(__name__)
# 
# try:
#     # Import aplikacji Flask
#     from app import app
#     
#     # Konfiguracja dla Waitress
#     application = app
#     
#     logger.info("✅ WSGI aplikacja załadowana pomyślnie")
#     logger.info("🌐 Domena: analizator.pl.mcd.com")
#     logger.info("🔒 SSL: Obsługiwany przez Nginx")
#     
# except Exception as e:
#     logger.error(f"❌ Błąd ładowania aplikacji WSGI: {e}")
#     raise
# 
# def create_waitress_server():
#     """Tworzy serwer Waitress z optymalną konfiguracją"""
#     from waitress import serve
#     
#     logger.info("🚀 Uruchamianie serwera Waitress...")
#     logger.info("   📍 Host: 127.0.0.1 (tylko localhost - Nginx proxy)")
#     logger.info("   📍 Port: 8001")
#     logger.info("   🔒 SSL: Obsługiwany przez Nginx reverse proxy")
#     logger.info("   🌐 Zewnętrzny dostęp: https://analizator.pl.mcd.com")
#     
#     try:
#         serve(
#             application,
#             host='127.0.0.1',          # Tylko localhost - bezpieczne za proxy
#             port=8001,                 # Port wewnętrzny dla Waitress
#             threads=12,                # Zwiększona liczba wątków dla lepszej wydajności
#             connection_limit=1000,     # Limit połączeń
#             cleanup_interval=30,       # Interwał czyszczenia (sekundy)
#             channel_timeout=15000,       # Timeout kanału - 5 minut dla długich analiz
#             log_socket_errors=True,    # Logowanie błędów socket
#             asyncore_use_poll=True,    # Używaj poll() zamiast select() - lepsze dla Windows
#             url_scheme='https',        # Informuj aplikację o HTTPS (przez proxy)
#             
#             # Dodatkowe ustawienia bezpieczeństwa
#             send_bytes=65536,          # Rozmiar bufora wysyłania
#             recv_bytes=65536,          # Rozmiar bufora odbioru
#             expose_tracebacks=False,   # Nie pokazuj szczegółów błędów w produkcji
#             
#             # Ustawienia dla reverse proxy
#             trusted_proxy='127.0.0.1', # Zaufaj Nginx na localhost
#             trusted_proxy_headers=['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto'],
#             clear_untrusted_proxy_headers=True
#         )
#     except Exception as e:
#         logger.error(f"❌ Błąd uruchamiania serwera Waitress: {e}")
#         raise
# 
# if __name__ == '__main__':
#     # Sprawdź podstawowe wymagania
#     ssl_cert_path = r'C:\AnalizatorProblemowJira\Analizator\ssl\pl.mcd.com.pem'
#     ssl_key_path = r'C:\AnalizatorProblemowJira\Analizator\ssl\pl.mcd.com_decrypted.key'
#     logs_dir = r'C:\AnalizatorProblemowJira\Analizator\logs'
#     
#     if not os.path.exists(ssl_cert_path):
#         logger.error(f"❌ BŁĄD: Brak certyfikatu SSL {ssl_cert_path}")
#         sys.exit(1)
#     
#     if not os.path.exists(ssl_key_path):
#         logger.error(f"❌ BŁĄD: Brak klucza SSL {ssl_key_path}")
#         sys.exit(1)
#     
#     logger.info("✅ Pliki SSL znalezione")
#     
#     # Utwórz katalog logów jeśli nie istnieje
#     os.makedirs(logs_dir, exist_ok=True)
#     
#     # Uruchom serwer
#     create_waitress_server()

print("⚠️  Ten plik jest wyłączony dla prezentacji pracy inżynierskiej.")
print("Użyj: python app.py")
