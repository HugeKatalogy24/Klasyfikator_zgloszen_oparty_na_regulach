#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Główny punkt wejścia aplikacji Flask - Analizator Problemów Jira
Zrefaktoryzowany na modułową strukturę dla lepszej organizacji kodu
"""

import os
import sys
import socket
import logging

# Import modułów konfiguracji i routów
from app_config import create_app, configure_ssl_production
from app_core import register_routes

def main():
    """Główna funkcja uruchamiająca aplikację"""
    try:
        # Tworzenie aplikacji i komponentów
        app, security, limiter, jira_api, classifier, app_logger = create_app()
        
        # Rejestracja routów
        register_routes(app, security, limiter, jira_api, classifier, app_logger)
        
        # Jeśli uruchamiany bezpośrednio (nie przez WSGI)
        if __name__ == '__main__':
            # Sprawdź tryb aplikacji
            flask_env = os.getenv('FLASK_ENV', 'development').lower()
            
            if flask_env == 'development':
                # Tryb development - bez SSL, localhost tylko
                app_logger.info("=== TRYB DEVELOPMENT - BEZ SSL ===")
                app_logger.info("Aplikacja dostępna pod adresami:")
                app_logger.info("   • Lokalnie: http://localhost:5001")
                app_logger.info("   • Panel admina: http://localhost:5001/admin/login")
                app_logger.info("   • SSL/HTTPS: WYŁĄCZONY (development mode)")
                
                # Uruchom bez SSL
                app.run(
                    debug=True,  # Włącz debug w development
                    host='127.0.0.1',  # Tylko localhost w development
                    port=5001,  # Zmiana portu na 5001
                    threaded=True,
                    use_reloader=False  # Wyłącz auto-reload żeby uniknąć spamu z .venv
                )
            else:
                # Tryb produkcyjny - z SSL
                ssl_context, ssl_port = configure_ssl_production()
                
                # Konfiguracja dla udostępnienia w sieci lokalnej
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                # Wybierz port i protokół
                port = ssl_port if ssl_context else 5000
                protocol = "https" if ssl_context else "http"
                
                app_logger.info("=== TRYB PRODUKCYJNY ===")
                app_logger.info("Aplikacja dostępna pod adresami:")
                app_logger.info(f"   • Lokalnie: {protocol}://localhost:{port}")
                app_logger.info(f"   • W sieci lokalnej: {protocol}://{local_ip}:{port}")
                app_logger.info(f"   • Wszystkie interfejsy: {protocol}://0.0.0.0:{port}")
                
                if ssl_context:
                    app_logger.info("   • SSL/HTTPS: WŁĄCZONY [OK]")
                    ssl_cert_path = os.getenv('SSL_CERT_PATH', 'ssl/pl.mcd.com.pem')
                    app_logger.info(f"   • Certyfikat: {ssl_cert_path}")
                else:
                    app_logger.warning("   • SSL/HTTPS: WYŁĄCZONY [WARNING]")
                
            
            app_logger.info("Udostępnij kolegom adres IP w sieci lokalnej (tylko w trybie produkcyjnym)")
            app_logger.info("Panel administracyjny: /admin/login (login: admin)")
            
            # Uruchom aplikację
            if flask_env != 'development':
                # Tryb produkcyjny z konfiguracją SSL
                app.run(
                    debug=False,  # Wyłącz debug dla bezpieczeństwa
                    host='0.0.0.0',  # Nasłuchuj na wszystkich interfejsach
                    port=port,  # Port aplikacji (443 dla HTTPS, 5000 dla HTTP)
                    threaded=True,  # Obsługa wielu użytkowników jednocześnie
                    use_reloader=False,  # Wyłącz auto-reload
                    ssl_context=ssl_context  # Kontekst SSL jeśli dostępny
                )
        
        return app
        
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.critical(f"Krytyczny błąd uruchamiania aplikacji: {e}")
        sys.exit(1)

# Eksport aplikacji dla WSGI
app = main()

if __name__ == '__main__':
    main()