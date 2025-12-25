#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Główne routy i logika biznesowa aplikacji Flask.
"""

from flask import render_template, request, flash, redirect, url_for, session, send_file, jsonify, abort, g, Response, stream_with_context
from markupsafe import escape
import pandas as pd
import os
import io
import logging
import threading
import time
import json
from datetime import datetime, date, timedelta
from rules_manager import rules_manager

logger = logging.getLogger(__name__)

# Globalny słownik do śledzenia postępu analiz
analysis_progress = {}

def perform_analysis_background(analysis_id, start_dt, end_dt, start_date_str, end_date_str, jira_api, classifier, logger):
    """Wykonuje analizę w wątku w tle z raportowaniem postępu."""
    try:
        
        data_file = f'data/jira_data_{start_date_str}_{end_date_str}.csv'
        os.makedirs('data', exist_ok=True)
        
        start_time = time.time()
        refresh_data = True
        
        # Początkowy status
        analysis_progress[analysis_id].update({
            'progress': 0,
            'status': 'Sprawdzanie liczby zgłoszeń...',
            'current_count': 0,
            'total_count': 0,
            'eta_seconds': 0
        })
        
        # Pobranie dokładnej liczby zgłoszeń
        logger.info("Pobieranie dokładnej liczby zgłoszeń...")
        estimated_count = jira_api.get_total_issues_count(start_dt, end_dt)
        
        if estimated_count is not None and estimated_count > 0:
            logger.info(f"✓ Dokładna liczba zgłoszeń do pobrania: {estimated_count}")
            # Zaktualizuj frontend z dokładną liczbą
            analysis_progress[analysis_id].update({
                'progress': 1,
                'status': f'Znaleziono {estimated_count} zgłoszeń. Rozpoczynam pobieranie...',
                'current_count': 0,
                'total_count': estimated_count
            })
        else:
            logger.warning("Nie udało się pobrać dokładnej liczby zgłoszeń")
            analysis_progress[analysis_id].update({
                'progress': 1,
                'status': 'Rozpoczynam pobieranie zgłoszeń...',
                'current_count': 0,
                'total_count': 0
            })
        
        if refresh_data or not os.path.exists(data_file):
            logger.info(f"Pobieranie danych z Jira dla okresu {start_date_str} - {end_date_str}")
            
            # KROK 2: Pobieranie danych z raportowaniem postępu
            df = jira_api.fetch_issues_with_progress(start_dt, end_dt, analysis_id, analysis_progress, estimated_count)
            
            if df.empty:
                analysis_progress[analysis_id].update({
                    'completed': True,
                    'error': 'Nie znaleziono zgłoszeń w podanym zakresie dat.',
                    'progress': 100
                })
                return
            
            # Aktualizacja postępu: klasyfikacja
            analysis_progress[analysis_id].update({
                'progress': 88,
                'status': f'Klasyfikacja {len(df)} problemów...',
                'current_count': len(df),
                'total_count': len(df),
                'eta_seconds': 0
            })
            
            logger.info(f"Rozpoczynam klasyfikację {len(df)} problemów")
            classified_data = classifier.classify_issues(df)
            
            # Aktualizacja postępu: zapisywanie
            analysis_progress[analysis_id].update({
                'progress': 95,
                'status': 'Zapisywanie wyników...',
                'eta_seconds': 0
            })
            
            # Sanityzacja i zapisanie danych
            from security_validation import ValidationManager
            security_validator = ValidationManager()
            # Sprawdź czy metoda sanitize_csv_dataframe istnieje
            if hasattr(security_validator, 'sanitize_csv_dataframe'):
                classified_data = security_validator.sanitize_csv_dataframe(classified_data)
            
            # Bezpieczne zapisywanie pliku z obsługą błędów
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Usuń stary plik jeśli istnieje
                    if os.path.exists(data_file):
                        try:
                            os.remove(data_file)
                            logger.info(f"Usunięto istniejący plik: {data_file}")
                        except OSError as e:
                            logger.warning(f"Nie można usunąć istniejącego pliku {data_file}: {e}")
                    
                    # Zapisz nowy plik
                    classified_data.to_csv(data_file, index=False, encoding='utf-8-sig')
                    logger.info(f"Dane zapisane do pliku: {data_file}")
                    break  # Sukces - wyjdź z pętli
                    
                except (PermissionError, OSError) as e:
                    retry_count += 1
                    logger.warning(f"Błąd zapisu pliku (próba {retry_count}/{max_retries}): {e}")
                    
                    if retry_count < max_retries:
                        time.sleep(1)  # Czekaj sekundę przed ponowną próbą
                        # Spróbuj z inną nazwą pliku
                        data_file = f'data/jira_data_{start_date_str}_{end_date_str}_{int(time.time())}.csv'
                        logger.info(f"Próba zapisu z nową nazwą: {data_file}")
                    else:
                        # Ostatnia próba nie powiodła się
                        raise Exception(f"Nie można zapisać pliku po {max_retries} próbach: {e}")
        else:
            logger.info(f"Ładowanie danych z pliku: {data_file}")
            classified_data = pd.read_csv(data_file)
        
        # Zakończenie analizy
        elapsed_time = time.time() - start_time
        
        # Zapisanie informacji o analizie w odpowiednim formacie
        session_data = {
            'last_analysis_file': data_file,
            'analysis_period': f"{start_date_str}_{end_date_str}"
        }
        
        analysis_progress[analysis_id].update({
            'progress': 100,
            'status': f'Analiza zakończona w {elapsed_time:.1f}s',
            'eta_seconds': 0,
            'completed': True,
            'session_data': session_data,
            'redirect_url': f'/results?period={start_date_str}_{end_date_str}&file={data_file}'
        })
        
        logger.info(f"Analiza {analysis_id} zakończona pomyślnie w {elapsed_time:.1f}s")
        
        # Oczyszczenie starych analiz z pamięci (zostaw tylko ostatnie 10)
        if len(analysis_progress) > 10:
            oldest_keys = sorted(analysis_progress.keys())[:len(analysis_progress)-10]
            for key in oldest_keys:
                del analysis_progress[key]
        
    except Exception as e:
        logger.exception(f"Błąd podczas analizy w tle {analysis_id}: {e}")
        analysis_progress[analysis_id].update({
            'completed': True,
            'error': f'Błąd podczas analizy: {str(e)}',
            'progress': 100
        })

def register_routes(app, security, limiter, jira_api, classifier, logger):
    """Rejestracja wszystkich route'ów aplikacji."""
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        # Logowanie błędu limitu
        logger.warning(f"Rate limit exceeded: {e.description} at {request.path}")
        
        # Jeśli to żądanie API lub AJAX (JSON)
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({
                "success": False,
                "error": f"Przekroczono limit zapytań: {e.description}",
                "rate_limit_exceeded": True
            }), 429
            
        # Domyślnie zwracaj HTML dla przeglądarki
        return render_template('error.html', error=f"Przekroczono limit zapytań: {e.description}"), 429

    @app.context_processor
    def inject_security_context():
        """Tokeny bezpieczeństwa dostępne we wszystkich szablonach."""
        return {
            'csrf_token': security.generate_csrf_token(),
            'csp_nonce': getattr(g, 'csp_nonce', None)
        }

    @app.template_filter('to_datetime')
    def to_datetime_filter(date_string):
        """Konwersja stringa daty do datetime."""
        try:
            return datetime.strptime(date_string, '%Y-%m-%d')
        except:
            return datetime.now()

    def get_data_from_session():
        """Wczytuje dane CSV ze ścieżki zapisanej w sesji."""
        data_file_path = session.get('last_analysis_file')
        if not data_file_path:
            return None
        
        # Walidacja ścieżki pliku
        allowed_dirs = [
            os.path.join(os.getcwd(), 'data'),
            os.path.join(os.getcwd(), 'backups'),
            os.getcwd()  # Katalog roboczy
        ]
        
        if not security.validate_file_path(data_file_path, allowed_dirs):
            logger.warning(f"Nieprawidłowa ścieżka pliku: {data_file_path}")
            return None
        
        if not os.path.exists(data_file_path):
            logger.warning(f"Plik nie istnieje: {data_file_path}")
            return None
        
        try:
            return pd.read_csv(data_file_path)
        except Exception as e:
            logger.exception(f"Błąd wczytywania pliku CSV: {data_file_path} - {e}")
            return None

    @app.route('/')
    def index():
        """Renderuje stronę główną z formularzem."""
        if app.debug:
            logger.debug("index() endpoint called")
        
        # Delikatna walidacja parametrów URL dla endpointu głównego
        if request.args:
            query_validation = security.validate_query_parameters(request.args)
            if not query_validation['valid']:
                # Loguj podejrzane parametry, ale nie przerywaj działania
                for error in query_validation['errors']:
                    logger.warning(f"Suspicious query parameter in index: {error}")
        
        # Przekaż dzisiejszą datę i wczorajszą do template dla walidacji
        today = date.today().strftime('%Y-%m-%d')
        yesterday = (date.today() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        # Przekaż aktualne reguły klasyfikacji
        try:
            categories_list = list(rules_manager.get_rules().keys())
            logger.info(f"Wczytano {len(categories_list)} kategorii reguł")
        except Exception as e:
            logger.exception(f"Błąd ładowania reguł klasyfikacji: {e}")
            categories_list = []
        
        return render_template('index.html', 
                                today=today, 
                                yesterday=yesterday, 
                                categories=categories_list,
                                csrf_token=security.generate_csrf_token(),
                                csp_nonce=getattr(g, 'csp_nonce', ''))

    @app.route('/api/analysis-progress/<analysis_id>')
    def get_analysis_progress(analysis_id):
        """Zwraca aktualny postęp analizy"""
        try:
            # Wyczyść stare analizy (starsze niż 1 godzina)
            current_time = time.time()
            stale_analyses = [
                aid for aid, data in analysis_progress.items() 
                if current_time - data.get('start_time', current_time) > 3600
            ]
            for aid in stale_analyses:
                del analysis_progress[aid]
            
            if analysis_id not in analysis_progress:
                logger.warning(f"Nieznany identyfikator analizy: {analysis_id}")
                logger.info(f"Dostępne identyfikatory: {list(analysis_progress.keys())}")
                return jsonify({
                    'success': False,
                    'error': 'Analiza nie została znaleziona lub wygasła. Uruchom nową analizę.',
                    'should_reload': True  # Sygnał dla frontendu żeby odświeżyć stronę
                }), 404
            
            progress_data = analysis_progress[analysis_id]
            
            return jsonify({
                'success': True,
                'progress': progress_data['progress'],
                'status': progress_data['status'],
                'eta_seconds': progress_data.get('eta_seconds', 0),
                'current_count': progress_data.get('current_count', 0),
                'total_count': progress_data.get('total_count', 0),
                'completed': progress_data.get('completed', False),
                'error': progress_data.get('error'),
                'redirect_url': progress_data.get('redirect_url')
            })
            
        except Exception as e:
            logger.exception(f"Błąd podczas pobierania postępu analizy: {e}")
            return jsonify({
                'success': False,
                'error': 'Błąd serwera'
            }), 500

    # === USUNIĘTO: Martwy kod SSE (Server-Sent Events) ===
    # Endpoint /api/analyze-stream został usunięty - nieużywany po rollbacku do polling
    # Jeśli potrzebujesz SSE, sprawdź historię git

    @app.route('/analyze', methods=['POST'])
    @security.require_csrf
    @limiter.limit("100 per 10 minutes")  # Zwiększony limit analiz
    def analyze():
        """Uruchamia analizę w tle i zwraca JSON z identyfikatorem do śledzenia postępu."""
        try:
            # Sanityzacja i walidacja danych formularza
            form_validation = security.sanitize_and_validate_form_data(request.form)
            if not form_validation['valid']:
                return jsonify({
                    'success': False,
                    'errors': form_validation['errors']
                }), 400
            
            form_data = form_validation['data']
            start_date_str = form_data.get('start_date')
            end_date_str = form_data.get('end_date')
            
            # Walidacja obecności dat
            if not start_date_str or not end_date_str:
                return jsonify({
                    'success': False,
                    'errors': ['Proszę wybrać datę początkową i końcową.']
                }), 400
            
            # Walidacja formatu i zakresu dat
            date_errors = security.validate_date_range(start_date_str, end_date_str)
            if date_errors:
                return jsonify({
                    'success': False,
                    'errors': date_errors
                }), 400
            
            # Konwersja dat (już zwalidowanych)
            start_dt = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_dt = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            
            # Sprawdzenie czy komponenty są zainicjalizowane
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'errors': ['Błąd: JiraAPI nie został zainicjalizowany. Sprawdź konfigurację.']
                }), 500
            
            if classifier is None:
                return jsonify({
                    'success': False,
                    'errors': ['Błąd: ProblemClassifier nie został zainicjalizowany.']
                }), 500
            
            # Sprawdź czy reguły są dostępne
            if rules_manager.get_rules_count() == 0:
                logger.warning('Brak reguł klasyfikacji. Dodaj reguły w panelu administratora.')
            
            # Generowanie unikalnego ID analizy
            analysis_id = f"analysis_{int(time.time() * 1000)}"
            
            # Inicjalizacja śledzenia postępu
            analysis_progress[analysis_id] = {
                'progress': 0,
                'status': 'Przygotowywanie analizy...',
                'eta_seconds': 0,
                'completed': False,
                'error': None,
                'start_time': time.time()
            }
            
            # Uruchomienie analizy w tle
            thread = threading.Thread(
                target=perform_analysis_background,
                args=(analysis_id, start_dt, end_dt, start_date_str, end_date_str, jira_api, classifier, logger)
            )
            thread.daemon = True
            thread.start()
            
            # Zwróć JSON z identyfikatorem analizy
            return jsonify({
                'success': True,
                'analysis_id': analysis_id,
                'message': 'Analiza została uruchomiona'
            })
        
        except Exception as e:
            logger.exception(f"Wystąpił błąd krytyczny podczas uruchamiania analizy: {e}")
            return jsonify({
                'success': False,
                'errors': [f'Wystąpił błąd podczas analizy: {str(e)}']
            }), 500

    @app.route('/results')
    def results():
        """Wyświetla wyniki analizy na podstawie parametrów URL"""
        try:
            period = request.args.get('period')
            file_path = request.args.get('file')
            
            if not period or not file_path:
                flash(escape('Brak wymaganych parametrów analizy.'), 'error')
                return redirect(url_for('index'))
            
            # BEZPIECZEŃSTWO: Walidacja ścieżki pliku
            allowed_dirs = [
                os.path.join(os.getcwd(), 'data'),
                os.path.join(os.getcwd(), 'backups'),
                os.getcwd()  # Katalog roboczy
            ]
            
            if not security.validate_file_path(file_path, allowed_dirs):
                logger.error(f"Nieprawidłowa ścieżka pliku wyników: {file_path}")
                flash(escape('Błąd: Nieprawidłowa ścieżka pliku wyników.'), 'error')
                return redirect(url_for('index'))
            
            if not os.path.exists(file_path):
                flash(escape('Plik z wynikami analizy nie istnieje.'), 'error')
                return redirect(url_for('index'))
            
            # Wczytaj dane
            classified_data = pd.read_csv(file_path)
            
            # Zapisanie informacji o analizie w sesji
            session['last_analysis_file'] = file_path
            session['analysis_period'] = period
            
            # Przygotowanie statystyk
            stats = prepare_statistics(classified_data)
            
            # Parsowanie dat z periodu
            try:
                start_date_str, end_date_str = period.split('_')
            except:
                start_date_str = end_date_str = period
            
            return render_template('results.html',
                                 stats=stats,
                                 start_date=start_date_str,
                                 end_date=end_date_str)
        
        except Exception as e:
            logger.exception(f"Błąd podczas wyświetlania wyników: {e}")
            flash(escape('Błąd podczas ładowania wyników analizy.'), 'error')
            return redirect(url_for('index'))

    @app.route('/export_csv')
    def export_csv():
        """Eksportuje ostatnio analizowane dane do pliku CSV."""
        try:
            df = get_data_from_session()
            if df is None:
                flash(escape('Brak danych do wyeksportowania. Proszę najpierw przeprowadzić analizę.'), 'error')
                return redirect(url_for('index'))
            
            # Sprawdzenie dostępnych kolumn
            available_columns = [
                'created', 'key', 'title', 'issue_type', 'site', 'site_name', 
                'category', 'request_type', 'confidence', 'status', 'priority', 'last_update', 
                'team', 'assignee', 'creator', 'organisation', 
                'agent', 'reporter', 'jira_link'
            ]
            export_columns = [col for col in available_columns if col in df.columns]
            
            # Debugowanie kolumn w trybie development
            if os.getenv('FLASK_ENV') == 'development':
                logger.debug(f"Dostępne kolumny w DataFrame: {list(df.columns)}")
                logger.debug(f"Wybrane kolumny do eksportu: {export_columns}")
                if 'confidence' in df.columns:
                    logger.debug(f"Confidence column dtype: {df['confidence'].dtype}")
                    logger.debug(f"Confidence sample values: {df['confidence'].head().tolist()}")

            # Jeśli nie ma kolumny 'site', spróbuj ją wygenerować z 'reporter'
            if 'site' not in df.columns:
                if 'reporter' in df.columns:
                    try:
                        from jira_api import JiraAPI
                        jira = JiraAPI()
                        df['site'] = df['reporter'].apply(lambda x: jira.extract_site_from_reporter(str(x)))
                    except Exception as site_error:
                        logger.warning(f"Problem z generowaniem kolumny 'site': {site_error}")
                        df['site'] = 'Nieznany'
                else:
                    df['site'] = 'Nieznany'
                if 'site' not in export_columns:
                    export_columns.insert(4, 'site')  # Dodaj w odpowiednie miejsce

            # Jeśli nie ma kolumny 'site_name', spróbuj ją wygenerować z 'reporter'
            if 'site_name' not in df.columns:
                if 'reporter' in df.columns:
                    try:
                        from jira_api import JiraAPI
                        jira = JiraAPI()
                        df['site_name'] = df['reporter'].apply(lambda x: jira.extract_site_name_from_reporter(str(x)))
                    except Exception as site_name_error:
                        logger.warning(f"Problem z generowaniem kolumny 'site_name': {site_name_error}")
                        df['site_name'] = 'Nieznana'
                else:
                    df['site_name'] = 'Nieznana'
                if 'site_name' not in export_columns:
                    export_columns.insert(5, 'site_name')  # Dodaj w odpowiednie miejsce

            # Generowanie kolumny "jira_link" z linkami do zgłoszeń Jira
            if 'key' in df.columns:
                jira_domain = "https://sdeskdro.atlassian.net"
                
                # Pobieramy ustawienie języka z konfiguracji
                excel_language = os.getenv('EXCEL_LANGUAGE', 'auto').lower()
                
                def detect_excel_language():
                    """Wykrywa odpowiedni język dla funkcji hyperlink"""
                    if excel_language == 'pl':
                        return True
                    elif excel_language == 'en':
                        return False
                    else:  # auto
                        # Automatyczne wykrywanie na podstawie locale systemu
                        import locale
                        try:
                            system_locale = locale.getdefaultlocale()[0]
                            return system_locale and 'pl' in system_locale.lower()
                        except:
                            # Fallback - sprawdź zmienne środowiskowe
                            lang_vars = [
                                os.getenv('LANG', ''),
                                os.getenv('LANGUAGE', ''),
                                os.getenv('LC_ALL', '')
                            ]
                            return any('pl' in var.lower() for var in lang_vars if var)
                
                is_polish = detect_excel_language()
                
                def create_excel_hyperlink(key):
                    url = f"{jira_domain}/browse/{key}"
                    if is_polish:
                        return f'=HIPERŁĄCZE("{url}";"{key}")'
                    else:
                        return f'=HYPERLINK("{url}";"{key}")'
                
                df['jira_link'] = df['key'].apply(create_excel_hyperlink)
                if 'jira_link' not in export_columns:
                    export_columns.append('jira_link')
                
                function_name = "HIPERŁĄCZE" if is_polish else "HYPERLINK"
                logger.info(f"Dodano kolumnę 'jira_link' z {len(df)} linkami do Jira (funkcja: {function_name}, język: {excel_language})")

            # Przygotowanie danych do eksportu z sanityzacją
            export_df = df[export_columns].copy()
            
            # Debug: sprawdź czy kolumna jira_link istnieje przed renaming
            if 'jira_link' in export_df.columns:
                logger.info("Kolumna 'jira_link' istnieje przed renaming")
                logger.info(f"Przykład linków: {export_df['jira_link'].head(3).tolist()}")
            else:
                logger.warning("Kolumna 'jira_link' nie istnieje przed renaming")
            
            # BEZPIECZEŃSTWO: Sanityzacja danych CSV przed eksportem - z obsługą błędów
            try:
                export_df = security.sanitize_csv_dataframe(export_df)
            except Exception as sanitize_error:
                logger.warning(f"Problem z sanityzacją danych CSV: {sanitize_error}")
                # Fallback - podstawowa sanityzacja
                for col in export_df.select_dtypes(include=['object']).columns:
                    export_df[col] = export_df[col].astype(str).str.replace(r'[^\w\s\-.,:/()áćęłńóśźżĄĆĘŁŃÓŚŹŻ]', '', regex=True)
            
            # Zmiana nazw kolumn na polskie
            column_mapping = {
                'created': 'Data utworzenia',
                'key': 'Klucz',
                'title': 'Tytuł',
                'issue_type': 'Typ zgłoszenia',
                'site': 'Numer restauracji',
                'site_name': 'Nazwa restauracji',
                'category': 'Dopasowana Reguła',
                'request_type': 'Typ żądania',
                'confidence': 'Pewność klasyfikacji',
                'status': 'Status',
                'priority': 'Priorytet',
                'last_update': 'Ostatnia aktualizacja',
                'team': 'Zespół',
                'assignee': 'Przypisany do',
                'creator': 'Utworzył',
                'organisation': 'Organizacja',
                'agent': 'Agent',
                'reporter': 'Zgłaszający',
                'jira_link': 'Link do Jira'
            }
            export_df.rename(columns=column_mapping, inplace=True)
            
            # Formatowanie dat - usunięto 'Data rozwiązania'
            date_columns = ['Data utworzenia', 'Ostatnia aktualizacja']
            for date_col in date_columns:
                if date_col in export_df.columns:
                    try:
                        # Sprawdź czy kolumna już jest datetime
                        if export_df[date_col].dtype == 'object':
                            # Jeśli to string, konwertuj na datetime
                            export_df[date_col] = pd.to_datetime(
                                export_df[date_col], 
                                format='mixed',
                                utc=True,
                                errors='coerce'  # Zastąp nieprawidłowe daty przez NaT
                            )
                        else:
                            # Jeśli już jest datetime, upewnij się że ma strefę czasową
                            export_df[date_col] = pd.to_datetime(
                                export_df[date_col],
                                utc=True,
                                errors='coerce'
                            )
                        
                        # Konwertuj na polską strefę czasową i sformatuj jako prostą datę i godzinę
                        export_df[date_col] = export_df[date_col].dt.tz_convert('Europe/Warsaw').dt.strftime('%Y-%m-%d %H:%M:%S')
                        
                    except Exception as date_error:
                        logger.warning(f"Problem z formatowaniem dat w kolumnie {date_col}: {date_error}")
                        # Fallback - spróbuj podstawowego formatowania
                        try:
                            export_df[date_col] = pd.to_datetime(
                                export_df[date_col], 
                                format='mixed',
                                errors='coerce'
                            ).dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            # Jeśli wszystko zawiedzie, zostaw oryginalne dane
                            logger.warning(f"Nie udało się sformatować dat w kolumnie {date_col} - pozostawiam oryginalne")
                            pass
            
            # Tworzenie dodatkowych kolumn daty i godziny z "Data utworzenia"
            if 'Data utworzenia' in export_df.columns:
                try:
                    logger.info(f"Kolumna 'Data utworzenia' zawiera {len(export_df)} rekordów")
                    logger.info(f"Przykład wartości: {export_df['Data utworzenia'].head(3).tolist()}")
                    
                    # Skonwertuj kolumnę "Data utworzenia" na datetime jeśli jeszcze nie jest
                    date_series = pd.to_datetime(export_df['Data utworzenia'], errors='coerce')
                    
                    # Sprawdź ile dat udało się skonwertować
                    valid_dates = date_series.notna().sum()
                    logger.info(f"Pomyślnie skonwertowano {valid_dates} z {len(date_series)} dat")
                    
                    # Tworzenie kolumny "Data" w formacie DD.MM.YYYY
                    export_df['Data'] = date_series.dt.strftime('%d.%m.%Y')
                    
                    # Tworzenie kolumny "Godzina" w formacie HH:MM
                    export_df['Godzina'] = date_series.dt.strftime('%H:%M')
                        
                    logger.info("Dodano kolumny 'Data' i 'Godzina' na podstawie 'Data utworzenia'")
                    logger.info(f"Przykład nowych kolumn - Data: {export_df['Data'].head(3).tolist()}, Godzina: {export_df['Godzina'].head(3).tolist()}")
                    
                except Exception as date_split_error:
                    logger.warning(f"Problem z tworzeniem kolumn daty i godziny: {date_split_error}")
                    # W przypadku błędu, kontynuuj bez dodatkowych kolumn
            
            # Formatowanie pewności klasyfikacji - z obsługą błędów
            if 'Pewność klasyfikacji' in export_df.columns:
                try:
                    # Konwertuj kolumnę na numeryczną, zastępując błędne wartości przez 0.0
                    export_df['Pewność klasyfikacji'] = pd.to_numeric(
                        export_df['Pewność klasyfikacji'], 
                        errors='coerce'  # Zastąp nieprawidłowe wartości przez NaN
                    ).fillna(0.0).round(2)  # Zastąp NaN przez 0.0 i zaokrąglij
                except Exception as conf_error:
                    logger.warning(f"Problem z formatowaniem pewności klasyfikacji: {conf_error}")
                    # Fallback - ustaw wszystkie wartości na 0.0
                    export_df['Pewność klasyfikacji'] = 0.0
            
            # Sortowanie kolumn dla lepszej czytelności
            desired_order = [
                'Data utworzenia', 'Data', 'Godzina', 'Link do Jira', 'Klucz', 'Tytuł', 'Typ zgłoszenia', 'Status', 'Priorytet',
                'Numer restauracji', 'Nazwa restauracji', 'Dopasowana Reguła', 'Typ żądania', 'Pewność klasyfikacji',
                'Ostatnia aktualizacja', 'Zespół', 'Przypisany do', 
                'Utworzył', 'Zgłaszający', 'Organizacja', 'Agent'
            ]
            existing_columns = [col for col in desired_order if col in export_df.columns]
            
            # Debug: sprawdź czy nowe kolumny zostały uwzględnione
            if 'Data' in export_df.columns:
                logger.info("Kolumna 'Data' jest dostępna w DataFrame")
            if 'Godzina' in export_df.columns:
                logger.info("Kolumna 'Godzina' jest dostępna w DataFrame")
            if 'Link do Jira' in export_df.columns:
                logger.info("Kolumna 'Link do Jira' jest dostępna w DataFrame")
            logger.info(f"Kolumny do eksportu: {existing_columns}")
            
            export_df = export_df[existing_columns]
            
            # Ostateczna walidacja danych przed eksportem
            try:
                # Sprawdź czy wszystkie kolumny mają odpowiednie typy danych
                for col in export_df.columns:
                    if col == 'Pewność klasyfikacji':
                        # Upewnij się, że kolumna jest numeryczna
                        export_df[col] = pd.to_numeric(export_df[col], errors='coerce').fillna(0.0)
                    else:
                        # Upewnij się, że inne kolumny są tekstowe
                        export_df[col] = export_df[col].astype(str)
                        
                logger.info(f"Przygotowano {len(export_df)} rekordów do eksportu CSV")
                
            except Exception as validation_error:
                logger.warning(f"Problem z walidacją danych przed eksportem: {validation_error}")
                # Fallback - konwertuj wszystko na string oprócz confidence
                for col in export_df.columns:
                    try:
                        if col == 'Pewność klasyfikacji':
                            export_df[col] = 0.0
                        else:
                            export_df[col] = export_df[col].astype(str)
                    except:
                        export_df[col] = 'N/A'
            
            # Tworzenie pliku CSV - z lepszą obsługą błędów
            try:
                output = io.StringIO()
                export_df.to_csv(output, index=False, encoding='utf-8-sig', sep=';')
                output.seek(0)
                
                # Konwersja na BytesIO
                csv_bytes = io.BytesIO()
                csv_content = output.getvalue()
                csv_bytes.write(csv_content.encode('utf-8-sig'))
                csv_bytes.seek(0)
                
                # Nazwa pliku z okresem analizy
                analysis_period = session.get('analysis_period', datetime.now().strftime('%Y-%m-%d'))
                filename = f'analiza_problemow_{analysis_period}.csv'
                
                logger.info(f"Pomyślnie przygotowano plik CSV: {filename} ({len(csv_content)} znaków)")
                
                return send_file(
                    csv_bytes,
                    mimetype='text/csv',
                    as_attachment=True,
                    download_name=filename
                )
                
            except Exception as csv_error:
                logger.exception(f"Błąd podczas tworzenia pliku CSV: {csv_error}")
                
                # Fallback - spróbuj z podstawowymi ustawieniami
                try:
                    output = io.StringIO()
                    # Upraszczamy dane do podstawowych typów
                    simple_df = export_df.copy()
                    for col in simple_df.columns:
                        simple_df[col] = simple_df[col].astype(str)
                    
                    simple_df.to_csv(output, index=False, sep=';')
                    output.seek(0)
                    
                    csv_bytes = io.BytesIO()
                    csv_bytes.write(output.getvalue().encode('utf-8'))
                    csv_bytes.seek(0)
                    
                    analysis_period = session.get('analysis_period', datetime.now().strftime('%Y-%m-%d'))
                    filename = f'analiza_problemow_{analysis_period}_simple.csv'
                    
                    logger.info(f"Używam fallback CSV: {filename}")
                    
                    return send_file(
                        csv_bytes,
                        mimetype='text/csv',
                        as_attachment=True,
                        download_name=filename
                    )
                    
                except Exception as fallback_error:
                    logger.exception(f"Błąd nawet z fallback CSV: {fallback_error}")
                    raise csv_error  # Pokaż oryginalny błąd
            
        except Exception as e:
            logger.exception(f"Błąd eksportu danych do CSV: {e}")
            flash(escape(f'Błąd podczas eksportu: {str(e)}'), 'error')
            return redirect(url_for('index'))

    def prepare_statistics(data):
        """Przygotowuje kluczowe statystyki do wyświetlenia."""
        # Łączna ilość zgłoszeń
        total_issues = len(data)
        
        # Sklasyfikowane zgłoszenia (wszystkie oprócz kategorii 'inne')
        classified_count = len(data[data['category'] != 'inne'])
        classification_rate = (classified_count / total_issues * 100) if total_issues > 0 else 0
        
        # Zmienna filtered_data dla kompatybilności z resztą kodu
        filtered_data = data.copy()
        
        # Statystyki kategorii
        top_problems = data['category'].value_counts().to_dict()
        
        # Statystyki typów zgłoszeń
        issue_type_stats = data['issue_type'].value_counts().to_dict()
        
        # Statystyki statusów (jeśli kolumna istnieje)
        status_stats = {}
        if 'status' in data.columns:
            status_stats = data['status'].value_counts().to_dict()
        
        # Statystyki priorytetów (jeśli kolumna istnieje)
        priority_stats = {}
        if 'priority' in data.columns:
            priority_stats = data['priority'].value_counts().to_dict()
        
        # Statystyki zespołów (jeśli kolumna istnieje)
        team_stats = {}
        if 'team' in data.columns:
            team_stats = data['team'].value_counts().head(10).to_dict()  # Top 10 zespołów
        
        # Dominujący typ zgłoszenia dla każdej kategorii
        category_dominant_types = {}
        for category in top_problems.keys():
            if category != 'inne':
                category_data = data[data['category'] == category]
                if not category_data.empty:
                    dominant_type = category_data['issue_type'].value_counts().idxmax()
                    category_dominant_types[category] = dominant_type
        
        # Wartości pewności klasyfikacji (confidence) dla wizualizacji
        confidence_values = []
        if 'confidence' in data.columns:
            confidence_values = data['confidence'].dropna().tolist()
        
        # Oblicz rzeczywiste dni z danych (nie z zakresu dat)
        if 'created' in data.columns and not data.empty:
            try:
                # Konwertuj kolumnę created na datetime jeśli jeszcze nie jest
                if data['created'].dtype == 'object':
                    data['created'] = pd.to_datetime(data['created'], format='mixed')
                unique_dates = data['created'].dt.date.nunique()
                actual_days = max(1, unique_dates)  # Minimum 1 dzień
            except Exception as e:
                logger.exception(f"Błąd konwersji daty w przygotowaniu statystyk: {e}")
                actual_days = 1
        else:
            actual_days = 1
        
        # Statystyki restauracji/lokalizacji - używamy oryginalnych danych ale bez excluded_sites
        top_sites = {}
        if 'site' in data.columns:
            # Wykluczenie asystenta systemowego, nieznanych i site 9993
            excluded_sites = ['Asystent', 'Nieznany', '9993']
            sites_filtered_data = data[~data['site'].isin(excluded_sites)].copy()
            
            if len(sites_filtered_data) > 0:
                # Tworzenie słownika z numerem restauracji jako kluczem i nazwą jako wartością
                site_info = {}
                for _, row in sites_filtered_data.iterrows():
                    site_num = row['site']
                    site_name = row.get('site_name', 'Nieznana')
                    if site_num not in site_info:
                        site_info[site_num] = site_name
                
                # Liczenie zgłoszeń dla każdej restauracji
                site_counts = sites_filtered_data['site'].value_counts().head(10)
                
                # Tworzenie słownika z dodatkowymi informacjami i statystykami typów zgłoszeń
                for site_num, count in site_counts.items():
                    site_name = site_info.get(site_num, 'Nieznana')
                    
                    # Filtruj dane dla konkretnej restauracji
                    site_data = sites_filtered_data[sites_filtered_data['site'] == site_num]
                    
                    # Policz typy zgłoszeń dla tej restauracji
                    incident_count = len(site_data[site_data['issue_type'] == 'Incydent'])
                    service_count = len(site_data[site_data['issue_type'] == 'Usługa'])
                    critical_count = len(site_data[site_data['issue_type'] == 'Poważny Incydent'])
                    
                    top_sites[site_num] = {
                        'count': count,
                        'name': site_name,
                        'incidents': incident_count,
                        'services': service_count,
                        'critical_incidents': critical_count
                    }
                
                # Dodaj "inne" dla pozostałych restauracji
                if len(sites_filtered_data['site'].value_counts()) > 10:
                    other_count = sites_filtered_data['site'].value_counts().iloc[10:].sum()
                    if other_count > 0:
                        # Policz typy zgłoszeń dla pozostałych restauracji
                        other_sites = sites_filtered_data['site'].value_counts().iloc[10:].index
                        other_data = sites_filtered_data[sites_filtered_data['site'].isin(other_sites)]
                        
                        other_incident_count = len(other_data[other_data['issue_type'] == 'Incydent'])
                        other_service_count = len(other_data[other_data['issue_type'] == 'Usługa'])
                        other_critical_count = len(other_data[other_data['issue_type'] == 'Poważny Incydent'])
                        
                        top_sites['Inne restauracje'] = {
                            'count': other_count,
                            'name': 'Inne restauracje',
                            'incidents': other_incident_count,
                            'services': other_service_count,
                            'critical_incidents': other_critical_count
                        }
        
        # --- DANE DO WIZUALIZACJI (DASHBOARD) ---
        
        # 1. Treemap Data (Mapa Częstości)
        treemap_data = {
            'labels': [],
            'values': []
        }
        for cat, count in top_problems.items():
            treemap_data['labels'].append(cat)
            treemap_data['values'].append(int(count))
            
        # 2. Trend Zgłoszeń w Czasie (Line Chart)
        daily_trend = {}
        daily_category_trend = {}
        
        if 'created' in data.columns and not data.empty:
            try:
                # Upewnij się, że created jest datetime
                if data['created'].dtype == 'object':
                    data['created'] = pd.to_datetime(data['created'], format='mixed')
                
                # Sortuj po dacie
                data_sorted = data.sort_values('created')
                
                # Grupuj po dacie (sam dzień) - Łącznie
                daily_counts = data_sorted.groupby(data_sorted['created'].dt.date).size()
                # Konwersja kluczy (date) na stringi dla JSON
                daily_trend = {str(k): int(v) for k, v in daily_counts.items()}
                
                # Grupuj po dacie i kategorii (dla top 5 kategorii)
                top_cats = [c for c in top_problems.keys() if c != 'inne'][:5]
                if not top_cats and top_problems:
                    top_cats = list(top_problems.keys())[:5]
                
                for cat in top_cats:
                    cat_data = data_sorted[data_sorted['category'] == cat]
                    if not cat_data.empty:
                        cat_daily = cat_data.groupby(cat_data['created'].dt.date).size()
                        daily_category_trend[cat] = {str(k): int(v) for k, v in cat_daily.items()}
                        
            except Exception as e:
                logger.exception(f"Błąd generowania trendów czasowych: {e}")

        return {
            'total_issues': total_issues,
            'classified_count': classified_count,
            'classification_rate': classification_rate,
            'top_problems': top_problems,
            'issue_type_stats': issue_type_stats,
            'status_stats': status_stats,
            'priority_stats': priority_stats,
            'team_stats': team_stats,
            'category_dominant_types': category_dominant_types,
            'actual_days': actual_days,
            'top_sites': top_sites,
            'confidence_values': confidence_values,
            'treemap_data': treemap_data,
            'daily_trend': daily_trend,
            'daily_category_trend': daily_category_trend
        }

    @app.errorhandler(404)
    def not_found_error(error):
        """Obsługa błędu 404."""
        flash(escape('Strona nie została znaleziona.'), 'error')
        return redirect(url_for('index'))

    @app.errorhandler(500)
    def internal_error(error):
        """Obsługa błędu 500."""
        flash(escape('Wystąpił błąd wewnętrzny serwera.'), 'error')
        return redirect(url_for('index'))

    # ===== FUNKCJE POMOCNICZE DO ZARZĄDZANIA REGUŁAMI =====

    def save_rules_to_file(rules_dict):
        """Zapisuje reguły do pliku JSON z kopią zapasową"""
        try:
            # Używa bezpiecznego menedżera reguł
            success = rules_manager.save_rules(rules_dict)
            if success:
                logger.info(f"✅ Zapisano {len(rules_dict)} reguł do pliku JSON")
                security.log_security_event('rules_updated', security.get_client_ip(), f"Updated with {len(rules_dict)} rules")
            else:
                logger.error("❌ Błąd zapisywania reguł")
                security.log_security_event('rules_save_failed', security.get_client_ip(), "Failed to save rules")
            return success
        except Exception as e:
            logger.exception(f"❌ Błąd zapisywania reguł do pliku: {e}")
            security.log_security_event('rules_save_failed', security.get_client_ip(), str(e))
            return False

    def reload_classifier():
        """Przeładowuje klasyfikator z nowymi regułami"""
        nonlocal classifier
        try:
            # Przeładuj reguły w menedżerze
            success = rules_manager.reload_rules()
            if success:
                # Utworzenie nowego klasyfikatora
                from classifier import ProblemClassifier
                classifier = ProblemClassifier()
                logger.info("✅ Klasyfikator przeładowany z nowymi regułami JSON")
                return True
            else:
                logger.error("❌ Błąd przeładowania reguł")
                return False
        except Exception as e:
            logger.exception(f"❌ Błąd przeładowania klasyfikatora z nowymi regułami: {e}")
            return False

    # ===== UWIERZYTELNIENIE ADMINISTRATORA =====

    @app.route('/admin/login', methods=['GET', 'POST'])
    @limiter.limit("1000 per hour")  # Bardzo wysoki limit dla wygody
    def admin_login():
        """Logowanie administratora z rozszerzoną walidacją"""
        if app.debug:
            logger.debug(f"admin_login called with method: {request.method}")
        
        if request.method == 'GET':
            # Jeśli już zalogowany, przekieruj do panelu
            if security.is_admin_authenticated():
                return redirect(url_for('index', show_admin='true'))
            return render_template('admin_login.html')
        
        try:
            if app.debug:
                logger.debug("POST data received")
            
            # Sanityzacja i walidacja danych formularza
            form_validation = security.sanitize_and_validate_form_data(request.form)
            if not form_validation['valid']:
                for error in form_validation['errors']:
                    flash(escape(error), 'error')
                return render_template('admin_login.html')
            
            form_data = form_validation['data']
            
            # Walidacja CSRF z dodatkowym debugowaniem
            csrf_token = form_data.get('csrf_token')
            session_csrf = session.get('csrf_token')
            
            if app.debug:
                logger.debug(f"CSRF token from form: {csrf_token[:20] if csrf_token else 'None'}...")
                logger.debug(f"CSRF token from session: {session_csrf[:20] if session_csrf else 'None'}...")
            
            if not security.validate_csrf_token(csrf_token):
                if app.debug:
                    logger.debug("CSRF validation failed")
                flash(escape('Błąd bezpieczeństwa. Spróbuj ponownie.'), 'error')
                return render_template('admin_login.html')
            
            # Walidacja danych logowania
            username = form_data.get('username', '')
            password = form_data.get('password', '')
            
            # Walidacja nazwy użytkownika
            username_validation = security.validate_text_input(username, "Nazwa użytkownika", min_length=1, max_length=50)
            if not username_validation['valid']:
                for error in username_validation['errors']:
                    flash(escape(error), 'error')
                return render_template('admin_login.html')
            
            username = username_validation['text']
            
            # Walidacja hasła
            if not password or len(password) < 1:
                flash(escape('Hasło jest wymagane.'), 'error')
                return render_template('admin_login.html')
            
            if len(password) > 1000:  # Rozsądny limit dla hasła
                flash(escape('Hasło zbyt długie.'), 'error')
                return render_template('admin_login.html')
            
            if app.debug:
                logger.debug(f"Username: {username}, Password length: {len(password)}")
            
            # Próba uwierzytelnienia
            if security.authenticate_admin(username, password):
                flash(escape('Pomyślnie zalogowano jako administrator.'), 'success')
                if app.debug:
                    logger.debug("Admin authenticated successfully")
                return redirect(url_for('index', show_admin='true'))
            else:
                flash(escape('Nieprawidłowa nazwa użytkownika lub hasło.'), 'error')
                if app.debug:
                    logger.debug("Admin authentication failed")
                return render_template('admin_login.html')
                
        except Exception as e:
            logger.exception(f"Błąd podczas procesu logowania administratora: {e}")
            flash(escape(f'Błąd logowania: {str(e)}'), 'error')
            return render_template('admin_login.html')

    @app.route('/admin/logout')
    def admin_logout():
        """Wylogowanie administratora"""
        security.logout_admin()
        flash(escape('Zostałeś wylogowany z panelu administratora.'), 'info')
        return redirect(url_for('index'))

    # ===== ENDPOINTY PANELU ADMINISTRATORA =====

    @app.route('/admin/get-rules')
    @security.require_admin
    def get_rules():
        """Zwraca aktualne reguły klasyfikacji w formacie JSON"""
        try:
            logger.debug(f"get_rules endpoint called by {security.get_client_ip()}")
            rules_dict = rules_manager.get_rules()
            logger.debug(f"Loaded {len(rules_dict)} rules successfully")
            return jsonify({
                'success': True,
                'rules': rules_dict
            })
        except Exception as e:
            logger.exception(f"Błąd pobierania reguł klasyfikacji: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    @app.route('/admin/add-rule', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    @limiter.limit("20 per 5 minutes")  # 20 dodawań reguł na 5 minut
    def add_rule():
        """Dodaje nową regułę klasyfikacji z rozszerzoną walidacją"""
        try:
            # Sanityzacja i walidacja danych formularza
            form_validation = security.sanitize_and_validate_form_data(request.form)
            if not form_validation['valid']:
                for error in form_validation['errors']:
                    flash(escape(error), 'error')
                return redirect(url_for('index'))
            
            form_data = form_validation['data']
            
            # Pobieranie i sanityzacja danych
            rule_name = form_data.get('rule_name', '')
            keywords_str = form_data.get('keywords', '')
            combinations_str = form_data.get('required_combinations', '')
            forbidden_str = form_data.get('forbidden', '')
            min_score_str = form_data.get('min_score', '2')
            
            # Walidacja przez SecurityManager
            validation_errors = security.validate_rule_data(
                rule_name, keywords_str, combinations_str, forbidden_str, min_score_str
            )
            
            if validation_errors:
                for error in validation_errors:
                    flash(escape(error), 'error')
                return redirect(url_for('index'))
            
            # Konwersja min_score (już zwalidowana)
            min_score = int(min_score_str)
            
            # Parsowanie keywords z dodatkowymi walidacjami
            keywords = []
            for word in keywords_str.split(','):
                word = word.strip().lower()
                if word:
                    # Dodatkowa walidacja każdego słowa
                    word_validation = security.validate_text_input(word, "Słowo kluczowe", min_length=2, max_length=50)
                    if word_validation['valid']:
                        keywords.append(word_validation['text'])
                    else:
                        flash(escape(f"Nieprawidłowe słowo kluczowe: {word}"), 'error')
                        return redirect(url_for('index'))
            
            # Parsowanie kombinacji (opcjonalne)
            required_combinations = []
            if combinations_str:
                lines = combinations_str.strip().split('\n')
                for line in lines:
                    if line.strip():
                        combination = []
                        for word in line.split('+'):
                            word = word.strip().lower()
                            if word:
                                word_validation = security.validate_text_input(word, "Słowo w kombinacji", min_length=2, max_length=50)
                                if word_validation['valid']:
                                    combination.append(word_validation['text'])
                                else:
                                    flash(escape(f"Nieprawidłowe słowo w kombinacji: {word}"), 'error')
                                    return redirect(url_for('index'))
                        
                        if len(combination) >= 2:
                            required_combinations.append(combination)
            
            # Parsowanie słów zabronionych (opcjonalne)
            forbidden = []
            if forbidden_str:
                for word in forbidden_str.split(','):
                    word = word.strip().lower()
                    if word:
                        word_validation = security.validate_text_input(word, "Słowo zabronione", min_length=2, max_length=50)
                        if word_validation['valid']:
                            forbidden.append(word_validation['text'])
                        else:
                            flash(escape(f"Nieprawidłowe słowo zabronione: {word}"), 'error')
                            return redirect(url_for('index'))
            
            # Ładowanie aktualnych reguł
            current_rules = rules_manager.get_rules()
            
            # Sprawdzenie czy reguła już istnieje
            if rule_name in current_rules:
                flash(escape(f'Reguła "{rule_name}" już istnieje. Użyj funkcji edycji aby ją zmodyfikować.'), 'warning')
                return redirect(url_for('index'))
            
            # Tworzenie nowej reguły
            new_rule = {
                'keywords': keywords,
                'min_score': min_score
            }
            
            if required_combinations:
                new_rule['required_combinations'] = required_combinations
            
            if forbidden:
                new_rule['forbidden'] = forbidden
            
            # Dodanie nowej reguły
            current_rules[rule_name] = new_rule
            
            # Zapisanie do pliku JSON
            if save_rules_to_file(current_rules):
                if reload_classifier():
                    flash(escape(f'Reguła "{rule_name}" została dodana pomyślnie!'), 'success')
                else:
                    flash(escape('Reguła została dodana, ale wystąpił problem z przeładowaniem klasyfikatora.'), 'warning')
            else:
                flash(escape('Błąd podczas zapisywania reguły.'), 'error')
            
            return redirect(url_for('index'))
            
        except ValueError as e:
            flash(escape(f'Nieprawidłowa wartość: {str(e)}'), 'error')
            return redirect(url_for('index'))
        except Exception as e:
            logger.exception(f"Błąd podczas dodawania reguły klasyfikacji: {e}")
            flash(escape(f'Błąd podczas dodawania reguły: {str(e)}'), 'error')
            return redirect(url_for('index'))

    @app.route('/admin/delete-rule', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    @limiter.limit("10 per 5 minutes")  # 10 usunięć na 5 minut
    def delete_rule():
        """Usuwa regułę klasyfikacji"""
        try:
            logger.info("Delete rule endpoint called")
            data = request.get_json()
            logger.info(f"Received data: {data}")
            
            rule_name = data.get('rule_name')
            logger.info(f"Rule name to delete: {rule_name}")
            
            if not rule_name:
                logger.warning("No rule name provided")
                return jsonify({'success': False, 'error': 'Nazwa reguły jest wymagana'})
            
            # Sprawdzenie czy reguła istnieje
            current_rules = rules_manager.get_rules()
            if rule_name not in current_rules:
                logger.warning(f"Rule '{rule_name}' not found in rules")
                return jsonify({'success': False, 'error': 'Reguła nie istnieje'})
            
            logger.info(f"Attempting to delete rule: {rule_name}")
            # Usunięcie reguły
            if rules_manager.delete_rule(rule_name):
                logger.info(f"Rule '{rule_name}' deleted successfully, reloading classifier")
                if reload_classifier():
                    logger.info(f"Classifier reloaded successfully after deleting rule '{rule_name}'")
                    return jsonify({'success': True, 'message': f'Reguła "{rule_name}" została usunięta'})
                else:
                    logger.error(f"Failed to reload classifier after deleting rule '{rule_name}'")
                    return jsonify({'success': False, 'error': 'Problem z przeładowaniem klasyfikatora'})
            else:
                logger.error(f"Failed to delete rule '{rule_name}'")
                return jsonify({'success': False, 'error': 'Błąd podczas zapisywania'})
            
        except Exception as e:
            logger.exception(f"Błąd podczas usuwania reguły klasyfikacji: {e}")
            return jsonify({'success': False, 'error': str(e)})

    @app.route('/admin/edit-rule', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    @limiter.limit("20 per 5 minutes")  # 20 edycji na 5 minut
    def edit_rule():
        """Edytuje istniejącą regułę klasyfikacji"""
        try:
            original_rule_name = request.form.get('original_rule_name', '').strip()
            new_rule_name = request.form.get('rule_name', '').strip()
            keywords_str = request.form.get('keywords', '').strip()
            combinations_str = request.form.get('required_combinations', '').strip()
            forbidden_str = request.form.get('forbidden', '').strip()
            min_score = int(request.form.get('min_score', 2))
            
            # Walidacja danych
            if not original_rule_name:
                flash(escape('Błąd: brak oryginalnej nazwy reguły.'), 'error')
                return redirect(url_for('index'))
            
            if not new_rule_name:
                flash(escape('Nazwa reguły jest wymagana.'), 'error')
                return redirect(url_for('index'))
            
            if not keywords_str:
                flash(escape('Słowa kluczowe są wymagane.'), 'error')
                return redirect(url_for('index'))
            
            # Parsowanie danych (tak samo jak w add_rule)
            keywords = [word.strip().lower() for word in keywords_str.split(',') if word.strip()]
            
            required_combinations = []
            if combinations_str:
                lines = combinations_str.strip().split('\n')
                for line in lines:
                    if line.strip():
                        combination = [word.strip().lower() for word in line.split('+') if word.strip()]
                        if len(combination) >= 2:
                            required_combinations.append(combination)
            
            forbidden = []
            if forbidden_str:
                forbidden = [word.strip().lower() for word in forbidden_str.split(',') if word.strip()]
            
            # Ładowanie aktualnych reguł
            current_rules = rules_manager.get_rules()
            
            # Sprawdzenie czy oryginalna reguła istnieje
            if original_rule_name not in current_rules:
                flash(escape(f'Reguła "{original_rule_name}" nie istnieje.'), 'error')
                return redirect(url_for('index'))
            
            # Jeśli nazwa się zmieniła, sprawdź czy nowa nazwa nie jest zajęta
            if new_rule_name != original_rule_name and new_rule_name in current_rules:
                flash(escape(f'Reguła o nazwie "{new_rule_name}" już istnieje.'), 'warning')
                return redirect(url_for('index'))
            
            # Tworzenie zaktualizowanej reguły
            updated_rule = {
                'keywords': keywords,
                'min_score': min_score
            }
            
            if required_combinations:
                updated_rule['required_combinations'] = required_combinations
            
            if forbidden:
                updated_rule['forbidden'] = forbidden
            
            # Usunięcie starej reguły (jeśli nazwa się zmieniła)
            if new_rule_name != original_rule_name:
                del current_rules[original_rule_name]
            
            # Dodanie zaktualizowanej reguły
            current_rules[new_rule_name] = updated_rule
            
            # Zapisanie do pliku JSON
            if save_rules_to_file(current_rules):
                if reload_classifier():
                    flash(escape(f'Reguła została zaktualizowana pomyślnie!'), 'success')
                else:
                    flash(escape('Reguła została zaktualizowana, ale wystąpił problem z przeładowaniem klasyfikatora.'), 'warning')
            else:
                flash(escape('Błąd podczas zapisywania reguły.'), 'error')
            
            return redirect(url_for('index'))
            
        except ValueError:
            flash(escape('Nieprawidłowa wartość minimalnego wyniku.'), 'error')
            return redirect(url_for('index'))
        except Exception as e:
            logger.exception(f"Błąd podczas edycji reguły klasyfikacji: {e}")
            flash(escape(f'Błąd podczas edycji reguły: {str(e)}'), 'error')
            return redirect(url_for('index'))

    @app.route('/admin/reload-rules', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    def reload_rules():
        """Przeładowuje reguły klasyfikacji bez restartowania aplikacji"""
        try:
            # Przeładuj reguły
            if reload_classifier():
                flash(escape('Reguły zostały pomyślnie przeładowane!'), 'success')
                
                # Sprawdź ile reguł zostało załadowanych
                rule_count = rules_manager.get_rules_count()
                flash(escape(f'Załadowano {rule_count} reguł klasyfikacji.'), 'info')
                
                # Logowanie zdarzenia
                security.log_security_event('rules_reloaded', security.get_client_ip(), f"Reloaded {rule_count} rules")
            else:
                flash(escape('Błąd podczas przeładowania reguł.'), 'error')
                
        except Exception as e:
            logger.exception(f"Błąd podczas przeładowania reguł klasyfikacji: {e}")
            flash(escape(f'Błąd podczas przeładowania reguł: {str(e)}'), 'error')
        
        return redirect(url_for('index'))

    @app.route('/admin/test-rules')
    @security.require_admin
    def test_rules():
        """Test nowych reguł klasyfikacji"""
        try:
            current_rules = rules_manager.get_rules()
            
            # Testowe zdania dla nowych reguł
            test_cases = [
                "FOE63 - nieprawidłowy dzień biznesowy",
                "MOP - brak fiskalizacji zamówień",
                "MOP - zamówienia nie drukują się",
                "Mystore - brak zużycia PP",
                "Mystore - brak danych w raporcie PMX",
                "POS01 - not initalized",
                "POS07 - waystation offline",
                "POS03 - zawieszony terminal",
                "CSO25 - skaner nie działa",
                "POS20 - admin logon nie można uruchomić",
                "KVS15 - czerwona M na ekranie"
            ]
            
            results = []
            for test_case in test_cases:
                # Symuluj klasyfikację
                if classifier:
                    test_df = pd.DataFrame({'title': [test_case]})
                    classified = classifier.classify_issues(test_df)
                    category = classified['category'].iloc[0] if not classified.empty else 'nieznana'
                    confidence = classified['confidence'].iloc[0] if not classified.empty else 0.0
                else:
                    category = 'błąd klasyfikatora'
                    confidence = 0.0
                    
                results.append({
                    'title': test_case,
                    'category': category,
                    'confidence': confidence
                })
            
            return jsonify({
                'success': True,
                'total_rules': len(current_rules),
                'test_results': results
            })
            
        except Exception as e:
            logger.exception(f"Błąd testowania reguł klasyfikacji: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    # ===== ENDPOINTY ZMIANY TYPU ZGŁOSZENIA =====

    @app.route('/api/get-issue-types')
    @limiter.limit("100 per 5 minutes")  # 100 zapytań na 5 minut
    def get_issue_types():
        """Zwraca dostępne typy zgłoszeń z Jira"""
        try:
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'error': 'JiraAPI nie został zainicjalizowany'
                })
            
            issue_types = jira_api.get_issue_types()
            return jsonify({
                'success': True,
                'issue_types': issue_types
            })
            
        except Exception as e:
            logger.exception(f"Błąd pobierania typów zgłoszeń: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    @app.route('/api/get-request-types')
    @limiter.limit("100 per 5 minutes")  # 100 zapytań na 5 minut
    def get_request_types():
        """Zwraca dostępne typy żądań z Jira Service Desk, opcjonalnie filtrowane po typie zgłoszenia"""
        try:
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'error': 'JiraAPI nie został zainicjalizowany'
                })
            
            # Pobierz opcjonalny parametr issue_type_id z query string
            issue_type_id = request.args.get('issue_type_id')
            
            request_types = jira_api.get_request_types(issue_type_id=issue_type_id)
            return jsonify({
                'success': True,
                'request_types': request_types,
                'filtered_by_issue_type': issue_type_id
            })
            
        except Exception as e:
            logger.exception(f"Błąd pobierania typów żądań: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    @app.route('/api/validate-issues', methods=['POST'])
    @limiter.limit("100 per 5 minutes")  # 100 walidacji na 5 minut
    def validate_issues():
        """Waliduje klucze zgłoszeń i zwraca informacje o nich"""
        try:
            # Sanityzacja i walidacja danych formularza
            form_validation = security.sanitize_and_validate_form_data(request.form)
            if not form_validation['valid']:
                return jsonify({
                    'success': False,
                    'error': 'Nieprawidłowe dane formularza',
                    'details': form_validation['errors']
                })
            
            form_data = form_validation['data']
            issue_keys_str = form_data.get('issue_keys', '').strip()
            
            if not issue_keys_str:
                return jsonify({
                    'success': False,
                    'error': 'Nie podano kluczy zgłoszeń'
                })
            
            # Parsowanie kluczy zgłoszeń
            import re
            # Znajdź wszystkie klucze w formacie SD-XXXXX
            issue_keys = re.findall(r'SD-\d+', issue_keys_str.upper())
            
            if not issue_keys:
                return jsonify({
                    'success': False,
                    'error': 'Nie znaleziono prawidłowych kluczy zgłoszeń w formacie SD-XXXXX'
                })
            
            if len(issue_keys) > 1000:
                return jsonify({
                    'success': False,
                    'error': f'Zbyt wiele zgłoszeń ({len(issue_keys)}). Maksymalnie 1000 zgłoszeń na raz.'
                })
            
            # Usuń duplikaty zachowując kolejność
            unique_keys = []
            seen = set()
            for key in issue_keys:
                if key not in seen:
                    unique_keys.append(key)
                    seen.add(key)
            
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'error': 'JiraAPI nie został zainicjalizowany'
                })
            
            # Waliduj klucze w Jira
            valid_issues, invalid_issues = jira_api.validate_issue_keys(unique_keys)
            
            # Sprawdź dozwolone typy zgłoszeń dla pierwszego poprawnego zgłoszenia
            # (zakładamy, że wszystkie zgłoszenia są w podobnym stanie, co jest uproszczeniem, ale praktycznym)
            allowed_target_types = []
            if valid_issues:
                # Grupuj zgłoszenia po typie
                issues_by_type = {}
                for issue in valid_issues:
                    current_type = issue.get('issue_type_name', 'Unknown')
                    if current_type not in issues_by_type:
                        issues_by_type[current_type] = issue['key']
                
                # Pobierz allowedValues dla jednego zgłoszenia z każdego typu
                all_allowed_ids = None
                
                for type_name, key in issues_by_type.items():
                    allowed = jira_api.get_allowed_issue_types(key)
                    allowed_ids = {t['id'] for t in allowed}
                    
                    if all_allowed_ids is None:
                        all_allowed_ids = allowed_ids
                    else:
                        # Część wspólna - typ musi być dozwolony dla WSZYSTKICH grup
                        all_allowed_ids = all_allowed_ids.intersection(allowed_ids)
                
                if all_allowed_ids:
                    allowed_target_types = list(all_allowed_ids)
            
            return jsonify({
                'success': True,
                'total_keys': len(unique_keys),
                'valid_count': len(valid_issues),
                'invalid_count': len(invalid_issues),
                'valid_issues': valid_issues,
                'invalid_issues': invalid_issues,
                'allowed_target_types': allowed_target_types
            })
            
        except Exception as e:
            logger.exception(f"Błąd walidacji zgłoszeń: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    @app.route('/api/update-issue-types', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    @limiter.limit("100 per 10 minutes")  # 100 aktualizacji na 10 minut
    def update_issue_types():
        """Aktualizuje typ zgłoszenia dla podanych kluczy"""
        try:
            # Pobierz dane JSON
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Brak danych JSON'
                })
            
            issue_keys = data.get('issue_keys', [])
            new_issue_type_id = data.get('new_issue_type_id')
            
            if not issue_keys:
                return jsonify({
                    'success': False,
                    'error': 'Nie podano kluczy zgłoszeń'
                })
            
            if not new_issue_type_id:
                return jsonify({
                    'success': False,
                    'error': 'Nie podano nowego typu zgłoszenia'
                })
            
            if len(issue_keys) > 1000:
                return jsonify({
                    'success': False,
                    'error': f'Zbyt wiele zgłoszeń ({len(issue_keys)}). Maksymalnie 1000 zgłoszeń na raz.'
                })
            
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'error': 'JiraAPI nie został zainicjalizowany'
                })
            
            # Wyniki aktualizacji
            results = {
                'total': len(issue_keys),
                'success_count': 0,
                'failed_count': 0,
                'failed_issues': [],
                'success_issues': []
            }
            
            # Aktualizuj każde zgłoszenie
            for issue_key in issue_keys:
                success, error_msg = jira_api.update_issue_type(issue_key, new_issue_type_id)
                if success:
                    results['success_count'] += 1
                    results['success_issues'].append(issue_key)
                else:
                    results['failed_count'] += 1
                    # Zapisz obiekt z kluczem i błędem
                    results['failed_issues'].append({
                        'key': issue_key,
                        'error': error_msg
                    })
            
            # Logowanie wyników
            logger.info(f"Aktualizacja typów zgłoszeń - powodzenie: {results['success_count']}, błędy: {results['failed_count']}")
            security.log_security_event('issue_types_updated', security.get_client_ip(), 
                                       f"Updated {results['success_count']} issue types, {results['failed_count']} failed")
            
            return jsonify({
                'success': True,
                'results': results
            })
            
        except Exception as e:
            logger.exception(f"Błąd aktualizacji typów zgłoszeń: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    @app.route('/api/update-request-types', methods=['POST'])
    @security.require_admin
    @security.require_csrf
    @limiter.limit("100 per 10 minutes")  # 100 aktualizacji na 10 minut
    def update_request_types():
        """Aktualizuje typ żądania dla podanych kluczy"""
        try:
            # Pobierz dane JSON
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Brak danych JSON'
                })
            
            issue_keys = data.get('issue_keys', [])
            new_request_type_id = data.get('new_request_type_id')
            
            if not issue_keys:
                return jsonify({
                    'success': False,
                    'error': 'Nie podano kluczy zgłoszeń'
                })
            
            if not new_request_type_id:
                return jsonify({
                    'success': False,
                    'error': 'Nie podano nowego typu żądania'
                })
            
            if len(issue_keys) > 1000:
                return jsonify({
                    'success': False,
                    'error': f'Zbyt wiele zgłoszeń ({len(issue_keys)}). Maksymalnie 1000 zgłoszeń na raz.'
                })
            
            if jira_api is None:
                return jsonify({
                    'success': False,
                    'error': 'JiraAPI nie został zainicjalizowany'
                })
            
            # Wyniki aktualizacji
            results = {
                'total': len(issue_keys),
                'success_count': 0,
                'failed_count': 0,
                'failed_issues': [],
                'success_issues': []
            }
            
            # Aktualizuj każde zgłoszenie
            for issue_key in issue_keys:
                if jira_api.update_request_type(issue_key, new_request_type_id):
                    results['success_count'] += 1
                    results['success_issues'].append(issue_key)
                else:
                    results['failed_count'] += 1
                    results['failed_issues'].append(issue_key)
            
            # Logowanie wyników
            logger.info(f"Aktualizacja typów żądań - powodzenie: {results['success_count']}, błędy: {results['failed_count']}")
            security.log_security_event('request_types_updated', security.get_client_ip(), 
                                       f"Updated {results['success_count']} request types, {results['failed_count']} failed")
            
            return jsonify({
                'success': True,
                'results': results
            })
            
        except Exception as e:
            logger.exception(f"Błąd aktualizacji typów żądań: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            })

    # ===== ENDPOINT FAVICON =====
    
    @app.route('/favicon.ico')
    def favicon():
        """Endpoint dla favicon.ico - bezpośredni dostęp"""
        try:
            return send_file(
                os.path.join(app.static_folder, 'favicon.ico'),
                mimetype='image/x-icon'
            )
        except Exception as e:
            logger.warning(f"Błąd serwowania favicon: {e}")
            abort(404)
