import requests
import pandas as pd
import os
import logging
import time
from datetime import datetime
from dotenv import load_dotenv

# Ładowanie zmiennych środowiskowych
load_dotenv()

# Konfiguracja loggera dla Jira API
jira_logger = logging.getLogger('jira_api')
jira_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
jira_logger.addHandler(console_handler)

class JiraAPI:
    def __init__(self):
        self.domain = os.getenv('JIRA_DOMAIN', "https://sdeskdro.atlassian.net")
        self.email = os.getenv('JIRA_EMAIL', "dominik.rochaczewski@gmail.com")
        self.token = os.getenv('JIRA_TOKEN')
        
        if not self.token:
            raise ValueError("JIRA_TOKEN nie został ustawiony w zmiennych środowiskowych")
    
    def get_total_issues_count(self, start_date, end_date):
        """
        Pobiera DOKŁADNĄ liczbę zgłoszeń w zakresie dat.
        Ta funkcja musi zwrócić poprawną liczbę zanim rozpocznie się pobieranie.
        """
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        jql = f'project = SD AND created >= "{start_str}" AND created <= "{end_str}"'
        
        # Użyj standardowego endpointu search (v2/v3) który zwraca 'total'
        # Endpoint /rest/api/3/search zwraca total w odpowiedzi
        url = f"{self.domain}/rest/api/3/search"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        params = {
            "jql": jql,
            "maxResults": 0,  # Nie pobieraj żadnych zgłoszeń, tylko metadane
            "fields": "key"   # Minimalne pole
        }
        
        try:
            jira_logger.info(f"Sprawdzanie liczby zgłoszeń dla: {jql}")
            response = requests.get(url, headers=headers, auth=auth, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                jira_logger.info(f"Odpowiedź API (klucze): {list(data.keys())}")
                
                if 'total' in data:
                    total = data['total']
                    jira_logger.info(f"✓ Dokładna liczba zgłoszeń: {total}")
                    return total
                else:
                    jira_logger.warning(f"Brak pola 'total' w odpowiedzi. Dane: {data}")
            else:
                jira_logger.error(f"Błąd API: {response.status_code} - {response.text[:200]}")
            
            # Fallback - spróbuj pobrać pierwszą stronę i policzyć
            jira_logger.info("Próba fallback - pobieranie pierwszej strony...")
            params['maxResults'] = 100
            response = requests.get(url, headers=headers, auth=auth, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if 'total' in data:
                    total = data['total']
                    jira_logger.info(f"✓ Liczba zgłoszeń (fallback): {total}")
                    return total
            
            jira_logger.error("Nie udało się pobrać liczby zgłoszeń")
            return None
            
        except Exception as e:
            jira_logger.exception(f"Błąd podczas pobierania liczby zgłoszeń: {e}")
            return None

    def estimate_issues_count(self, start_date, end_date):
        """Alias dla kompatybilności wstecznej"""
        return self.get_total_issues_count(start_date, end_date)

    def fetch_issues_streaming(self, start_date, end_date, total_count):
        """
        Generator streamujący pobieranie zgłoszeń z Jira.
        Zwraca (yield) słowniki z postępem i danymi.
        
        Typy zwracanych danych:
        - {'type': 'progress', 'current': N, 'total': M} - postęp
        - {'type': 'batch', 'issues': [...]} - batch danych
        - {'type': 'done', 'all_issues': [...]} - zakończenie
        - {'type': 'error', 'error': 'msg'} - błąd
        """
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        jql = f'project = SD AND created >= "{start_str}" AND created <= "{end_str}"'
        url = f"{self.domain}/rest/api/3/search/jql"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        all_issues = []
        next_page_token = None
        batch_size = 100
        
        jira_logger.info(f"[STREAMING] Start pobierania dla: {jql}")
        
        while True:
            params = {
                "jql": jql,
                "maxResults": batch_size,
                "fields": "summary,created,key,issuetype,reporter,status,priority,updated,assignee,creator"
            }
            
            if next_page_token:
                params["nextPageToken"] = next_page_token
            
            try:
                response = requests.get(url, headers=headers, auth=auth, params=params, timeout=30)
                
                if response.status_code == 429:
                    jira_logger.warning("Rate limit hit, czekam 60s...")
                    time.sleep(60)
                    continue
                
                if response.status_code != 200:
                    jira_logger.error(f"Błąd API: {response.status_code}")
                    yield {'type': 'error', 'error': f'Błąd API Jira: {response.status_code}'}
                    return
                
                data = response.json()
                issues = data.get('issues', [])
                
                if not issues and not all_issues:
                    yield {'type': 'error', 'error': 'Brak zgłoszeń do pobrania'}
                    return
                
                all_issues.extend(issues)
                
                # Yield postępu
                yield {
                    'type': 'progress',
                    'current': len(all_issues),
                    'total': total_count
                }
                
                # Yield batch danych (dla trybu przyrostowego)
                yield {
                    'type': 'batch',
                    'issues': issues
                }
                
                jira_logger.info(f"[STREAMING] Pobrano: {len(all_issues)}/{total_count}")
                
                # Sprawdź czy to ostatnia strona
                is_last = data.get('isLast', True)
                next_page_token = data.get('nextPageToken')
                
                if is_last or not next_page_token:
                    break
                    
            except requests.exceptions.Timeout:
                jira_logger.error("Timeout podczas pobierania z Jira")
                yield {'type': 'error', 'error': 'Timeout połączenia z Jira'}
                return
            except Exception as e:
                jira_logger.exception(f"Błąd podczas streaming fetch: {e}")
                yield {'type': 'error', 'error': str(e)}
                return
        
        jira_logger.info(f"[STREAMING] Zakończono - łącznie {len(all_issues)} zgłoszeń")
        yield {'type': 'done', 'all_issues': all_issues}

    def issues_to_dataframe(self, issues):
        """
        Konwertuje listę issues z API do DataFrame.
        Wydzielone z fetch_issues dla reużywalności.
        """
        if not issues:
            return pd.DataFrame()
        
        records = []
        for issue in issues:
            try:
                # Reporter
                reporter_info = issue['fields'].get('reporter', {})
                reporter_name = reporter_info.get('displayName', 'Nieznany') if reporter_info else 'Nieznany'
                
                # Assignee
                assignee_info = issue['fields'].get('assignee', {})
                assignee_name = assignee_info.get('displayName', 'Nieprzypisany') if assignee_info else 'Nieprzypisany'
                
                # Creator
                creator_info = issue['fields'].get('creator', {})
                creator_name = creator_info.get('displayName', 'Nieznany') if creator_info else 'Nieznany'
                
                # Status
                status_info = issue['fields'].get('status', {})
                status_name = status_info.get('name', 'Nieznany') if status_info else 'Nieznany'
                
                # Priority
                priority_info = issue['fields'].get('priority', {})
                priority_name = priority_info.get('name', 'Nieznany') if priority_info else 'Nieznany'
                
                # Site extraction
                site = self.extract_site_from_reporter(reporter_name)
                site_name = self.extract_site_name_from_reporter(reporter_name)
                
                # Custom fields
                team = self.safe_get_field(issue['fields'], 'customfield_10100', 'Nieznany')
                category = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznana')
                request_type = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznany')
                organisation = self.safe_get_field(issue['fields'], 'customfield_10002', 'Nieznana')
                agent = self.safe_get_field(issue['fields'], 'customfield_10227', 'Nieznany')
                
                records.append({
                    'key': issue['key'],
                    'title': issue['fields']['summary'],
                    'created': issue['fields']['created'],
                    'issue_type': issue['fields']['issuetype']['name'],
                    'reporter': reporter_name,
                    'site': site,
                    'site_name': site_name,
                    'status': status_name,
                    'priority': priority_name,
                    'last_update': issue['fields'].get('updated', ''),
                    'assignee': assignee_name,
                    'creator': creator_name,
                    'team': team,
                    'category': category,
                    'request_type': request_type,
                    'organisation': organisation,
                    'agent': agent
                })
            except Exception as e:
                jira_logger.warning(f"Błąd przetwarzania issue {issue.get('key', 'unknown')}: {e}")
                continue
        
        df = pd.DataFrame(records)
        
        # Czyszczenie tytułów
        if not df.empty and 'title' in df.columns:
            df['title_clean'] = df['title'].str.strip()
            df['title_lower'] = df['title_clean'].str.lower()
        
        jira_logger.info(f"[DF] Utworzono DataFrame z {len(df)} rekordami")
        return df

    def fetch_issues_with_progress(self, start_date, end_date, analysis_id=None, progress_dict=None, total_estimated=None):
        """Pobiera zgłoszenia z Jira w podanym zakresie dat z raportowaniem postępu"""
        
        # Jeśli start_date == end_date, pobieramy cały ten dzień
        # Jeśli start_date != end_date, pobieramy od początku start_date do końca end_date
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        # Uproszczone zapytanie - pobiera wszystkie zgłoszenia z projektu SD w zakresie dat
        jql = f'project = SD AND created >= "{start_str}" AND created <= "{end_str}"'

        url = f"{self.domain}/rest/api/3/search/jql"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        all_issues = []
        start_at = 0
        batch_size = 100
        
        jira_logger.info(f"Pobieranie danych z Jira dla okresu {start_str} - {end_str}")
        jira_logger.info(f"Używane JQL: {jql}")
        
        # API v3 używa cursor-based pagination - nie można z góry sprawdzić total
        # Rozpoczynamy pobieranie bez wstępnego szacowania
        all_issues = []
        next_page_token = None
        batch_size = 100
        
        while True:
            # Przygotuj parametry dla API v3 (cursor-based pagination)
            # Uproszczone pola - pobieramy tylko podstawowe informacje
            params = {
                "jql": jql,
                "maxResults": batch_size,
                "fields": "summary,created,key,issuetype,reporter,status,priority,updated,assignee,creator"
            }
            
            # Dodaj token dla następnej strony jeśli istnieje
            if next_page_token:
                params["nextPageToken"] = next_page_token
            
            try:
                response = requests.get(url, headers=headers, auth=auth, params=params, timeout=30)
                
                if response.status_code == 429:
                    jira_logger.warning("Rate limit hit, czekam...")
                    time.sleep(60)
                    continue
                if response.status_code != 200:
                    jira_logger.error(f"Błąd API: Status {response.status_code}")
                    jira_logger.error(f"Response: {response.text}")
                    raise Exception(f"Błąd API: {response.status_code}")
                
                data = response.json()
                
                # ZAWSZE aktualizuj total_estimated jeśli API zwraca 'total'
                # To naprawia sytuację, gdy szacowanie się nie powiodło lub było niedokładne
                if 'total' in data:
                    real_total = data['total']
                    if total_estimated != real_total:
                        jira_logger.info(f"Aktualizacja total_estimated: {total_estimated} -> {real_total}")
                        total_estimated = real_total
                
                issues = data.get('issues', [])
                
                if not issues:
                    break
                    
                all_issues.extend(issues)
                jira_logger.info(f"Pobrano: {len(all_issues)} zgłoszeń...")
                
                # Sprawdź czy to ostatnia strona
                is_last = data.get('isLast', True)
                next_page_token = data.get('nextPageToken')
                
                # Aktualizuj postęp, jeśli przekazano parametry
                if analysis_id and progress_dict and analysis_id in progress_dict:
                    # Oblicz postęp na podstawie liczby pobranych zgłoszeń
                    
                    if total_estimated and total_estimated > 0:
                        # Mamy dokładną liczbę zgłoszeń - oblicz procent
                        # Pobieranie to 0-85%, klasyfikacja i zapis to 85-100%
                        ratio = min(1.0, len(all_issues) / total_estimated)
                        fetch_progress = ratio * 85
                        
                        status_msg = 'Pobieranie zgłoszeń z Jira...'
                        
                        progress_dict[analysis_id].update({
                            'progress': fetch_progress,
                            'status': status_msg,
                            'current_count': len(all_issues),
                            'total_count': total_estimated,
                            'eta_seconds': 0
                        })
                    else:
                        # Fallback - nie mamy total (bardzo rzadkie)
                        status_msg = f'Pobrano {len(all_issues)} zgłoszeń...'
                        
                        progress_dict[analysis_id].update({
                            'progress': min(50, len(all_issues) / 10),  # Powoli rośnie
                            'status': status_msg,
                            'current_count': len(all_issues),
                            'total_count': 0,
                            'eta_seconds': 0
                        })
                
                # Zakończ jeśli to ostatnia strona
                if is_last or not next_page_token:
                    jira_logger.info(f"Pobieranie zakończone - łącznie {len(all_issues)} zgłoszeń")
                    break
                    
            except Exception as e:
                jira_logger.exception(f"Błąd podczas pobierania danych z Jira API: {e}")
                if hasattr(e, 'response'):
                    jira_logger.error(f"Response text: {e.response.text}")
                break
        
        # Konwersja do DataFrame (ta sama logika jak w fetch_issues)
        if not all_issues:
            return pd.DataFrame()
            
        records = []
        for issue in all_issues:
            # [Pozostała część kodu identyczna jak w fetch_issues...]
            # Pobierz informacje o zgłaszającym (reporter)
            reporter_info = issue['fields'].get('reporter', {})
            reporter_name = reporter_info.get('displayName', 'Nieznany') if reporter_info else 'Nieznany'
            
            # Pobierz informacje o assignee
            assignee_info = issue['fields'].get('assignee', {})
            assignee_name = assignee_info.get('displayName', 'Nieprzypisany') if assignee_info else 'Nieprzypisany'
            
            # Pobierz informacje o creator
            creator_info = issue['fields'].get('creator', {})
            creator_name = creator_info.get('displayName', 'Nieznany') if creator_info else 'Nieznany'
            
            # Pobierz status
            status_info = issue['fields'].get('status', {})
            status_name = status_info.get('name', 'Nieznany') if status_info else 'Nieznany'
            
            # Pobierz priority
            priority_info = issue['fields'].get('priority', {})
            priority_name = priority_info.get('name', 'Nieznany') if priority_info else 'Nieznany'
            
            # Wyciągnij numer restauracji z reportera
            site = self.extract_site_from_reporter(reporter_name)
            
            # Wyciągnij nazwę restauracji z reportera
            site_name = self.extract_site_name_from_reporter(reporter_name)
            
            # Pobierz custom fields - te mogą mieć różne ID w różnych instancjach Jira
            # Sprawdzimy które pola są dostępne
            team = self.safe_get_field(issue['fields'], 'customfield_10100', 'Nieznany')  # Team
            category = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznana')  # Category (z customfield_10010)
            request_type = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznany')  # Request Type (surowa wartość customfield_10010)
            organisation = self.safe_get_field(issue['fields'], 'customfield_10002', 'Nieznana')  # Organisation
            agent = self.safe_get_field(issue['fields'], 'customfield_10227', 'Nieznany')  # Agent
            
            records.append({
                'key': issue['key'],
                'title': issue['fields']['summary'],
                'created': issue['fields']['created'],
                'issue_type': issue['fields']['issuetype']['name'],
                'reporter': reporter_name,
                'site': site,
                'site_name': site_name,
                'status': status_name,
                'priority': priority_name,
                'last_update': issue['fields'].get('updated', ''),
                'assignee': assignee_name,
                'creator': creator_name,
                'team': team,
                'category': category,
                'request_type': request_type,
                'organisation': organisation,
                'agent': agent
            })
        
        df = pd.DataFrame(records)
        
        # Usunięto filtrowanie exclude_phrases - pobieramy wszystkie zgłoszenia
        # Podstawowe czyszczenie tylko dla title
        df['title_clean'] = df['title'].str.strip()
        df['title_lower'] = df['title_clean'].str.lower()
        
        jira_logger.info(f"Zwracam {len(df)} zgłoszeń (wszystkie bez filtrowania)")
        return df

    def fetch_issues(self, start_date, end_date):
        """Pobiera zgłoszenia z Jira w podanym zakresie dat"""
        
        # Jeśli start_date == end_date, pobieramy cały ten dzień
        # Jeśli start_date != end_date, pobieramy od początku start_date do końca end_date
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        # Uproszczone zapytanie - pobiera wszystkie zgłoszenia z projektu SD w zakresie dat
        jql = f'project = SD AND created >= "{start_str}" AND created <= "{end_str}"'

        url = f"{self.domain}/rest/api/3/search/jql"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        all_issues = []
        next_page_token = None
        batch_size = 100
        
        jira_logger.info(f"Pobieranie danych z Jira dla okresu {start_str} - {end_str}")
        jira_logger.info(f"Używane JQL: {jql}")
        
        while True:
            # Przygotuj parametry dla API v3 (cursor-based pagination)
            params = {
                "jql": jql,
                "maxResults": batch_size,
                "fields": "summary,created,key,issuetype,reporter,status,priority,updated,assignee,creator"
            }
            
            # Dodaj token dla następnej strony jeśli istnieje
            if next_page_token:
                params["nextPageToken"] = next_page_token
            
            try:
                response = requests.get(url, headers=headers, auth=auth, params=params, timeout=30)
                
                if response.status_code == 429:
                    jira_logger.warning("Rate limit hit, czekam...")
                    import time
                    time.sleep(60)
                    continue
                if response.status_code != 200:
                    jira_logger.error(f"Błąd API: Status {response.status_code}")
                    jira_logger.error(f"Response: {response.text}")
                    raise Exception(f"Błąd API: {response.status_code}")
                
                data = response.json()
                issues = data.get('issues', [])
                
                if not issues:
                    break
                    
                all_issues.extend(issues)
                jira_logger.info(f"Pobrano: {len(all_issues)} zgłoszeń...")
                
                # Sprawdź czy to ostatnia strona
                is_last = data.get('isLast', True)
                next_page_token = data.get('nextPageToken')
                
                # Zakończ jeśli to ostatnia strona
                if is_last or not next_page_token:
                    jira_logger.info(f"Pobieranie zakończone - łącznie {len(all_issues)} zgłoszeń")
                    break
                    
            except Exception as e:
                jira_logger.exception(f"Błąd podczas pobierania danych z Jira API: {e}")
                if hasattr(e, 'response'):
                    jira_logger.error(f"Response text: {e.response.text}")
                break
        
        # Konwersja do DataFrame
        if not all_issues:
            return pd.DataFrame()
            
        records = []
        for issue in all_issues:
            # Pobierz informacje o zgłaszającym (reporter)
            reporter_info = issue['fields'].get('reporter', {})
            reporter_name = reporter_info.get('displayName', 'Nieznany') if reporter_info else 'Nieznany'
            
            # Pobierz informacje o assignee
            assignee_info = issue['fields'].get('assignee', {})
            assignee_name = assignee_info.get('displayName', 'Nieprzypisany') if assignee_info else 'Nieprzypisany'
            
            # Pobierz informacje o creator
            creator_info = issue['fields'].get('creator', {})
            creator_name = creator_info.get('displayName', 'Nieznany') if creator_info else 'Nieznany'
            
            # Pobierz status
            status_info = issue['fields'].get('status', {})
            status_name = status_info.get('name', 'Nieznany') if status_info else 'Nieznany'
            
            # Pobierz priority
            priority_info = issue['fields'].get('priority', {})
            priority_name = priority_info.get('name', 'Nieznany') if priority_info else 'Nieznany'
            
            # Wyciągnij numer restauracji z reportera
            site = self.extract_site_from_reporter(reporter_name)
            
            # Wyciągnij nazwę restauracji z reportera
            site_name = self.extract_site_name_from_reporter(reporter_name)
            
            # Pobierz custom fields - te mogą mieć różne ID w różnych instancjach Jira
            # Sprawdzimy które pola są dostępne
            team = self.safe_get_field(issue['fields'], 'customfield_10100', 'Nieznany')  # Team
            category = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznana')  # Category (z customfield_10010)
            request_type = self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznany')  # Request Type (surowa wartość customfield_10010)
            organisation = self.safe_get_field(issue['fields'], 'customfield_10002', 'Nieznana')  # Organisation
            agent = self.safe_get_field(issue['fields'], 'customfield_10227', 'Nieznany')  # Agent
            
            records.append({
                'key': issue['key'],
                'title': issue['fields']['summary'],
                'created': issue['fields']['created'],
                'issue_type': issue['fields']['issuetype']['name'],
                'reporter': reporter_name,
                'site': site,
                'site_name': site_name,
                'status': status_name,
                'priority': priority_name,
                'last_update': issue['fields'].get('updated', ''),
                'assignee': assignee_name,
                'creator': creator_name,
                'team': team,
                'category': category,
                'request_type': request_type,
                'organisation': organisation,
                'agent': agent
            })
        
        df = pd.DataFrame(records)
        
        # Usunięto filtrowanie exclude_phrases - pobieramy wszystkie zgłoszenia
        # Podstawowe czyszczenie tylko dla title
        df['title_clean'] = df['title'].str.strip()
        df['title_lower'] = df['title_clean'].str.lower()
        
        jira_logger.info(f"Zwracam {len(df)} zgłoszeń (wszystkie bez filtrowania)")
        return df
    
    def safe_get_field(self, fields, field_name, default_value):
        """Bezpiecznie pobiera wartość pola, obsługując różne typy danych"""
        try:
            field_value = fields.get(field_name)
            if field_value is None:
                return default_value
            
            # Specjalna obsługa dla customfield_10010 (Request Type) - wyciągnij 'name'
            if field_name == 'customfield_10010' and isinstance(field_value, dict):
                # Na podstawie podanej struktury: szukaj requestType.name
                if 'requestType' in field_value:
                    request_type = field_value['requestType']
                    if isinstance(request_type, dict) and 'name' in request_type:
                        return request_type['name']
                
                # Fallback: szukaj bezpośrednio 'name'
                if 'name' in field_value:
                    return field_value['name']
                
                # Jeśli nie znaleziono, zwróć skróconą wersję
                return str(field_value)[:100] + "..." if len(str(field_value)) > 100 else str(field_value)
            
            # Standardowa obsługa dla innych pól
            # Jeśli to obiekt z 'value' lub 'name'
            if isinstance(field_value, dict):
                if 'value' in field_value:
                    return field_value['value']
                elif 'name' in field_value:
                    return field_value['name']
                elif 'displayName' in field_value:
                    return field_value['displayName']
                else:
                    return str(field_value) if field_value else default_value
            
            # Jeśli to lista
            elif isinstance(field_value, list):
                if len(field_value) > 0:
                    first_item = field_value[0]
                    if isinstance(first_item, dict):
                        if 'value' in first_item:
                            return first_item['value']
                        elif 'name' in first_item:
                            return first_item['name']
                        else:
                            return str(first_item)
                    else:
                        return str(first_item)
                else:
                    return default_value
            
            # Jeśli to zwykła wartość
            else:
                return str(field_value) if field_value else default_value
                
        except Exception as e:
            jira_logger.warning(f"Błąd pobierania pola {field_name}: {e}")
            return default_value
    
    def extract_site_from_reporter(self, reporter_name):
        """Wyciąga numer restauracji z nazwy reportera"""
        if not reporter_name or reporter_name == 'Nieznany':
            return 'Nieznany'
        
        import re
        
        # Wykluczenie asystenta systemowego
        if reporter_name.lower() in ['pl-asista', 'asista', 'system', 'admin']:
            return 'Asystent'
        
        # Wzorce do wyciągania numeru restauracji w kolejności od najbardziej specyficznych
        patterns = [
            # Format McDonald's PL-00XXX (3-cyfrowy efektywny numer)
            r'PL-00(\d{3})',  # PL-00624 -> 624
            r'pl-00(\d{3})',  # pl-00624 -> 624
            
            # Format McDonald's PL-0XXXX (4-cyfrowy efektywny numer)
            r'PL-0(\d{4})',   # PL-01234 -> 1234
            r'pl-0(\d{4})',   # pl-01234 -> 1234
            
            # Format McDonald's PL-XXXXX (5-cyfrowy efektywny numer)
            r'PL-(\d{5})',    # PL-12345 -> 12345
            r'pl-(\d{5})',    # pl-12345 -> 12345
            
            # Format McDonald's na końcu nazwy
            r'PL-00(\d{3})\s',  # "Warszawa Reguly PL-00689" -> 689
            r'PL-0(\d{4})\s',   # "Warszawa Reguly PL-01234" -> 1234
            
            # Ogólne wzorce numerów
            r'(\d{4})',       # 4-cyfrowy numer restauracji
            r'(\d{3})',       # 3-cyfrowy numer restauracji
            r'R(\d+)',        # R123 format
            r'Rest(\d+)',     # Rest123 format
            r'Restauracja\s*(\d+)', # Restauracja 123
        ]
        
        for pattern in patterns:
            match = re.search(pattern, reporter_name)
            if match:
                return match.group(1) if len(match.groups()) == 1 else match.group(0)
        
        # Jeśli nie znaleziono numeru, zwróć "Nieznany"
        return 'Nieznany'
    
    def extract_site_name_from_reporter(self, reporter_name):
        """Wyciąga nazwę restauracji z nazwy reportera"""
        if not reporter_name or reporter_name == 'Nieznany':
            return 'Nieznana'
        
        import re
        
        # Wykluczenie asystenta systemowego
        if reporter_name.lower() in ['pl-asista', 'asista', 'system', 'admin']:
            return 'Asystent systemowy'
        
        # Wzorce do wyciągania nazwy restauracji
        patterns = [
            # Format: "PL-00XXX Nazwa Miasto"
            r'PL-\d{5}\s+(.+)',   # PL-00266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            r'PL-\d{4}\s+(.+)',   # PL-0266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            r'PL-\d{3}\s+(.+)',   # PL-266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            r'pl-\d{5}\s+(.+)',   # pl-00266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            r'pl-\d{4}\s+(.+)',   # pl-0266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            r'pl-\d{3}\s+(.+)',   # pl-266 Krakow 13 Mogilany -> Krakow 13 Mogilany
            
            # Format: "Nazwa PL-00XXX"
            r'(.+)\s+PL-\d{3,5}',  # Warszawa Reguly PL-00689 -> Warszawa Reguly
            r'(.+)\s+pl-\d{3,5}',  # Warszawa Reguly pl-00689 -> Warszawa Reguly
        ]
        
        for pattern in patterns:
            match = re.search(pattern, reporter_name)
            if match:
                name = match.group(1).strip()
                # Ograniczenie długości i czyszczenie
                return name[:50] if name else 'Nieznana'
        
        # Jeśli nie znaleziono wzorca, zwróć całą nazwę (skróconą)
        return reporter_name[:50]
    
    def get_issue_types(self):
        """Pobiera wszystkie dostępne typy zgłoszeń z Jira"""
        url = f"{self.domain}/rest/api/3/issuetype"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        try:
            response = requests.get(url, headers=headers, auth=auth, timeout=30)
            
            if response.status_code != 200:
                jira_logger.error(f"Błąd pobierania typów zgłoszeń: Status {response.status_code}")
                return []
            
            issue_types = response.json()
            # Filtruj tylko typy używane w projekcie SD
            relevant_types = []
            for issue_type in issue_types:
                if issue_type.get('id') in ['10004', '10011', '10066']:  # Incydent, Poważny Incydent, Usługa
                    relevant_types.append({
                        'id': issue_type['id'],
                        'name': issue_type['name'],
                        'description': issue_type.get('description', '')
                    })
            
            jira_logger.info(f"Pobrano {len(relevant_types)} typów zgłoszeń")
            return relevant_types
            
        except Exception as e:
            jira_logger.exception(f"Błąd podczas pobierania typów zgłoszeń: {e}")
            return []
    
    def get_request_types(self, issue_type_id=None):
        """Pobiera dostępne typy żądań z Jira Service Desk, opcjonalnie filtrowane po typie zgłoszenia"""
        # Najpierw pobierz service desk ID dla projektu SD
        url = f"{self.domain}/rest/servicedeskapi/servicedesk"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        try:
            response = requests.get(url, headers=headers, auth=auth, timeout=30)
            
            if response.status_code != 200:
                jira_logger.error(f"Błąd pobierania service desk: Status {response.status_code}")
                return []
            
            service_desks = response.json().get('values', [])
            sd_service_desk_id = None
            
            # Znajdź service desk dla projektu SD
            for sd in service_desks:
                if sd.get('projectKey') == 'SD':
                    sd_service_desk_id = sd.get('id')
                    break
            
            if not sd_service_desk_id:
                jira_logger.error("Nie znaleziono service desk dla projektu SD")
                return []
            
            # Pobierz typy żądań dla znalezionego service desk
            url = f"{self.domain}/rest/servicedeskapi/servicedesk/{sd_service_desk_id}/requesttype"
            response = requests.get(url, headers=headers, auth=auth, timeout=30)
            
            if response.status_code != 200:
                jira_logger.error(f"Błąd pobierania typów żądań: Status {response.status_code}")
                return []
            
            request_types = response.json().get('values', [])
            
            # Przefiltruj i sformatuj typy żądań
            formatted_types = []
            for rt in request_types:
                rt_issue_type_id = rt.get('issueTypeId')
                
                # Jeśli podano issue_type_id, filtruj tylko pasujące typy żądań
                if issue_type_id and rt_issue_type_id != issue_type_id:
                    continue
                
                formatted_types.append({
                    'id': rt.get('id'),
                    'name': rt.get('name'),
                    'description': rt.get('description', ''),
                    'issueTypeId': rt_issue_type_id
                })
            
            if issue_type_id:
                jira_logger.info(f"Pobrano {len(formatted_types)} typów żądań dla typu zgłoszenia {issue_type_id}")
            else:
                jira_logger.info(f"Pobrano {len(formatted_types)} typów żądań (wszystkie)")
            return formatted_types
            
        except Exception as e:
            jira_logger.exception(f"Błąd podczas pobierania typów żądań: {e}")
            return []
    
    def update_issue_type(self, issue_key, new_issue_type_id):
        """Aktualizuje typ zgłoszenia dla podanego klucza"""
        url = f"{self.domain}/rest/api/3/issue/{issue_key}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        auth = (self.email, self.token)
        
        payload = {
            "fields": {
                "issuetype": {
                    "id": new_issue_type_id
                }
            }
        }
        
        try:
            response = requests.put(url, headers=headers, auth=auth, json=payload, timeout=30)
            
            if response.status_code == 204:
                jira_logger.info(f"Pomyślnie zaktualizowano typ zgłoszenia dla {issue_key}")
                return True
            else:
                jira_logger.error(f"Błąd aktualizacji typu zgłoszenia {issue_key}: Status {response.status_code}")
                jira_logger.error(f"Response: {response.text}")
                return False
                
        except Exception as e:
            jira_logger.exception(f"Błąd podczas aktualizacji typu zgłoszenia {issue_key}: {e}")
            return False
    
    def update_request_type(self, issue_key, new_request_type_id):
        """Aktualizuje typ żądania (customfield_10010) dla podanego klucza"""
        
        # Najpierw spróbuj standardowego Jira API
        success = self._update_request_type_standard(issue_key, new_request_type_id)
        if success:
            return True
        
        # Jeśli standardowe API nie działa, spróbuj Service Desk API
        jira_logger.info(f"Standardowe API nie powiodło się dla {issue_key}, próbuję Service Desk API...")
        return self.update_request_type_servicedesk(issue_key, new_request_type_id)
    
    def _update_request_type_standard(self, issue_key, new_request_type_id):
        """Próbuje aktualizować typ żądania przez standardowe Jira API"""
        url = f"{self.domain}/rest/api/3/issue/{issue_key}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        auth = (self.email, self.token)
        
        # Spróbuj różnych struktur dla customfield_10010
        payloads_to_try = [
            # Struktura 1: Proste ID
            {
                "fields": {
                    "customfield_10010": new_request_type_id
                }
            },
            # Struktura 2: Object z id
            {
                "fields": {
                    "customfield_10010": {
                        "id": new_request_type_id
                    }
                }
            },
            # Struktura 3: requestType zagnieżdżone (obecne)
            {
                "fields": {
                    "customfield_10010": {
                        "requestType": {
                            "id": new_request_type_id
                        }
                    }
                }
            }
        ]
        
        for i, payload in enumerate(payloads_to_try, 1):
            try:
                jira_logger.info(f"Standardowe API - Próba {i}/3 dla {issue_key}")
                response = requests.put(url, headers=headers, auth=auth, json=payload, timeout=30)
                
                if response.status_code == 204:
                    jira_logger.info(f"Pomyślnie zaktualizowano typ żądania przez standardowe API dla {issue_key} (metoda {i})")
                    return True
                else:
                    jira_logger.warning(f"Standardowe API - Próba {i} nieudana dla {issue_key}: Status {response.status_code}")
                    jira_logger.warning(f"Response: {response.text}")
                        
            except Exception as e:
                jira_logger.warning(f"Standardowe API - Próba {i} dla {issue_key} rzuciła wyjątek: {e}")
                    
        return False
    
    def update_request_type_servicedesk(self, issue_key, new_request_type_id):
        """Alternatywna metoda aktualizacji typu żądania używając Service Desk API"""
        # Najpierw pobierz Service Desk ID
        url = f"{self.domain}/rest/servicedeskapi/servicedesk"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        try:
            response = requests.get(url, headers=headers, auth=auth, timeout=30)
            if response.status_code != 200:
                jira_logger.error(f"Błąd pobierania service desk: Status {response.status_code}")
                return False
            
            service_desks = response.json().get('values', [])
            sd_service_desk_id = None
            
            # Znajdź service desk dla projektu SD
            for sd in service_desks:
                if sd.get('projectKey') == 'SD':
                    sd_service_desk_id = sd.get('id')
                    break
            
            if not sd_service_desk_id:
                jira_logger.error("Nie znaleziono service desk dla projektu SD")
                return False
            
            # Spróbuj zaktualizować przez Service Desk API
            # Metoda 1: Update request
            sd_url = f"{self.domain}/rest/servicedeskapi/request/{issue_key}"
            sd_payload = {
                "requestTypeId": new_request_type_id,
                "serviceDeskId": sd_service_desk_id
            }
            
            headers["Content-Type"] = "application/json"
            response = requests.put(sd_url, headers=headers, auth=auth, json=sd_payload, timeout=30)
            
            if response.status_code in [200, 204]:
                jira_logger.info(f"Pomyślnie zaktualizowano typ żądania przez Service Desk API dla {issue_key}")
                return True
            else:
                jira_logger.warning(f"Service Desk API nieudane dla {issue_key}: Status {response.status_code}")
                jira_logger.warning(f"Response: {response.text}")
                return False
                
        except Exception as e:
            jira_logger.exception(f"Błąd Service Desk API dla {issue_key}: {e}")
            return False
    
    def validate_issue_keys(self, issue_keys):
        """Waliduje i pobiera informacje o zgłoszeniach na podstawie kluczy"""
        valid_issues = []
        invalid_issues = []
        
        # Utwórz JQL do pobrania wszystkich zgłoszeń jednym zapytaniem
        keys_str = ",".join(issue_keys)
        jql = f'key IN ({keys_str})'
        
        url = f"{self.domain}/rest/api/3/search/jql"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        params = {
            "jql": jql,
            "fields": "key,summary,issuetype,customfield_10010",
            "maxResults": 1000
        }
        
        try:
            response = requests.get(url, headers=headers, auth=auth, params=params, timeout=30)
            
            if response.status_code != 200:
                jira_logger.error(f"Błąd walidacji kluczy: Status {response.status_code}")
                return valid_issues, issue_keys  # Wszystkie klucze jako nieprawidłowe
            
            data = response.json()
            found_issues = data.get('issues', [])
            found_keys = [issue['key'] for issue in found_issues]
            
            # Przygotuj informacje o znalezionych zgłoszeniach
            for issue in found_issues:
                issue_info = {
                    'key': issue['key'],
                    'summary': issue['fields']['summary'],
                    'current_issue_type': issue['fields']['issuetype']['name'],
                    'current_issue_type_id': issue['fields']['issuetype']['id'],
                    'current_request_type': self.safe_get_field(issue['fields'], 'customfield_10010', 'Nieznany')
                }
                valid_issues.append(issue_info)
            
            # Znajdź klucze, które nie zostały znalezione
            invalid_issues = [key for key in issue_keys if key not in found_keys]
            
            jira_logger.info(f"Walidacja kluczy: {len(valid_issues)} prawidłowych, {len(invalid_issues)} nieprawidłowych")
            return valid_issues, invalid_issues
            
        except Exception as e:
            jira_logger.exception(f"Błąd podczas walidacji kluczy: {e}")
            return [], issue_keys
