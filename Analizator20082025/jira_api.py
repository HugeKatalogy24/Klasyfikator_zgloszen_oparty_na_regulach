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
        self.email = os.getenv('JIRA_EMAIL', "dominik.rochaczewski@pl.mcd.com")
        self.token = os.getenv('JIRA_TOKEN')
        
        if not self.token:
            raise ValueError("JIRA_TOKEN nie został ustawiony w zmiennych środowiskowych")
    
    def estimate_issues_count(self, start_date, end_date):
        """Szybkie oszacowanie liczby zgłoszeń bez pobierania pełnych danych"""
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        jql = f'project = SD AND issuetype IN (10004, 10011, 10066) AND created >= "{start_str}" AND created <= "{end_str}"'
        
        url = f"{self.domain}/rest/api/2/search"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        params = {
            "jql": jql,
            "startAt": 0,
            "maxResults": 1,  # Pobieramy tylko jeden rekord, aby uzyskać total
            "fields": "key"
        }
        
        try:
            response = requests.get(url, headers=headers, auth=auth, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                total_count = data.get('total', 0)
                jira_logger.info(f"Szacowana liczba zgłoszeń: {total_count}")
                return total_count
            else:
                jira_logger.warning(f"Nie udało się oszacować liczby zgłoszeń: Status {response.status_code}")
                return None
        except Exception as e:
            jira_logger.warning(f"Błąd podczas szacowania liczby zgłoszeń: {e}")
            return None

    def fetch_issues_with_progress(self, start_date, end_date, analysis_id=None, progress_dict=None):
        """Pobiera zgłoszenia z Jira w podanym zakresie dat z raportowaniem postępu"""
        
        # Jeśli start_date == end_date, pobieramy cały ten dzień
        # Jeśli start_date != end_date, pobieramy od początku start_date do końca end_date
        start_str = start_date.strftime('%Y-%m-%d 00:00')
        end_str = end_date.strftime('%Y-%m-%d 23:59')
        
        # Typy zgłoszeń: 10004=Incydent, 10011=Poważny Incydent, 10066=Usługa
        # Pobieramy wszystkie zgłoszenia z projektu SD - usunięto wykluczenie "Telefon do zgłoszenia"
        jql = f'project = SD AND issuetype IN (10004, 10011, 10066) AND created >= "{start_str}" AND created <= "{end_str}"'

        url = f"{self.domain}/rest/api/2/search"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        all_issues = []
        start_at = 0
        batch_size = 100
        
        jira_logger.info(f"Pobieranie danych z Jira dla okresu {start_str} - {end_str}")
        jira_logger.info(f"Używane JQL: {jql}")
        
        # Najpierw sprawdź łączną liczbę zgłoszeń
        initial_params = {
            "jql": jql,
            "startAt": 0,
            "maxResults": 1,
            "fields": "key"
        }
        
        try:
            response = requests.get(url, headers=headers, auth=auth, params=initial_params, timeout=30)
            if response.status_code == 200:
                total_issues = response.json().get('total', 0)
                jira_logger.info(f"Znaleziono łącznie {total_issues} zgłoszeń do pobrania")
            else:
                total_issues = None
        except:
            total_issues = None
        
        while True:
            params = {
                "jql": jql,
                "startAt": start_at,
                "maxResults": batch_size,
                "fields": "summary,created,key,issuetype,reporter,status,priority,updated,assignee,creator,customfield_10100,customfield_10010,customfield_10002,customfield_10227"
            }
            
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
                issues = data.get('issues', [])
                
                if not issues:
                    break
                    
                all_issues.extend(issues)
                start_at += batch_size
                
                jira_logger.info(f"Pobrano: {len(all_issues)} zgłoszeń...")
                
                # Aktualizuj postęp, jeśli przekazano parametry
                if analysis_id and progress_dict and analysis_id in progress_dict:
                    if total_issues and total_issues > 0:
                        # Postęp pobierania: od 15% do 75%
                        fetch_progress = min(75, 15 + (len(all_issues) / total_issues) * 60)
                    else:
                        # Szacunkowy postęp na podstawie liczby pobranych
                        fetch_progress = min(75, 15 + min(len(all_issues) / 500, 1) * 60)
                    
                    start_time = progress_dict[analysis_id].get('start_time', time.time())
                    elapsed = time.time() - start_time
                    
                    # Bardziej realistyczne szacowanie pozostałego czasu
                    if len(all_issues) > 20:  # Mamy wystarczająco dużo danych do szacowania
                        if total_issues and total_issues > 0:
                            # Oblicz rzeczywisty czas na zgłoszenie
                            time_per_issue = elapsed / len(all_issues)
                            remaining_issues = total_issues - len(all_issues)
                            estimated_remaining_fetch = remaining_issues * time_per_issue
                            # Dodaj czas na klasyfikację (2-8 sekund w zależności od liczby)
                            classify_time = max(2, min(total_issues * 0.002, 8))
                            eta = max(1, estimated_remaining_fetch + classify_time)
                        else:
                            # Prostsze szacowanie jeśli nie znamy total
                            eta = max(5, 30 - elapsed)  # Maksymalnie 30 sekund łącznie
                    else:
                        # Na początku - konserwatywne szacowanie
                        if total_issues and total_issues > 0:
                            eta = max(5, total_issues * 0.05 + 5 - elapsed)  # 0.05s na zgłoszenie + overhead
                        else:
                            eta = max(10, 25 - elapsed)  # Domyślnie 25 sekund łącznie
                    
                    progress_dict[analysis_id].update({
                        'progress': fetch_progress,
                        'status': f'Pobrano {len(all_issues)}{f"/{total_issues}" if total_issues else ""} zgłoszeń...',
                        'eta_seconds': int(max(1, eta))  # Minimum 1 sekunda
                    })
                
                if len(issues) < batch_size:
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
        
        # Typy zgłoszeń: 10004=Incydent, 10011=Poważny Incydent, 10066=Usługa
        # Pobieramy wszystkie zgłoszenia z projektu SD - usunięto wykluczenie "Telefon do zgłoszenia"
        jql = f'project = SD AND issuetype IN (10004, 10011, 10066) AND created >= "{start_str}" AND created <= "{end_str}"'

        url = f"{self.domain}/rest/api/2/search"
        headers = {"Accept": "application/json"}
        auth = (self.email, self.token)
        
        all_issues = []
        start_at = 0
        batch_size = 100
        
        jira_logger.info(f"Pobieranie danych z Jira dla okresu {start_str} - {end_str}")
        jira_logger.info(f"Używane JQL: {jql}")
        
        while True:
            params = {
                "jql": jql,
                "startAt": start_at,
                "maxResults": batch_size,
                "fields": "summary,created,key,issuetype,reporter,status,priority,updated,assignee,creator,customfield_10100,customfield_10010,customfield_10002,customfield_10227"
            }
            
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
                start_at += batch_size
                
                jira_logger.info(f"Pobrano: {len(all_issues)} zgłoszeń...")
                
                if len(issues) < batch_size:
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
        url = f"{self.domain}/rest/api/2/issuetype"
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
        url = f"{self.domain}/rest/api/2/issue/{issue_key}"
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
        url = f"{self.domain}/rest/api/2/issue/{issue_key}"
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
        
        url = f"{self.domain}/rest/api/2/search"
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
