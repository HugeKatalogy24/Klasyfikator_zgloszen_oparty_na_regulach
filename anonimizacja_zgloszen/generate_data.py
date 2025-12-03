import pandas as pd
import random
import json
import os
import re
import string
from faker import Faker
from datetime import datetime, timedelta

# Konfiguracja
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEL_FILENAME = os.path.join(OUTPUT_DIR, 'zgloszenia_testowe_v10.xlsx')
JSON_FILENAME = os.path.join(OUTPUT_DIR, 'test_rules.json')

START_DATE = datetime(2025, 11, 1)
END_DATE = datetime(2025, 11, 10)
MIN_DAILY_TICKETS = 300
MAX_DAILY_TICKETS = 500
KNOWN_CATEGORY_RATIO = 0.35  # 35% znanych, 65% szumu

fake = Faker('pl_PL')

# --- LOGIKA PUNKTACJI (Z CLASSIFIER.PY) ---

def normalize_text(text):
    """Normalizuje tekst usuwając polskie znaki diakrytyczne"""
    if not isinstance(text, str):
        return text
    polish_chars = {
        'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 
        'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z',
        'Ą': 'A', 'Ć': 'C', 'Ę': 'E', 'Ł': 'L', 'Ń': 'N',
        'Ó': 'O', 'Ś': 'S', 'Ź': 'Z', 'Ż': 'Z'
    }
    normalized = text
    for polish, latin in polish_chars.items():
        normalized = normalized.replace(polish, latin)
    return normalized

def calculate_rule_score(title, rule):
    """Oblicza wynik dopasowania tytułu do reguły (logika z classifier.py)"""
    if not isinstance(title, str): return 0
    
    title_lower = title.lower()
    title_normalized = normalize_text(title_lower)
    score = 0
    
    # 1. Forbidden
    if 'forbidden' in rule:
        for forbidden in rule['forbidden']:
            forbidden_normalized = normalize_text(forbidden)
            if (forbidden in title_lower or 
                forbidden_normalized in title_normalized or
                forbidden in title_normalized):
                return 0 # Odrzucenie
                
    # 2. Combinations
    if 'required_combinations' in rule:
        for combination in rule['required_combinations']:
            all_words_found = True
            for word in combination:
                word_normalized = normalize_text(word)
                word_found = (word in title_lower or 
                            word_normalized in title_normalized or
                            word in title_normalized)
                if not word_found:
                    all_words_found = False
                    break
            
            if all_words_found:
                if len(combination) == 2: score += 3
                elif len(combination) == 3: score += 4
                else: score += len(combination)

    # 3. Keywords
    if 'keywords' in rule:
        for keyword in rule['keywords']:
            try:
                escaped_keyword = re.escape(keyword)
                keyword_normalized = normalize_text(keyword)
                escaped_keyword_normalized = re.escape(keyword_normalized)
                
                if (re.search(escaped_keyword, title_lower) or 
                    re.search(escaped_keyword_normalized, title_normalized) or
                    re.search(escaped_keyword, title_normalized)):
                    score += 1
            except:
                pass
                
    return score

# --- BAZA DANYCH DO GENEROWANIA (PROFESJONALNA - KONKRETNE BŁĘDY) ---

# Prefiksy
PREFIXES = [
    "Zgłoszenie awarii:", "Problem techniczny:", "Błąd systemu:", 
    "Awaria:", "Incydent:", "Prośba o wsparcie:", 
    "Dotyczy:", "Wymagany serwis:", ""
]

# Sufiksy
SUFFIXES = [
    "- prośba o pilną weryfikację.", "- stanowisko nieczynne.", 
    "- blokuje obsługę klienta.", "- wymagany restart nie pomógł.",
    "- prośba o interwencję.", "- błąd powtarzalny."
]

# Słownik kategorii ZNANYCH (Specyficzne błędy/symptomy zamiast ogólnych grup)
KNOWN_CATEGORIES = {
    "POS - Błąd zamknięcia doby": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "zamknięcie dnia", "raport dobowy", "zamknięcie doby", "z-report", 
            "fiskalizacja doby", "procedura zamknięcia"
        ],
        "forbidden": ["drukarka biurowa", "faktura", "excel"],
        "required_combinations": [
            ["zamknięcie", "dnia"],
            ["raport", "dobowy"],
            ["błąd", "zamknięcia"],
            ["z-report", "błąd"]
        ],
        "components": [
            ["Błąd krytyczny bazy danych podczas zamknięcia dnia", "Niepowodzenie generowania raportu dobowego - timeout", "System zawiesza się przy zamykaniu doby (SQL Error)", "Błąd spójności danych przy Z-Report"],
            ["na stanowisku POS {n}", "na głównej kasie", "w systemie centralnym"],
            ["komunikat: Database Locked", "brak wydruku potwierdzenia", "proces zatrzymuje się na 90%"]
        ]
    },
    "RCP - Błąd synchronizacji": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "czas pracy", "ewidencja", "odbicie karty", "rejestracja czasu", 
            "korekta godzin", "RCP"
        ],
        "forbidden": ["logowanie do windows", "hasło"],
        "required_combinations": [
            ["czas", "pracy"],
            ["odbicie", "karty"],
            ["rejestracja", "czasu"],
            ["błąd", "rcp"]
        ],
        "components": [
            ["Błąd synchronizacji ewidencji czasu pracy z serwerem", "Czytnik RCP nie przesyła odbić do systemu", "Nieprawidłowe naliczenie godzin - błąd algorytmu", "Brak rejestracji wejścia mimo poprawnego odbicia"],
            ["dla pracownika {name}", "dotyczy całego zespołu", "błąd systemowy"],
            ["karta pracownicza nie została zaczytana", "system nie uwzględnił nadgodzin", "błędna data w raporcie"]
        ]
    },
    "POS - Zawieszenie aplikacji": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "system pos", "aplikacja sprzedażowa", "zawieszenie systemu", 
            "brak reakcji", "zamrożenie ekranu"
        ],
        "forbidden": ["internet", "outlook", "excel"],
        "required_combinations": [
            ["system", "pos"],
            ["zawieszenie", "systemu"],
            ["brak", "reakcji"],
            ["zamrożenie", "ekranu"]
        ],
        "components": [
            ["Całkowite zawieszenie procesu aplikacji sprzedażowej", "Aplikacja POS przestała odpowiadać (Not Responding)", "Brak reakcji interfejsu na dotyk - freeze", "Czarny ekran na stanowisku sprzedażowym - proces tła działa"],
            ["stanowisko nr {n}", "wszystkie kasy", "terminal kasjerski"],
            ["wymagany twardy reset", "wyciek pamięci RAM", "aplikacja zamknęła się samoistnie"]
        ]
    },
    "POS - Błąd interfejsu": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "ikona ostrzegawcza", "błąd graficzny", "interfejs użytkownika", 
            "komunikat ekranowy", "GUI"
        ],
        "forbidden": ["drukarka", "toner"],
        "required_combinations": [
            ["błąd", "graficzny"],
            ["ikona", "ostrzegawcza"],
            ["interfejs", "użytkownika"],
            ["błąd", "gui"]
        ],
        "components": [
            ["Błąd renderowania ikon na pasku statusu", "Artefakty graficzne w interfejsie użytkownika", "Mrugający komunikat błędu UI na ekranie głównym", "Zniekształcony layout przycisków funkcyjnych"],
            ["zasłania przyciski funkcyjne", "uniemożliwia pracę", "na ekranie logowania"],
            ["kod błędu GUI-102", "pojawia się po zalogowaniu", "problem sterownika graficznego"]
        ]
    },
    "Terminal - Błąd komunikacji": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "terminal płatniczy", "pinpad", "transakcja odrzucona", 
            "brak komunikacji z bankiem", "autoryzacja"
        ],
        "forbidden": ["karta pracownicza", "logowanie"],
        "required_combinations": [
            ["terminal", "płatniczy"],
            ["transakcja", "odrzucona"],
            ["brak", "komunikacji"],
            ["błąd", "autoryzacji"]
        ],
        "components": [
            ["Utrata komunikacji z terminalem płatniczym (PED)", "Odrzucenie transakcji - błąd połączenia TCP/IP", "Pinpad nie otrzymuje zasilania z portu USB", "Błąd inicjalizacji protokołu płatniczego"],
            ["model Verifone", "model Ingenico", "na kasie nr {n}"],
            ["kod błędu ECR-TIMEOUT", "brak sygnału", "nie drukuje potwierdzenia"]
        ]
    },
    "Drukarka fiskalna - Błąd pamięci": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "drukarka fiskalna", "moduł fiskalny", "brak wydruku paragonu", 
            "błąd pamięci"
        ],
        "forbidden": ["drukarka sieciowa", "biurowa", "faktura"],
        "required_combinations": [
            ["drukarka", "fiskalna"],
            ["błąd", "pamięci"],
            ["brak", "wydruku"],
            ["moduł", "fiskalny"]
        ],
        "components": [
            ["Błąd sumy kontrolnej pamięci fiskalnej", "Awaria mechanizmu tnącego w drukarce fiskalnej", "Zablokowany bufor wydruku fiskalnego", "Błąd komunikacji RS232 z drukarką fiskalną"],
            ["stanowisko {n}", "drukarka Epson", "drukarka Posnet"],
            ["dioda Error świeci ciągle", "nie można zafiskalizować transakcji", "paragon nie wysuwa się"]
        ]
    },
    "Dostęp - Błąd autoryzacji POS": {
        "type": "[System] Service request",
        "min_score": 3,
        "keywords": [
            "logowanie do pos", "uprawnienia kasjera", "błąd autoryzacji", 
            "konto użytkownika", "dostęp zablokowany"
        ],
        "forbidden": ["domena", "windows", "vpn"],
        "required_combinations": [
            ["błąd", "autoryzacji"],
            ["konto", "użytkownika"],
            ["dostęp", "zablokowany"],
            ["logowanie", "pos"]
        ],
        "components": [
            ["Zablokowane konto kasjera - przekroczona liczba prób", "Prośba o reset hasła użytkownika POS", "Brak uprawnień do funkcji kierowniczych", "Konto użytkownika wygasło"],
            ["użytkownik {name}", "stanowisko {n}"],
            ["komunikat: Invalid Credentials", "karta magnetyczna nieaktywna", "wymagany reset uprawnień"]
        ]
    },
    "System - Opóźnienie replikacji": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "synchronizacja danych", "aktualizacja cennika", "błąd cen", 
            "replikacja", "baza produktów"
        ],
        "forbidden": ["czas pracy"],
        "required_combinations": [
            ["synchronizacja", "danych"],
            ["aktualizacja", "cennika"],
            ["błąd", "cen"],
            ["replikacja", "danych"]
        ],
        "components": [
            ["Opóźnienie replikacji cennika z serwera centralnego", "Niespójność sumy kontrolnej bazy produktów", "Błąd procedury aktualizacji PLU", "Zatrzymany serwis synchronizacji danych"],
            ["na wszystkich stanowiskach", "kasa nr {n}"],
            ["ceny nie zaktualizowały się", "brak pozycji promocyjnych", "błąd wersji bazy danych"]
        ]
    },
    "Kiosk - Awaria dotyku": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "kiosk samoobsługowy", "ngk", "ekran dotykowy kiosku", 
            "terminal kiosku"
        ],
        "forbidden": ["kasa tradycyjna"],
        "required_combinations": [
            ["kiosk", "samoobsługowy"],
            ["ekran", "dotykowy"],
            ["terminal", "kiosku"],
            ["awaria", "kiosku"]
        ],
        "components": [
            ["Awaria kontrolera dotyku w kiosku samoobsługowym", "Zawieszenie aplikacji KioskApp.exe", "Błąd inicjalizacji urządzenia płatniczego w kiosku", "Czarny ekran kiosku - brak sygnału wideo"],
            ["urządzenie wyłączone z eksploatacji", "ekran czarny", "system nie startuje"],
            ["wymagany serwis on-site", "błąd krytyczny aplikacji", "nie przyjmuje zamówień"]
        ]
    },
    "Waga - Błąd kalibracji": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "waga systemowa", "moduł ważący", "błąd tarowania", 
            "kalibracja wagi"
        ],
        "forbidden": ["towar"],
        "required_combinations": [
            ["waga", "systemowa"],
            ["błąd", "tarowania"],
            ["kalibracja", "wagi"],
            ["moduł", "ważący"]
        ],
        "components": [
            ["Błąd protokołu komunikacyjnego wagi systemowej", "Utrata kalibracji modułu ważącego", "Błąd tarowania - wartość poza zakresem", "Waga nie zwraca stabilnego odczytu"],
            ["stanowisko {n}", "waga Dibal", "waga CAS"],
            ["wymagana ponowna kalibracja", "wartość ujemna na wyświetlaczu", "blokuje sprzedaż produktów ważonych"]
        ]
    },
    "KDS - Brak sygnału wideo": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "system kds", "ekran kuchenny", "kontroler wideo", 
            "bumpbar", "wyświetlanie zamówień"
        ],
        "forbidden": ["biuro"],
        "required_combinations": [
            ["system", "kds"],
            ["ekran", "kuchenny"],
            ["kontroler", "wideo"],
            ["wyświetlanie", "zamówień"]
        ],
        "components": [
            ["Utrata sygnału wideo na kontrolerze KDS", "Błąd serwisu kolejkowania zamówień kuchennych", "Opóźnienia w renderowaniu na ekranach KDS", "Uszkodzony interfejs wejściowy Bumpbar"],
            ["stacja grill", "stacja napojów", "ekran ekspedycji"],
            ["zamówienia nie pojawiają się", "brak sygnału wideo", "system offline"]
        ]
    },
    "Aplikacja mobilna - Błąd API": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "aplikacja lojalnościowa", "skaner qr", "kupon mobilny", 
            "integracja mobile"
        ],
        "forbidden": ["kiosk", "skaner ręczny"],
        "required_combinations": [
            ["aplikacja", "lojalnościowa"],
            ["skaner", "qr"],
            ["kupon", "mobilny"],
            ["integracja", "mobile"]
        ],
        "components": [
            ["Błąd API podczas walidacji kuponu mobilnego", "Timeout połączenia z bramką zamówień mobilnych", "Nieprawidłowy format danych JSON z aplikacji", "Awaria mikroserwisu obsługi mobile"],
            ["zgłaszane przez klientów", "błąd API"],
            ["nie nalicza rabatów", "zamówienie nie dociera do POS", "błąd serwera"]
        ]
    },
    "Loyalty - Niedostępność serwisu": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "system lojalnościowy", "karta klienta", "punkty loyalty", 
            "serwer loyalty"
        ],
        "forbidden": ["karta płatnicza"],
        "required_combinations": [
            ["system", "lojalnościowy"],
            ["karta", "klienta"],
            ["punkty", "loyalty"],
            ["serwer", "loyalty"]
        ],
        "components": [
            ["Brak odpowiedzi z serwera lojalnościowego (Service Unavailable)", "Błąd autoryzacji tokena karty klienta", "Niemożność zapisu transakcji punktowej - błąd DB", "Awaria webserwisu obsługi nagród"],
            ["komunikat: system offline", "błąd bazy danych"],
            ["klient nie widzi punktów", "transakcja bez identyfikacji", "timeout połączenia"]
        ]
    },
    "Skaner - Błąd sterownika": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "czytnik kodów", "skaner ręczny", "skaner stacjonarny", 
            "brak odczytu kodu"
        ],
        "forbidden": ["skaner dokumentów"],
        "required_combinations": [
            ["czytnik", "kodów"],
            ["skaner", "ręczny"],
            ["brak", "odczytu"],
            ["skaner", "stacjonarny"]
        ],
        "components": [
            ["Błąd sterownika HID skanera kodów", "Czytnik nie dekoduje standardu EAN-13", "Uszkodzenie modułu laserowego skanera", "Błąd enumeracji urządzenia USB (Skaner)"],
            ["stanowisko {n}", "skaner Zebra", "skaner Honeywell"],
            ["nie świeci wiązka lasera", "błąd interfejsu USB", "przerywa połączenie"]
        ]
    },
    "Faktury - Błąd API": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "moduł faktur", "wystawianie faktury", "nip nabywcy", 
            "wydruk faktury"
        ],
        "forbidden": ["paragon"],
        "required_combinations": [
            ["moduł", "faktur"],
            ["wystawianie", "faktury"],
            ["nip", "nabywcy"],
            ["wydruk", "faktury"]
        ],
        "components": [
            ["Wyjątek w module fakturowania - NullReferenceException", "Błąd walidacji NIP w zewnętrznym API GUS", "Błąd generowania pliku PDF faktury", "Niemożność zapisu faktury do repozytorium"],
            ["błąd walidacji danych", "problem z bazą GUS"],
            ["dokument nie został utworzony", "błędne dane kontrahenta", "zawieszenie modułu fakturowania"]
        ]
    },
    "Szuflada - Awaria otwarcia": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "szuflada kasowa", "elektromagnes", "otwarcie szuflady", 
            "kasetka pieniężna"
        ],
        "forbidden": ["sejf"],
        "required_combinations": [
            ["szuflada", "kasowa"],
            ["otwarcie", "szuflady"],
            ["kasetka", "pieniężna"],
            ["awaria", "szuflady"]
        ],
        "components": [
            ["Awaria elektromagnesu otwierającego szufladę (Solenoid)", "Brak sygnału sterującego otwarciem szuflady (RJ11)", "Mechaniczne zablokowanie prowadnicy szuflady", "Błąd czujnika otwarcia szuflady"],
            ["stanowisko {n}", "klucz utknął w zamku"],
            ["nie można wydać reszty", "szuflada nie domyka się", "awaria mechaniczna"]
        ]
    },
    "RCP - Korekta czasu": {
        "type": "[System] Service request",
        "min_score": 3,
        "keywords": [
            "korekta czasu", "zapomniałem odbić", "złe odbicie", "edycja czasu",
            "wniosek o korektę", "błędne godziny"
        ],
        "forbidden": ["błąd synchronizacji", "awaria", "czytnik"],
        "required_combinations": [
            ["korekta", "czasu"],
            ["edycja", "czasu"],
            ["złe", "odbicie"],
            ["wniosek", "korektę"]
        ],
        "components": [
            ["Prośba o korektę czasu pracy - zapomniane odbicie", "Wniosek o edycję godzin - błędnie wybrane wejście", "Prośba o anulowanie błędnego odbicia RCP", "Uzupełnienie brakującego czasu pracy"],
            ["pracownik {name}", "data wczorajsza"],
            ["zapomniałem karty", "odbicie prywatne zamiast służbowego", "pomyłka przy rejestracji"]
        ]
    }
}

# --- SZUM (NOISE) - KATEGORIE "INNE" (PROFESJONALNE IT) ---
# Wyłącznie problemy IT, ale nie pasujące do powyższych kategorii Retail.
# Brak "cieknących sufitów" i "braku papieru w toalecie".
NOISE_CATEGORIES = {
    "SPRZET_BIUROWY": {
        "type": "[System] Incident",
        "templates": [
            "Awaria stacji dokującej laptopa", "Monitor zewnętrzny nie wykrywa sygnału", 
            "Uszkodzona matryca w laptopie służbowym", "Mysz bezprzewodowa nie paruje się z odbiornikiem", 
            "Klawiatura numeryczna nie działa", "Problem z zasilaczem do laptopa Dell", 
            "Słuchawki z mikrofonem nie są wykrywane przez system", "Uszkodzone gniazdo LAN w ścianie", 
            "Drukarka sieciowa w biurze offline", "Zacięcie papieru w urządzeniu wielofunkcyjnym",
            "Brak tonera w drukarce korytarzowej", "Skaner dokumentów nie pobiera kartek"
        ]
    },
    "OPROGRAMOWANIE_BIUROWE": {
        "type": "[System] Incident",
        "templates": [
            "Błąd uruchamiania Microsoft Outlook", "Excel zawiesza się przy otwieraniu pliku", 
            "Brak dostępu do dysku sieciowego Z:", "Problem z certyfikatem VPN", 
            "Nieudana aktualizacja systemu Windows", "Błąd licencji pakietu Office", 
            "Przeglądarka Chrome nie ładuje stron intranetu", "Program antywirusowy blokuje aplikację", 
            "Teams nie łączy z spotkaniem", "Adobe Reader nie otwiera plików PDF"
        ]
    },
    "KONTA_I_DOSTEPIE": {
        "type": "[System] Service request",
        "templates": [
            "Zablokowane konto domenowe AD", "Wygasło hasło do systemu Windows", 
            "Brak dostępu do folderu współdzielonego", "Prośba o nadanie uprawnień do grupy", 
            "Problem z uwierzytelnianiem dwuskładnikowym (MFA)", "Konto pocztowe przepełnione", 
            "Nie działa logowanie do portalu pracowniczego", "Błąd synchronizacji hasła"
        ]
    },
    "SIEC_I_INFRASTRUKTURA": {
        "type": "[System] Incident",
        "templates": [
            "Brak dostępu do sieci Wi-Fi", "Niska przepustowość łącza internetowego", 
            "Telefon VoIP nie ma sygnału", "Błąd konfiguracji adresu IP", 
            "Utrata połączenia z serwerem plików", "Awaria switcha w szafie rack", 
            "Brak dostępu do zasobów zewnętrznych"
        ]
    }
}

def introduce_typos(text):
    """Wprowadza realistyczne literówki (brak polskich znaków)"""
    if not isinstance(text, str): return text
    
    # Szansa na wystąpienie literówki w całym tekście
    if random.random() > 0.15: # 15% szans na modyfikację
        return text
        
    chars = list(text)
    for i, char in enumerate(chars):
        # Zamiana polskich znaków na łacińskie (np. ł -> l, ń -> n)
        if char in 'ąęćłńóśźżĄĘĆŁŃÓŚŹŻ':
            if random.random() < 0.3: # 30% szans na zmianę konkretnego znaku
                replacements = {
                    'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 
                    'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z',
                    'Ą': 'A', 'Ć': 'C', 'Ę': 'E', 'Ł': 'L', 'Ń': 'N',
                    'Ó': 'O', 'Ś': 'S', 'Ź': 'Z', 'Ż': 'Z'
                }
                chars[i] = replacements.get(char, char)
    
    return "".join(chars)

def lowercase_start(text):
    """Zmienia pierwszą literę na małą"""
    if not isinstance(text, str) or len(text) == 0: return text
    
    if random.random() < 0.15: # 15% szans na małą literę na początku
        return text[0].lower() + text[1:]
    return text

def generate_dynamic_description(category_key):
    """Buduje unikalne zdanie z komponentów dla danej kategorii"""
    cat_data = KNOWN_CATEGORIES[category_key]
    components = cat_data["components"]
    
    parts = []
    
    # 1. Prefiks (rzadziej, tylko profesjonalne)
    if random.random() > 0.6:
        parts.append(random.choice(PREFIXES))
        
    # 2. Główny problem (zawsze)
    parts.append(random.choice(components[0]))
    
    # 3. Szczegóły (często)
    if random.random() > 0.3:
        parts.append(random.choice(components[1]))
        
    # 4. Dodatkowy kontekst (czasami)
    if len(components) > 2 and random.random() > 0.5:
        parts.append(random.choice(components[2]))
        
    # 5. Sufiks (rzadko)
    if random.random() > 0.7:
        parts.append(random.choice(SUFFIXES))
        
    full_sentence = " ".join(parts)
    
    # Wstawianie zmiennych
    if "{n}" in full_sentence:
        full_sentence = full_sentence.replace("{n}", str(random.randint(1, 15)))
    if "{name}" in full_sentence:
        full_sentence = full_sentence.replace("{name}", fake.first_name())
        
    return full_sentence

def generate_noise_description():
    """Generuje zgłoszenie typu szum (Profesjonalne IT)"""
    noise_key = random.choice(list(NOISE_CATEGORIES.keys()))
    noise_data = NOISE_CATEGORIES[noise_key]
    base_template = random.choice(noise_data["templates"])
    
    parts = []
    if random.random() > 0.8:
        parts.append(random.choice(PREFIXES))
    
    parts.append(base_template)
    
    if random.random() > 0.8:
        parts.append(random.choice(SUFFIXES))
        
    return " ".join(parts), noise_data["type"]

def generate_dataset():
    """Główna funkcja generująca dane z weryfikacją punktacji"""
    print(f"Rozpoczynam generowanie PROFESJONALNYCH danych IT od {START_DATE.date()} do {END_DATE.date()}...")
    
    data = []
    current_id = 1001
    
    current_date = START_DATE
    while current_date <= END_DATE:
        daily_count = random.randint(MIN_DAILY_TICKETS, MAX_DAILY_TICKETS)
        print(f"Generowanie dla {current_date.date()}: {daily_count} zgłoszeń")
        
        for _ in range(daily_count):
            # Decyzja: Znana kategoria czy Szum?
            is_known = random.random() < KNOWN_CATEGORY_RATIO
            
            score = 0
            confidence = 0.0
            issue_type = "[System] Incident" # Domyślnie
            
            if is_known:
                category_key = random.choice(list(KNOWN_CATEGORIES.keys()))
                rule = KNOWN_CATEGORIES[category_key]
                min_score = rule.get('min_score', 3)
                issue_type = rule.get('type', "[System] Incident")
                
                # Próba wygenerowania tytułu spełniającego reguły
                attempts = 0
                while attempts < 10:
                    title = generate_dynamic_description(category_key)
                    score = calculate_rule_score(title, rule)
                    
                    if score >= min_score:
                        break
                    attempts += 1
                
                # Jeśli po 10 próbach nadal za mało punktów, dodaj sztucznie słowa kluczowe
                if score < min_score:
                    # Awaryjne doklejenie kombinacji
                    if 'required_combinations' in rule and rule['required_combinations']:
                        combo = rule['required_combinations'][0]
                        title += " " + " ".join(combo)
                        score = calculate_rule_score(title, rule) # Recalculate
                
                category_label = category_key
                confidence = min(0.9, 0.6 + score * 0.1)
            else:
                title, issue_type = generate_noise_description()
                category_label = "Inne"
                score = 0
                confidence = 0.0
            
            # --- HUMANIZACJA (LITERÓWKI I MAŁE LITERY) ---
            # Aplikujemy PO wyliczeniu punktacji, ponieważ normalize_text w classifier.py
            # i tak usuwa polskie znaki i zmienia wielkość liter, więc wynik się nie zmieni.
            title = introduce_typos(title)
            title = lowercase_start(title)
            
            # Data utworzenia
            hour = random.choices(
                range(6, 24), 
                weights=[1, 2, 5, 6, 7, 8, 9, 9, 8, 8, 7, 6, 5, 4, 3, 2, 1, 1]
            )[0]
            
            creation_time = current_date + timedelta(
                hours=hour,
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            data.append({
                "ID zgłoszenia": current_id,
                "Tytuł zgłoszenia": title,
                "Dopasowana reguła": category_label,
                "Typ zgłoszenia": issue_type,
                "Data utworzenia zgłoszenia": creation_time,
                "Oczekiwany wynik": score,
                "Pewność": round(confidence, 2)
            })
            
            current_id += 1
            
        current_date += timedelta(days=1)
        
    return pd.DataFrame(data)

def generate_rules_json():
    """Generuje plik reguł na podstawie konfiguracji, zgodny ze strukturą aplikacji"""
    rules = {}
    for cat_key, cat_data in KNOWN_CATEGORIES.items():
        rules[cat_key] = {
            "keywords": cat_data["keywords"],
            "min_score": cat_data.get("min_score", 3),  # Użyj zdefiniowanego min_score
            "required_combinations": cat_data.get("required_combinations", []),
            "forbidden": cat_data["forbidden"]
        }
    
    # Struktura wymagana przez rules_manager.py
    final_structure = {
        "classification_rules": rules,
        "metadata": {
            "last_updated": datetime.now().isoformat(),
            "version": "2.0",
            "rules_count": len(rules)
        }
    }
    
    return final_structure

def main():
    # 1. Generowanie danych Excel
    df = generate_dataset()
    
    # Zapis do Excela
    print(f"Zapisywanie {len(df)} zgłoszeń do {EXCEL_FILENAME}...")
    df.to_excel(EXCEL_FILENAME, index=False)
    
    # 2. Generowanie reguł JSON
    rules_structure = generate_rules_json()
    
    # Zapis do JSON
    print(f"Zapisywanie reguł do {JSON_FILENAME}...")
    with open(JSON_FILENAME, 'w', encoding='utf-8') as f:
        json.dump(rules_structure, f, indent=4, ensure_ascii=False)
        
    print("Zakończono sukcesem! Wygenerowano profesjonalny zbiór danych IT.")

if __name__ == "__main__":
    main()