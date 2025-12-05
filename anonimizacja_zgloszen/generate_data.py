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
EXCEL_FILENAME = os.path.join(OUTPUT_DIR, 'zgloszenia_testowe_v19.xlsx')
CSV_FILENAME = os.path.join(OUTPUT_DIR, 'zgloszenia_testowe_v19.csv')
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
        "priority": "High",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "zamknięcie", "doba", "raport", "z-report", "fiskalizacja", "dobowy"
        ],
        "forbidden": ["drukarka biurowa", "faktura", "excel"],
        "required_combinations": [
            ["zamknięcie", "dnia"],
            ["raport", "dobowy"],
            ["błąd", "zamknięcia"],
            ["z-report", "błąd"],
            ["zamknięcie", "doby"]
        ],
        "components": [
            ["Błąd krytyczny bazy danych podczas zamknięcia dnia", "Niepowodzenie generowania raportu dobowego - timeout", "System zawiesza się przy zamykaniu doby (SQL Error)", "Błąd spójności danych przy Z-Report"],
            ["na stanowisku POS {n}", "na głównej kasie", "w systemie centralnym"],
            ["komunikat: Database Locked", "brak wydruku potwierdzenia", "proces zatrzymuje się na 90%"]
        ],
        "actions": [
            "Wykonano restart usługi bazy danych SQL na serwerze lokalnym.",
            "Przeprowadzono ręczne wymuszenie generowania raportu Z z poziomu narzędzi administracyjnych.",
            "Oczyszczono pliki tymczasowe transakcji i ponowiono proces zamknięcia.",
            "Zrestartowano stanowisko POS i zweryfikowano spójność bazy danych."
        ],
        "summaries": [
            "Raport dobowy wygenerował się poprawnie po restarcie usług.",
            "Problem rozwiązany, zamknięcie dnia zakończone sukcesem.",
            "Wymagana była interwencja w strukturę bazy danych, system działa stabilnie.",
            "Błąd jednorazowy, po ponowieniu procedury raport wydrukował się."
        ]
    },
    "RCP - Błąd synchronizacji": {
        "type": "[System] Incident",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "rcp", "ewidencja", "odbicie", "czas", "synchronizacja", "czytnik"
        ],
        "forbidden": ["logowanie do windows", "hasło", "korekta"],
        "required_combinations": [
            ["czas", "pracy"],
            ["odbicie", "karty"],
            ["rejestracja", "czasu"],
            ["błąd", "rcp"],
            ["synchronizacja", "rcp"]
        ],
        "components": [
            ["Błąd synchronizacji ewidencji czasu pracy z serwerem", "Czytnik RCP nie przesyła odbić do systemu", "Nieprawidłowe naliczenie godzin - błąd algorytmu", "Brak rejestracji wejścia mimo poprawnego odbicia"],
            ["dla pracownika {name}", "dotyczy całego zespołu", "błąd systemowy"],
            ["karta pracownicza nie została zaczytana", "system nie uwzględnił nadgodzin", "błędna data w raporcie"]
        ],
        "actions": [
            "Zrestartowano urządzenie RCP (hard reset).",
            "Wymuszono ręczną synchronizację danych z serwerem centralnym.",
            "Sprawdzono konfigurację sieciową czytnika, przywrócono połączenie.",
            "Zaktualizowano firmware czytnika RCP do najnowszej wersji."
        ],
        "summaries": [
            "Synchronizacja przywrócona, brakujące odbicia pojawiły się w systemie.",
            "Urządzenie działa poprawnie, test karty pracowniczej pozytywny.",
            "Problem wynikał z chwilowego braku sieci, dane uzupełnione.",
            "Korekta godzin została wprowadzona, system przeliczył czas pracy."
        ]
    },
    "POS - Zawieszenie aplikacji": {
        "type": "[System] Incident",
        "priority": "High",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "pos", "zawieszenie", "aplikacja", "sprzedaż", "ekran", "freeze"
        ],
        "forbidden": ["internet", "outlook", "excel", "kiosk"],
        "required_combinations": [
            ["system", "pos"],
            ["zawieszenie", "systemu"],
            ["brak", "reakcji"],
            ["zamrożenie", "ekranu"],
            ["aplikacja", "sprzedażowa"]
        ],
        "components": [
            ["Całkowite zawieszenie procesu aplikacji sprzedażowej", "Aplikacja POS przestała odpowiadać (Not Responding)", "Brak reakcji interfejsu na dotyk - freeze", "Czarny ekran na stanowisku sprzedażowym - proces tła działa"],
            ["stanowisko nr {n}", "wszystkie kasy", "terminal kasjerski"],
            ["wymagany twardy reset", "wyciek pamięci RAM", "aplikacja zamknęła się samoistnie"]
        ],
        "actions": [
            "Zabito proces aplikacji POS w menedżerze zadań i uruchomiono ponownie.",
            "Wykonano pełny restart stanowiska kasowego.",
            "Oczyszczono pamięć podręczną aplikacji i zaktualizowano sterowniki dotyku.",
            "Przeinstalowano aplikację sprzedażową na stanowisku."
        ],
        "summaries": [
            "Aplikacja działa płynnie po restarcie.",
            "Stanowisko przywrócone do pracy, brak ponownych zawieszeń.",
            "Problem rozwiązany, zalecana obserwacja wydajności.",
            "Usunięto przyczynę wycieku pamięci, system stabilny."
        ]
    },
    "POS - Błąd interfejsu": {
        "type": "[System] Incident",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "interfejs", "gui", "ikona", "grafika", "ekran", "wyświetlanie"
        ],
        "forbidden": ["drukarka", "toner", "kiosk"],
        "required_combinations": [
            ["błąd", "graficzny"],
            ["ikona", "ostrzegawcza"],
            ["interfejs", "użytkownika"],
            ["błąd", "gui"],
            ["komunikat", "ekranowy"]
        ],
        "components": [
            ["Błąd renderowania ikon na pasku statusu", "Artefakty graficzne w interfejsie użytkownika", "Mrugający komunikat błędu UI na ekranie głównym", "Zniekształcony layout przycisków funkcyjnych"],
            ["zasłania przyciski funkcyjne", "uniemożliwia pracę", "na ekranie logowania"],
            ["kod błędu GUI-102", "pojawia się po zalogowaniu", "problem sterownika graficznego"]
        ],
        "actions": [
            "Przeładowano interfejs użytkownika (UI Reload).",
            "Zaktualizowano sterowniki karty graficznej na terminalu POS.",
            "Zmieniono rozdzielczość ekranu i przywrócono ustawienia domyślne.",
            "Wyczyszczono cache graficzny aplikacji."
        ],
        "summaries": [
            "Interfejs wyświetla się poprawnie, artefakty zniknęły.",
            "Problem rozwiązany po aktualizacji sterowników.",
            "Przyciski funkcyjne są widoczne i aktywne.",
            "Błąd graficzny ustąpił po restarcie aplikacji."
        ]
    },
    "Terminal - Błąd komunikacji": {
        "type": "[System] Incident",
        "priority": "High",
        "request_type": "Report broken hardware",
        "min_score": 3,
        "keywords": [
            "terminal", "pinpad", "płatność", "karta", "autoryzacja", "transakcja"
        ],
        "forbidden": ["karta pracownicza", "logowanie", "lojalnościowa"],
        "required_combinations": [
            ["terminal", "płatniczy"],
            ["transakcja", "odrzucona"],
            ["brak", "komunikacji"],
            ["błąd", "autoryzacji"],
            ["odrzucenie", "karty"]
        ],
        "components": [
            ["Utrata komunikacji z terminalem płatniczym (PED)", "Odrzucenie transakcji - błąd połączenia TCP/IP", "Pinpad nie otrzymuje zasilania z portu USB", "Błąd inicjalizacji protokołu płatniczego"],
            ["model Verifone", "model Ingenico", "na kasie nr {n}"],
            ["kod błędu ECR-TIMEOUT", "brak sygnału", "nie drukuje potwierdzenia"]
        ],
        "actions": [
            "Zrestartowano terminal płatniczy (miękki reset).",
            "Sprawdzono i dociśnięto okablowanie terminala.",
            "Skonfigurowano ponownie adres IP terminala w ustawieniach POS.",
            "Wykonano test połączenia z hostem autoryzacyjnym."
        ],
        "summaries": [
            "Komunikacja z terminalem przywrócona, transakcja testowa OK.",
            "Terminal loguje się do sieci poprawnie.",
            "Problem z kablem USB rozwiązany, zasilanie przywrócone.",
            "Autoryzacja kart działa bez opóźnień."
        ]
    },
    "Drukarka fiskalna - Błąd pamięci": {
        "type": "[System] Incident",
        "priority": "High",
        "request_type": "Report broken hardware",
        "min_score": 3,
        "keywords": [
            "drukarka", "fiskalna", "paragon", "pamięć", "moduł", "wydruk"
        ],
        "forbidden": ["drukarka sieciowa", "biurowa", "faktura"],
        "required_combinations": [
            ["drukarka", "fiskalna"],
            ["błąd", "pamięci"],
            ["brak", "wydruku"],
            ["moduł", "fiskalny"],
            ["awaria", "drukarki"]
        ],
        "components": [
            ["Błąd sumy kontrolnej pamięci fiskalnej", "Awaria mechanizmu tnącego w drukarce fiskalnej", "Zablokowany bufor wydruku fiskalnego", "Błąd komunikacji RS232 z drukarką fiskalną"],
            ["stanowisko {n}", "drukarka Epson", "drukarka Posnet"],
            ["dioda Error świeci ciągle", "nie można zafiskalizować transakcji", "paragon nie wysuwa się"]
        ],
        "actions": [
            "Wykonano reset sprzętowy drukarki fiskalnej.",
            "Odblokowano mechanizm tnący i usunięto zacięty papier.",
            "Sprawdzono połączenie kablowe RS232/USB.",
            "Wezwano serwis zewnętrzny producenta drukarki."
        ],
        "summaries": [
            "Drukarka fiskalna gotowa do pracy, paragon testowy wydrukowany.",
            "Błąd pamięci ustąpił po restarcie.",
            "Mechanizm odblokowany, drukarka nie zgłasza błędów.",
            "Zgłoszenie przekazane do serwisu zewnętrznego."
        ]
    },
    "Dostęp - Błąd autoryzacji POS": {
        "type": "[System] Service request",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "logowanie", "hasło", "uprawnienia", "konto", "dostęp", "autoryzacja"
        ],
        "forbidden": ["domena", "windows", "vpn", "terminal"],
        "required_combinations": [
            ["błąd", "autoryzacji"],
            ["konto", "użytkownika"],
            ["dostęp", "zablokowany"],
            ["logowanie", "pos"],
            ["reset", "hasła"]
        ],
        "components": [
            ["Zablokowane konto kasjera - przekroczona liczba prób", "Prośba o reset hasła użytkownika POS", "Brak uprawnień do funkcji kierowniczych", "Konto użytkownika wygasło"],
            ["użytkownik {name}", "stanowisko {n}"],
            ["komunikat: Invalid Credentials", "karta magnetyczna nieaktywna", "wymagany reset uprawnień"]
        ],
        "actions": [
            "Zresetowano hasło użytkownika w systemie centralnym.",
            "Odblokowano konto po weryfikacji tożsamości.",
            "Nadano brakujące uprawnienia kierownicze.",
            "Przeprogramowano kartę magnetyczną użytkownika."
        ],
        "summaries": [
            "Użytkownik zalogował się poprawnie nowym hasłem.",
            "Dostęp przywrócony, uprawnienia zaktualizowane.",
            "Konto odblokowane, karta działa.",
            "Problem rozwiązany, użytkownik może pracować."
        ]
    },
    "System - Opóźnienie replikacji": {
        "type": "[System] Incident",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "min_score": 3,
        "keywords": [
            "replikacja", "synchronizacja", "cennik", "ceny", "baza", "aktualizacja"
        ],
        "forbidden": ["czas pracy", "rcp"],
        "required_combinations": [
            ["synchronizacja", "danych"],
            ["aktualizacja", "cennika"],
            ["błąd", "cen"],
            ["replikacja", "danych"],
            ["baza", "produktów"]
        ],
        "components": [
            ["Opóźnienie replikacji cennika z serwera centralnego", "Niespójność sumy kontrolnej bazy produktów", "Błąd procedury aktualizacji PLU", "Zatrzymany serwis synchronizacji danych"],
            ["na wszystkich stanowiskach", "kasa nr {n}"],
            ["ceny nie zaktualizowały się", "brak pozycji promocyjnych", "błąd wersji bazy danych"]
        ],
        "actions": [
            "Zrestartowano usługę replikacji danych.",
            "Wymuszono pełną synchronizację bazy produktów.",
            "Sprawdzono logi serwera i usunięto blokadę transakcji.",
            "Pobrano paczkę aktualizacyjną ręcznie."
        ],
        "summaries": [
            "Cennik zaktualizowany na wszystkich stanowiskach.",
            "Replikacja przebiegła pomyślnie, ceny są poprawne.",
            "Baza produktów spójna z systemem centralnym.",
            "Problem rozwiązany, promocje są widoczne."
        ]
    },
    "Kiosk - Awaria dotyku": {
        "type": "[System] Incident",
        "priority": "Medium",
        "request_type": "Report broken hardware",
        "min_score": 3,
        "keywords": [
            "kiosk", "dotyk", "ekran", "ngk", "samoobsługowy", "terminal"
        ],
        "forbidden": ["kasa tradycyjna", "pos"],
        "required_combinations": [
            ["kiosk", "samoobsługowy"],
            ["ekran", "dotykowy"],
            ["terminal", "kiosku"],
            ["awaria", "kiosku"],
            ["nie", "działa", "dotyk"]
        ],
        "components": [
            ["Awaria kontrolera dotyku w kiosku samoobsługowym", "Zawieszenie aplikacji KioskApp.exe", "Błąd inicjalizacji urządzenia płatniczego w kiosku", "Czarny ekran kiosku - brak sygnału wideo"],
            ["urządzenie wyłączone z eksploatacji", "ekran czarny", "system nie startuje"],
            ["wymagany serwis on-site", "błąd krytyczny aplikacji", "nie przyjmuje zamówień"]
        ],
        "actions": [
            "Zrestartowano kiosk (odcięcie zasilania).",
            "Skalibrowano ekran dotykowy w menu serwisowym.",
            "Sprawdzono połączenia wewnętrzne kiosku.",
            "Zgłoszono awarię sprzętową do serwisu producenta."
        ],
        "summaries": [
            "Kiosk uruchomił się poprawnie, dotyk działa.",
            "Aplikacja działa stabilnie po restarcie.",
            "Urządzenie wymaga wymiany ekranu, wyłączono z użycia.",
            "Problem rozwiązany, kiosk przyjmuje zamówienia."
        ]
    },
    "Waga - Błąd kalibracji": {
        "type": "[System] Incident",
        "priority": "Low",
        "request_type": "Report broken hardware",
        "min_score": 3,
        "keywords": [
            "waga", "kalibracja", "tarowanie", "szalka", "ważenie", "moduł"
        ],
        "forbidden": ["towar", "cena"],
        "required_combinations": [
            ["waga", "systemowa"],
            ["błąd", "tarowania"],
            ["kalibracja", "wagi"],
            ["moduł", "ważący"],
            ["błąd", "wagi"]
        ],
        "components": [
            ["Błąd protokołu komunikacyjnego wagi systemowej", "Utrata kalibracji modułu ważącego", "Błąd tarowania - wartość poza zakresem", "Waga nie zwraca stabilnego odczytu"],
            ["stanowisko {n}", "waga Dibal", "waga CAS"],
            ["wymagana ponowna kalibracja", "wartość ujemna na wyświetlaczu", "blokuje sprzedaż produktów ważonych"]
        ],
        "actions": [
            "Wykonano zerowanie i tarowanie wagi.",
            "Odłączono i podłączono ponownie zasilanie wagi.",
            "Sprawdzono czy szalka wagi nie jest zablokowana mechanicznie.",
            "Przeprowadzono procedurę kalibracji serwisowej."
        ],
        "summaries": [
            "Waga wskazuje poprawnie, odczyt stabilny.",
            "Kalibracja zakończona sukcesem.",
            "Usunięto przeszkodę blokującą szalkę, waga działa.",
            "Komunikacja z POS przywrócona."
        ]
    },
    "KDS - Brak sygnału wideo": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "kds", "kuchnia", "ekran", "wideo", "bumpbar", "kontroler"
        ],
        "forbidden": ["biuro", "kiosk"],
        "required_combinations": [
            ["system", "kds"],
            ["ekran", "kuchenny"],
            ["kontroler", "wideo"],
            ["wyświetlanie", "zamówień"],
            ["brak", "sygnału"]
        ],
        "components": [
            ["Utrata sygnału wideo na kontrolerze KDS", "Błąd serwisu kolejkowania zamówień kuchennych", "Opóźnienia w renderowaniu na ekranach KDS", "Uszkodzony interfejs wejściowy Bumpbar"],
            ["stacja grill", "stacja napojów", "ekran ekspedycji"],
            ["zamówienia nie pojawiają się", "brak sygnału wideo", "system offline"]
        ],
        "actions": [
            "Zrestartowano kontroler KDS.",
            "Wymieniono kabel HDMI/VGA łączący kontroler z monitorem.",
            "Zrestartowano usługę KDS Service na serwerze.",
            "Podmieniono klawiaturę bumpbar na zapasową."
        ],
        "summaries": [
            "Obraz na ekranie kuchennym powrócił.",
            "Zamówienia wyświetlają się poprawnie i bez opóźnień.",
            "Bumpbar reaguje na wciśnięcia, system sprawny.",
            "Problem rozwiązany po restarcie kontrolera."
        ]
    },
    "Aplikacja mobilna - Błąd API": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "aplikacja", "mobile", "api", "kupon", "lojalność", "qr"
        ],
        "forbidden": ["kiosk", "skaner ręczny", "terminal"],
        "required_combinations": [
            ["aplikacja", "lojalnościowa"],
            ["skaner", "qr"],
            ["kupon", "mobilny"],
            ["integracja", "mobile"],
            ["błąd", "api"]
        ],
        "components": [
            ["Błąd API podczas walidacji kuponu mobilnego", "Timeout połączenia z bramką zamówień mobilnych", "Nieprawidłowy format danych JSON z aplikacji", "Awaria mikroserwisu obsługi mobile"],
            ["zgłaszane przez klientów", "błąd API"],
            ["nie nalicza rabatów", "zamówienie nie dociera do POS", "błąd serwera"]
        ],
        "actions": [
            "Zgłoszono problem do zespołu deweloperskiego aplikacji mobilnej.",
            "Zrestartowano bramkę API integrującą mobile z POS.",
            "Sprawdzono logi transakcji, błąd po stronie zewnętrznego dostawcy.",
            "Poinstruowano personel o procedurze awaryjnej (rabat ręczny)."
        ],
        "summaries": [
            "Usługa przywrócona przez dostawcę zewnętrznego.",
            "Kupony są ponownie walidowane poprawnie.",
            "Problem rozwiązany, komunikacja API stabilna.",
            "Zgłoszenie zamknięte, błąd globalny usunięty."
        ]
    },
    "Loyalty - Niedostępność serwisu": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "loyalty", "punkty", "karta", "klient", "serwer", "lojalność"
        ],
        "forbidden": ["karta płatnicza", "kredytowa"],
        "required_combinations": [
            ["system", "lojalnościowy"],
            ["karta", "klienta"],
            ["punkty", "loyalty"],
            ["serwer", "loyalty"],
            ["błąd", "autoryzacji"]
        ],
        "components": [
            ["Brak odpowiedzi z serwera lojalnościowego (Service Unavailable)", "Błąd autoryzacji tokena karty klienta", "Niemożność zapisu transakcji punktowej - błąd DB", "Awaria webserwisu obsługi nagród"],
            ["komunikat: system offline", "błąd bazy danych"],
            ["klient nie widzi punktów", "transakcja bez identyfikacji", "timeout połączenia"]
        ],
        "actions": [
            "Sprawdzono status usługi Loyalty (globalna awaria).",
            "Zrestartowano lokalny serwis proxy lojalnościowego.",
            "Zweryfikowano połączenie internetowe z chmurą loyalty.",
            "Zgłoszono incydent do dostawcy systemu lojalnościowego."
        ],
        "summaries": [
            "Serwer lojalnościowy odpowiada, punkty naliczają się.",
            "Awaria globalna usunięta przez dostawcę.",
            "Połączenie przywrócone, system działa online.",
            "Karty klientów są poprawnie autoryzowane."
        ]
    },
    "Skaner - Błąd sterownika": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "skaner", "czytnik", "kod", "ean", "laser", "sterownik"
        ],
        "forbidden": ["skaner dokumentów", "biuro"],
        "required_combinations": [
            ["czytnik", "kodów"],
            ["skaner", "ręczny"],
            ["brak", "odczytu"],
            ["skaner", "stacjonarny"],
            ["błąd", "skanera"]
        ],
        "components": [
            ["Błąd sterownika HID skanera kodów", "Czytnik nie dekoduje standardu EAN-13", "Uszkodzenie modułu laserowego skanera", "Błąd enumeracji urządzenia USB (Skaner)"],
            ["stanowisko {n}", "skaner Zebra", "skaner Honeywell"],
            ["nie świeci wiązka lasera", "błąd interfejsu USB", "przerywa połączenie"]
        ],
        "actions": [
            "Przepięto skaner do innego portu USB.",
            "Zeskanowano kody konfiguracyjne przywracające ustawienia fabryczne.",
            "Przeinstalowano sterownik urządzenia w systemie Windows.",
            "Wymieniono kabel USB skanera."
        ],
        "summaries": [
            "Skaner działa poprawnie, kody są odczytywane.",
            "Problem rozwiązany po rekonfiguracji urządzenia.",
            "Sterownik zainstalowany ponownie, urządzenie wykryte.",
            "Wymiana kabla pomogła, skaner sprawny."
        ]
    },
    "Faktury - Błąd API": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "faktura", "nip", "api", "gus", "wydruk", "moduł"
        ],
        "forbidden": ["paragon", "fiskalna"],
        "required_combinations": [
            ["moduł", "faktur"],
            ["wystawianie", "faktury"],
            ["nip", "nabywcy"],
            ["wydruk", "faktury"],
            ["błąd", "api"]
        ],
        "components": [
            ["Wyjątek w module fakturowania - NullReferenceException", "Błąd walidacji NIP w zewnętrznym API GUS", "Błąd generowania pliku PDF faktury", "Niemożność zapisu faktury do repozytorium"],
            ["błąd walidacji danych", "problem z bazą GUS"],
            ["dokument nie został utworzony", "błędne dane kontrahenta", "zawieszenie modułu fakturowania"]
        ],
        "actions": [
            "Sprawdzono dostępność serwisu GUS (baza NIP).",
            "Zrestartowano moduł fakturowania.",
            "Poprawiono błędne dane kontrahenta i ponowiono próbę.",
            "Wyczyszczono cache plików tymczasowych PDF."
        ],
        "summaries": [
            "Faktura wystawiona poprawnie po ponowieniu próby.",
            "Błąd API GUS ustąpił, dane pobierają się.",
            "Dokument wygenerowany i wydrukowany.",
            "Problem rozwiązany, moduł działa stabilnie."
        ]
    },
    "Szuflada - Awaria otwarcia": {
        "type": "[System] Incident",
        "min_score": 3,
        "keywords": [
            "szuflada", "kasetka", "klucz", "zamek", "otwarcie", "elektromagnes"
        ],
        "forbidden": ["sejf", "biurko"],
        "required_combinations": [
            ["szuflada", "kasowa"],
            ["otwarcie", "szuflady"],
            ["kasetka", "pieniężna"],
            ["awaria", "szuflady"],
            ["nie", "otwiera"]
        ],
        "components": [
            ["Awaria elektromagnesu otwierającego szufladę (Solenoid)", "Brak sygnału sterującego otwarciem szuflady (RJ11)", "Mechaniczne zablokowanie prowadnicy szuflady", "Błąd czujnika otwarcia szuflady"],
            ["stanowisko {n}", "klucz utknął w zamku"],
            ["nie można wydać reszty", "szuflada nie domyka się", "awaria mechaniczna"]
        ],
        "actions": [
            "Sprawdzono podłączenie kabla RJ11 do drukarki fiskalnej.",
            "Otwarto szufladę awaryjnie kluczem i sprawdzono mechanizm.",
            "Usunięto monetę blokującą prowadnicę.",
            "Wymieniono wkład szuflady na zapasowy."
        ],
        "summaries": [
            "Szuflada otwiera się automatycznie.",
            "Usunięto blokadę mechaniczną, sprzęt sprawny.",
            "Kabel podłączony poprawnie, sygnał dociera.",
            "Problem rozwiązany, zamek działa płynnie."
        ]
    },
    "RCP - Korekta czasu": {
        "type": "[System] Service request",
        "min_score": 3,
        "keywords": [
            "korekta", "czas", "wniosek", "odbicie", "godziny", "edycja"
        ],
        "forbidden": ["błąd synchronizacji", "awaria", "czytnik", "błąd rcp"],
        "required_combinations": [
            ["korekta", "czasu"],
            ["edycja", "czasu"],
            ["złe", "odbicie"],
            ["wniosek", "korektę"],
            ["zapomniane", "odbicie"]
        ],
        "components": [
            ["Prośba o korektę czasu pracy - zapomniane odbicie", "Wniosek o edycję godzin - błędnie wybrane wejście", "Prośba o anulowanie błędnego odbicia RCP", "Uzupełnienie brakującego czasu pracy"],
            ["pracownik {name}", "data wczorajsza"],
            ["zapomniałem karty", "odbicie prywatne zamiast służbowego", "pomyłka przy rejestracji"]
        ],
        "actions": [
            "Zweryfikowano obecność pracownika na monitoringu.",
            "Wprowadzono korektę czasu pracy w systemie HR.",
            "Anulowano błędne odbicie zgodnie z wnioskiem.",
            "Uzupełniono brakujące wejście/wyjście ręcznie."
        ],
        "summaries": [
            "Korekta wprowadzona, czas pracy zgodny.",
            "Wniosek rozpatrzony pozytywnie, dane zaktualizowane.",
            "Błąd pracownika skorygowany.",
            "Godziny pracy zostały wyrównane."
        ]
    }
}

# --- SZUM (NOISE) - KATEGORIE "INNE" (PROFESJONALNE IT) ---
# Wyłącznie problemy IT, ale nie pasujące do powyższych kategorii Retail.
# Brak "cieknących sufitów" i "braku papieru w toalecie".
NOISE_CATEGORIES = {
    "SPRZET_BIUROWY": {
        "type": "[System] Incident",
        "priority": "Low",
        "request_type": "Report broken hardware",
        "templates": [
            "Awaria stacji dokującej laptopa", "Monitor zewnętrzny nie wykrywa sygnału", 
            "Uszkodzona matryca w laptopie służbowym", "Mysz bezprzewodowa nie paruje się z odbiornikiem", 
            "Klawiatura numeryczna nie działa", "Problem z zasilaczem do laptopa Dell", 
            "Słuchawki z mikrofonem nie są wykrywane przez system", "Uszkodzone gniazdo LAN w ścianie", 
            "Drukarka sieciowa w biurze offline", "Zacięcie papieru w urządzeniu wielofunkcyjnym",
            "Brak tonera w drukarce korytarzowej", "Skaner dokumentów nie pobiera kartek"
        ],
        "actions": [
            "Wymieniono sprzęt na zapasowy z magazynu IT.",
            "Zaktualizowano firmware urządzenia.",
            "Przeczyszczono styki i sprawdzono okablowanie.",
            "Zgłoszono naprawę gwarancyjną u producenta."
        ],
        "summaries": [
            "Sprzęt działa poprawnie po wymianie.",
            "Użytkownik potwierdził rozwiązanie problemu.",
            "Urządzenie przywrócone do pełnej sprawności.",
            "Zgłoszenie zamknięte, sprzęt sprawny."
        ]
    },
    "OPROGRAMOWANIE_BIUROWE": {
        "type": "[System] Incident",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "templates": [
            "Błąd uruchamiania Microsoft Outlook", "Excel zawiesza się przy otwieraniu pliku", 
            "Brak dostępu do dysku sieciowego Z:", "Problem z certyfikatem VPN", 
            "Nieudana aktualizacja systemu Windows", "Błąd licencji pakietu Office", 
            "Przeglądarka Chrome nie ładuje stron intranetu", "Program antywirusowy blokuje aplikację", 
            "Teams nie łączy z spotkaniem", "Adobe Reader nie otwiera plików PDF"
        ],
        "actions": [
            "Przeinstalowano pakiet oprogramowania biurowego.",
            "Wyczyszczono profil użytkownika i pliki tymczasowe.",
            "Zaktualizowano system operacyjny i sterowniki.",
            "Dodano wyjątek w zaporze sieciowej."
        ],
        "summaries": [
            "Aplikacja uruchamia się poprawnie.",
            "Dostęp do zasobów sieciowych przywrócony.",
            "Błąd nie występuje po aktualizacji.",
            "Problem rozwiązany, użytkownik może pracować."
        ]
    },
    "KONTA_I_DOSTEPIE": {
        "type": "[System] Service request",
        "priority": "Medium",
        "request_type": "Report a system problem",
        "templates": [
            "Zablokowane konto domenowe AD", "Wygasło hasło do systemu Windows", 
            "Brak dostępu do folderu współdzielonego", "Prośba o nadanie uprawnień do grupy", 
            "Problem z uwierzytelnianiem dwuskładnikowym (MFA)", "Konto pocztowe przepełnione", 
            "Nie działa logowanie do portalu pracowniczego", "Błąd synchronizacji hasła"
        ],
        "actions": [
            "Odblokowano konto w Active Directory.",
            "Zresetowano hasło i wymuszono zmianę przy logowaniu.",
            "Nadano wymagane uprawnienia do grupy bezpieczeństwa.",
            "Zwiększono limit quota dla skrzynki pocztowej."
        ],
        "summaries": [
            "Dostęp do konta przywrócony.",
            "Użytkownik zalogował się pomyślnie.",
            "Uprawnienia zostały zaktualizowane.",
            "Problem z logowaniem rozwiązany."
        ]
    },
    "SIEC_I_INFRASTRUKTURA": {
        "type": "[System] Incident",
        "priority": "High",
        "request_type": "Report a system problem",
        "templates": [
            "Brak dostępu do sieci Wi-Fi", "Niska przepustowość łącza internetowego", 
            "Telefon VoIP nie ma sygnału", "Błąd konfiguracji adresu IP", 
            "Utrata połączenia z serwerem plików", "Awaria switcha w szafie rack", 
            "Brak dostępu do zasobów zewnętrznych"
        ],
        "actions": [
            "Zrestartowano urządzenia sieciowe w lokalizacji.",
            "Skonfigurowano ponownie parametry karty sieciowej.",
            "Sprawdzono trasę pakietów i odblokowano porty.",
            "Przełączono na łącze zapasowe."
        ],
        "summaries": [
            "Połączenie sieciowe stabilne, parametry w normie.",
            "Dostęp do internetu i intranetu przywrócony.",
            "Telefon VoIP loguje się do centrali.",
            "Awaria infrastruktury usunięta."
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

def fuzz_priority(base_priority):
    """Wprowadza losowość w priorytetach (błędy ludzkie/różne oceny) z dynamicznymi zakresami"""
    r = random.random()
    
    # Dynamiczne zakresy prawdopodobieństwa dla każdego wywołania
    # Symuluje zmienność dnia/konsultanta
    
    if base_priority == "High":
        # High: 60-80% High, 15-25% Highest, reszta Medium
        retention = random.uniform(0.60, 0.80)
        upgrade = random.uniform(0.15, 0.25)
        
        if r < retention: return "High"
        elif r < (retention + upgrade): return "Highest"
        else: return "Medium"
        
    elif base_priority == "Medium":
        # Medium: 60-80% Medium, 10-20% High, reszta Low
        retention = random.uniform(0.60, 0.80)
        upgrade = random.uniform(0.10, 0.20)
        
        if r < retention: return "Medium"
        elif r < (retention + upgrade): return "High"
        else: return "Low"
        
    elif base_priority == "Low":
        # Low: 60-80% Low, 15-25% Lowest, reszta Medium
        retention = random.uniform(0.60, 0.80)
        downgrade = random.uniform(0.15, 0.25)
        
        if r < retention: return "Low"
        elif r < (retention + downgrade): return "Lowest"
        else: return "Medium"
        
    return base_priority

def fuzz_request_type(base_type):
    """Wprowadza rzadkie błędy w kategoryzacji typu żądania z dynamicznym zakresem"""
    r = random.random()
    
    # Dokładność od 92% do 98% (zmienna)
    accuracy_threshold = random.uniform(0.92, 0.98)
    
    if r < accuracy_threshold:
        return base_type
        
    # Pomyłka
    if base_type == "Report a system problem":
        return "Report broken hardware"
    else:
        return "Report a system problem"

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
    
    # Pobierz akcję i podsumowanie (z domyślnymi wartościami dla bezpieczeństwa)
    action = random.choice(noise_data.get("actions", ["Sprawdzono logi systemowe.", "Przekazano do II linii wsparcia."]))
    summary = random.choice(noise_data.get("summaries", ["Zgłoszenie zamknięte.", "Problem rozwiązany."]))
    
    # Pobierz priorytet i typ żądania z losowością
    base_priority = noise_data.get("priority", "Medium")
    priority = fuzz_priority(base_priority)
    
    base_request_type = noise_data.get("request_type", "Report a system problem")
    request_type = fuzz_request_type(base_request_type)
        
    return " ".join(parts), noise_data["type"], action, summary, priority, request_type

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
            action = ""
            summary = ""
            priority = "Medium"
            request_type = "Report a system problem"
            
            if is_known:
                category_key = random.choice(list(KNOWN_CATEGORIES.keys()))
                rule = KNOWN_CATEGORIES[category_key]
                min_score = rule.get('min_score', 3)
                issue_type = rule.get('type', "[System] Incident")
                
                # Pobierz priorytet i typ żądania z losowością
                base_priority = rule.get('priority', "Medium")
                priority = fuzz_priority(base_priority)
                
                base_request_type = rule.get('request_type', "Report a system problem")
                request_type = fuzz_request_type(base_request_type)
                
                # Losowanie akcji i podsumowania
                action = random.choice(rule.get("actions", ["Podjęto działania naprawcze."]))
                summary = random.choice(rule.get("summaries", ["Problem rozwiązany."]))
                
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
                title, issue_type, action, summary, priority, request_type = generate_noise_description()
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
            
            # Formatowanie kolumny Deskrypcjon zgodnie z wymaganiami
            full_description = f"Opis: {title} Działanie naprawcze: {action} Podsumowanie: {summary}"
            
            # Formatowanie daty: DD.MM.YYYY HH:MM:SS
            formatted_date = creation_time.strftime("%d.%m.%Y %H:%M:%S")

            data.append({
                "ID zgłoszenia": current_id,
                "Tytuł zgłoszenia": title,
                "Deskrypcjon": full_description,
                "Dopasowana reguła": category_label,
                "Typ zgłoszenia": issue_type,
                "Priorytet": priority,
                "Typ żądania": request_type,
                "Data utworzenia zgłoszenia": formatted_date,
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

    # Zapis do CSV
    print(f"Zapisywanie {len(df)} zgłoszeń do {CSV_FILENAME}...")
    df.to_csv(CSV_FILENAME, index=False, sep=',', encoding='utf-8')
    
    # 2. Generowanie reguł JSON
    rules_structure = generate_rules_json()
    
    # Zapis do JSON
    print(f"Zapisywanie reguł do {JSON_FILENAME}...")
    with open(JSON_FILENAME, 'w', encoding='utf-8') as f:
        json.dump(rules_structure, f, indent=4, ensure_ascii=False)
        
    print("Zakończono sukcesem! Wygenerowano profesjonalny zbiór danych IT.")

if __name__ == "__main__":
    main()