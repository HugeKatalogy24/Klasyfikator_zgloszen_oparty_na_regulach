# classifier.py

import pandas as pd
import re
import string
import logging
import unicodedata
from rules_manager import rules_manager, RulesSecurityError, RulesValidationError

# BEZPIECZEŃSTWO: Selektywne filtrowanie ostrzeżeń zamiast globalnego ukrywania
import warnings
# Filtry tylko dla konkretnych ostrzeżeń dtype cast jeśli konieczne
warnings.filterwarnings('ignore', category=pd.errors.DtypeWarning, module='pandas')
warnings.filterwarnings('ignore', message='.*DataFrame.dtypes.*')

# Konfiguracja logowania dla bezpieczeństwa
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# BEZPIECZEŃSTWO: Stałe konfiguracyjne dla walidacji
MAX_RULES_LIMIT = 1000  # Maksymalna liczba reguł do przetworzenia
MAX_TITLE_LENGTH = 500  # Maksymalna długość analizowanego tekstu
# Whitelista znaków kategorii (litery ASCII + polskie znaki diakrytyczne + cyfry + spacje + underscore + myślnik + slash + przecinki)
ALLOWED_CATEGORY_CHARS = string.ascii_letters + string.digits + "_- /," + "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ"

class ProblemClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.label_encoder = None
        self.feature_names = None
        self.model_package = None
        self.rules_manager = rules_manager
        self.load_model()

    def _normalize_text(self, text):
        """
        Normalizuje tekst usuwając polskie znaki diakrytyczne dla lepszego dopasowywania.
        
        DODANE 2025-08-11: Rozwiązanie problemu z polskimi znakami diakrytycznymi
        Przekształca: "zużycie" → "zuzycie", "połączenie" → "polaczenie"
        
        Args:
            text (str): Tekst do normalizacji
            
        Returns:
            str: Tekst bez znaków diakrytycznych
        """
        if not isinstance(text, str):
            return text
        
        # Mapowanie polskich znaków diakrytycznych
        polish_chars = {
            'ą': 'a', 'ć': 'c', 'ę': 'e', 'ł': 'l', 'ń': 'n', 
            'ó': 'o', 'ś': 's', 'ź': 'z', 'ż': 'z',
            'Ą': 'A', 'Ć': 'C', 'Ę': 'E', 'Ł': 'L', 'Ń': 'N',
            'Ó': 'O', 'Ś': 'S', 'Ź': 'Z', 'Ż': 'Z'
        }
        
        # Zastąp polskie znaki
        normalized = text
        for polish, latin in polish_chars.items():
            normalized = normalized.replace(polish, latin)
        
        return normalized

    def load_model(self):
        """
        Celowo wyłącza ładowanie modelu ML, aby zawsze używać klasyfikacji regułowej.
        """
        self.model = None
        logger.info("✅ Klasyfikator skonfigurowany do używania wyłącznie reguł JSON.")

    def classify_issues(self, df):
        """Klasyfikuje zgłoszenia wyłącznie za pomocą reguł."""
        # BEZPIECZEŃSTWO: Walidacja wymaganych kolumn DataFrame
        required_columns = ['title']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            error_msg = f"DataFrame nie zawiera wymaganych kolumn: {missing_columns}"
            logger.error(f"BŁĄD WALIDACJI: {error_msg}")
            raise ValueError(error_msg)
        
        logger.info("🔧 Rozpoczynanie klasyfikacji regułowej...")
        return self._classify_with_rules(df)

    def _classify_with_rules(self, df):
        """Klasyfikacja regułowa - reguły wczytane z bezpiecznego JSON"""
        logger.info("Rozpoczęto klasyfikację regułową. Liczba zgłoszeń: %d", len(df))
        df_copy = df.copy()
        
        # BEZPIECZEŃSTWO: Walidacja kolumn DataFrame przed użyciem
        if 'title' not in df_copy.columns:
            logger.error("BŁĄD WALIDACJI: Brak kolumny 'title' w DataFrame")
            raise ValueError("DataFrame musi zawierać kolumnę 'title'")
        
        # BEZPIECZEŃSTWO: Zabezpieczenie przed KeyError - bezpiecznie twórz kolumnę title_lower
        try:
            df_copy['title_lower'] = df_copy['title'].astype(str).str.lower()
        except Exception as e:
            logger.error(f"BŁĄD konwersji kolumny 'title': {e}")
            # Fallback - utwórz pustą kolumnę
            df_copy['title_lower'] = ''
        
        # BEZPIECZEŃSTWO: Ograniczenie długości analizowanego tekstu
        df_copy['title_lower'] = df_copy['title_lower'].str.slice(0, MAX_TITLE_LENGTH)
        
        # WYKLUCZENIE: Zgłoszenia zawierające "telefon do" nie są klasyfikowane
        # Identyfikacja zgłoszeń z frazą "telefon do"
        telefon_do_mask = df_copy['title_lower'].str.contains('telefon do', case=False, na=False)
        excluded_count = telefon_do_mask.sum()
        
        if excluded_count > 0:
            logger.info(f"🔇 Wykluczono {excluded_count} zgłoszeń zawierających 'telefon do' z klasyfikacji")
        
        df_copy['category'] = 'inne'
        df_copy['confidence'] = 0.5

        # Bezpieczne wczytanie reguł z JSON
        try:
            # Przeładuj reguły na wszelki wypadek
            self.rules_manager.reload_rules()
            rules_dict = self.rules_manager.get_rules()
            
            # BEZPIECZEŃSTWO: Limit maksymalnej liczby reguł
            if len(rules_dict) > MAX_RULES_LIMIT:
                logger.warning(f"OSTRZEŻENIE BEZPIECZEŃSTWA: Przekroczono limit reguł ({len(rules_dict)} > {MAX_RULES_LIMIT}). Ograniczam do pierwszych {MAX_RULES_LIMIT} reguł.")
                # Ogranicz do pierwszych MAX_RULES_LIMIT reguł
                rules_dict = dict(list(rules_dict.items())[:MAX_RULES_LIMIT])
            
            logger.info(f"🔄 Wczytano {len(rules_dict)} reguł z bezpiecznego JSON")
        except (RulesSecurityError, RulesValidationError) as e:
            logger.error(f"❌ Błąd bezpieczeństwa podczas ładowania reguł: {e}")
            return df_copy
        except Exception as e:
            logger.exception(f"❌ Błąd podczas ładowania reguł klasyfikacji: {e}")
            return df_copy

        classified_count = 0
        for category, rule in rules_dict.items():
            # BEZPIECZEŃSTWO: Walidacja nazw kategorii (whitelistowanie)
            if not self._validate_category_name(category):
                logger.warning(f"OSTRZEŻENIE BEZPIECZEŃSTWA: Pominięto kategorię z niedozwolonymi znakami: {category}")
                continue
                
            for idx, row in df_copy.iterrows():
                # WYKLUCZENIE: Pomiń zgłoszenia zawierające "telefon do"
                if telefon_do_mask.iloc[idx]:
                    continue
                
                # BEZPIECZEŃSTWO: Walidacja czy title_lower istnieje i nie jest NaN
                title_lower = row.get('title_lower', '')
                if pd.isna(title_lower) or not isinstance(title_lower, str):
                    title_lower = ''
                
                score = self._calculate_rule_score(title_lower, rule)
                if score >= rule.get('min_score', 1) and df_copy.loc[idx, 'category'] == 'inne':
                    df_copy.loc[idx, 'category'] = category
                    df_copy.loc[idx, 'confidence'] = min(0.9, 0.6 + score * 0.1)
                    classified_count += 1
        
        logger.info("Klasyfikacja regułowa zakończona. Sklasyfikowano: %d zgłoszeń", classified_count)
        if excluded_count > 0:
            logger.info(f"📊 Podsumowanie: {classified_count} sklasyfikowanych, {excluded_count} wykluczonych ('telefon do'), {len(df_copy) - classified_count - excluded_count} pozostało w kategorii 'inne'")
        else:
            logger.info(f"📊 Podsumowanie: {classified_count} sklasyfikowanych, {len(df_copy) - classified_count} pozostało w kategorii 'inne'")
        return df_copy

    def _validate_category_name(self, category_name):
        """
        BEZPIECZEŃSTWO: Waliduje nazwę kategorii używając whitelisty dozwolonych znaków.
        Dozwolone są tylko litery, cyfry, podkreślenie i myślnik.
        """
        if not category_name or not isinstance(category_name, str):
            return False
        
        # Sprawdź czy wszystkie znaki są dozwolone
        for char in category_name:
            if char not in ALLOWED_CATEGORY_CHARS:
                return False
        
        # Dodatkowe sprawdzenia długości (max 100 znaków)
        if len(category_name) > 100:
            return False
            
        return True

    def _calculate_rule_score(self, title_lower, rule):
        """
        Oblicza wynik dopasowania tytułu do reguły.
        
        ZMIENIONY MECHANIZM DOPASOWYWANIA (2025-08-11):
        - Keywords: Dopasowanie częściowe (substring) - "zawiesz" dopasuje "zawieszony"
        - Combinations: Dopasowanie częściowe (substring) - sprawdza czy wszystkie słowa występują jako podciągi
        - Forbidden: Dopasowanie częściowe (substring) - jeśli znajdzie jakiekolwiek słowo, odrzuca regułę
        - NOWE: Normalizacja polskich znaków diakrytycznych - "zużycie" dopasuje "zuzycie"
        
        PUNKTACJA:
        - Pojedyncze keyword: +1 punkt
        - Kombinacja 2 słów: +3 punkty
        - Kombinacja 3 słów: +4 punkty
        - Kombinacja n słów: +n punktów
        - Forbidden word: natychmiastowe odrzucenie (score = 0)
        
        BEZPIECZEŃSTWO: Dodano walidację danych wejściowych i error handling.
        """
        # BEZPIECZEŃSTWO: Walidacja danych wejściowych
        if not isinstance(title_lower, str):
            logger.warning(f"OSTRZEŻENIE: title_lower nie jest stringiem: {type(title_lower)}")
            return 0
        
        if not isinstance(rule, dict):
            logger.warning(f"OSTRZEŻENIE: reguła nie jest słownikiem: {type(rule)}")
            return 0
        
        # BEZPIECZEŃSTWO: Ograniczenie długości analizowanego tekstu
        if len(title_lower) > MAX_TITLE_LENGTH:
            title_lower = title_lower[:MAX_TITLE_LENGTH]
            logger.warning(f"OSTRZEŻENIE: Obcięto tytuł do {MAX_TITLE_LENGTH} znaków")
        
        # NOWE: Normalizacja tekstu dla lepszego dopasowywania polskich znaków
        title_normalized = self._normalize_text(title_lower)
        logger.debug(f"🔤 Znormalizowano tytuł: '{title_lower}' → '{title_normalized}'")
        
        score = 0
        
        # Sprawdź zabronione słowa z error handlingiem
        try:
            if 'forbidden' in rule and isinstance(rule['forbidden'], list):
                for forbidden in rule['forbidden']:
                    if isinstance(forbidden, str):
                        # NOWE: Sprawdź zarówno oryginalny tekst jak i znormalizowany
                        forbidden_normalized = self._normalize_text(forbidden)
                        if (forbidden in title_lower or 
                            forbidden_normalized in title_normalized or
                            forbidden in title_normalized):
                            logger.debug(f"🚫 Forbidden word '{forbidden}' wykryte - odrzucam regułę")
                            return 0
        except Exception as e:
            logger.error(f"BŁĄD podczas sprawdzania zabronionych słów: {e}")
        
        # Sprawdź kombinacje wymagane z error handlingiem
        try:
            if 'required_combinations' in rule and isinstance(rule['required_combinations'], list):
                for combination in rule['required_combinations']:
                    if isinstance(combination, list):
                        # ZMIANA: Dopasowanie częściowe dla kombinacji z normalizacją
                        # Sprawdź czy wszystkie słowa z kombinacji występują jako podciągi w title_lower lub title_normalized
                        all_words_found = True
                        for word in combination:
                            if not isinstance(word, str):
                                all_words_found = False
                                break
                            
                            # NOWE: Sprawdź zarówno oryginalny tekst jak i znormalizowany
                            word_normalized = self._normalize_text(word)
                            word_found = (word in title_lower or 
                                        word_normalized in title_normalized or
                                        word in title_normalized)
                            
                            if not word_found:
                                all_words_found = False
                                break
                        
                        if all_words_found:
                            if len(combination) == 2:
                                score += 3  # Podwójna kombinacja = 3 punkty
                                logger.debug(f"🎯 Dopasowano kombinację 2-słowną: {combination}")
                            elif len(combination) == 3:
                                score += 4  # Potrójna kombinacja = 4 punkty
                                logger.debug(f"🎯 Dopasowano kombinację 3-słowną: {combination}")
                            else:
                                # Domyślna punktacja dla kombinacji o innej długości
                                score += len(combination)
                                logger.debug(f"🎯 Dopasowano kombinację {len(combination)}-słowną: {combination}")
        except Exception as e:
            logger.error(f"BŁĄD podczas sprawdzania kombinacji wymaganych: {e}")

        # Dodatkowe punkty za pojedyncze słowa kluczowe z error handlingiem
        try:
            if 'keywords' in rule and isinstance(rule['keywords'], list):
                for keyword in rule['keywords']:
                    if isinstance(keyword, str):
                        # BEZPIECZEŃSTWO: Escape regex characters w keyword
                        try:
                            # ZMIANA: Dopasowanie częściowe z normalizacją polskich znaków
                            # Przykład: "zużycie" dopasuje "zuzycie", "zawiesz" dopasuje "zawieszony"
                            escaped_keyword = re.escape(keyword)
                            keyword_normalized = self._normalize_text(keyword)
                            escaped_keyword_normalized = re.escape(keyword_normalized)
                            
                            # Sprawdź dopasowanie w oryginalnym tekście lub znormalizowanym
                            original_match = re.search(escaped_keyword, title_lower)
                            normalized_match = re.search(escaped_keyword_normalized, title_normalized)
                            cross_match = re.search(escaped_keyword, title_normalized)
                            
                            if original_match or normalized_match or cross_match:
                                score += 1  # Keyword = 1 punkt
                                logger.debug(f"🎯 Dopasowano keyword '{keyword}' w tytule")
                        except re.error as regex_err:
                            logger.warning(f"OSTRZEŻENIE: Błąd regex dla keyword '{keyword}': {regex_err}")
        except Exception as e:
            logger.error(f"BŁĄD podczas sprawdzania keywords: {e}")
        
        return score
