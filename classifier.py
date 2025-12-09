# classifier.py
# Klasyfikator zgłoszeń - kategoryzacja na podstawie reguł JSON

import pandas as pd
import re
import string
import logging
import unicodedata
from rules_manager import rules_manager, RulesSecurityError, RulesValidationError

import warnings
warnings.filterwarnings('ignore', category=pd.errors.DtypeWarning, module='pandas')
warnings.filterwarnings('ignore', message='.*DataFrame.dtypes.*')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Limity bezpieczeństwa
MAX_RULES_LIMIT = 1000
MAX_TITLE_LENGTH = 500
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
        Normalizacja tekstu - usuwanie polskich znaków diakrytycznych.
        Przykład: "zużycie" → "zuzycie", "połączenie" → "polaczenie"
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
        """Inicjalizacja klasyfikatora - używamy tylko reguł JSON (bez ML)."""
        self.model = None
        logger.info("✅ Klasyfikator skonfigurowany do używania wyłącznie reguł JSON.")

    def classify_issues(self, df):
        """Klasyfikuje zgłoszenia za pomocą reguł."""
        # Walidacja wymaganych kolumn
        required_columns = ['title']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            error_msg = f"DataFrame nie zawiera wymaganych kolumn: {missing_columns}"
            logger.error(f"BŁĄD WALIDACJI: {error_msg}")
            raise ValueError(error_msg)
        
        logger.info("🔧 Rozpoczynanie klasyfikacji regułowej...")
        return self._classify_with_rules(df)

    def _classify_with_rules(self, df):
        """Główna logika klasyfikacji na podstawie reguł JSON."""
        logger.info("Rozpoczęto klasyfikację regułową. Liczba zgłoszeń: %d", len(df))
        df_copy = df.copy()
        
        # Walidacja kolumny 'title'
        if 'title' not in df_copy.columns:
            logger.error("BŁĄD WALIDACJI: Brak kolumny 'title' w DataFrame")
            raise ValueError("DataFrame musi zawierać kolumnę 'title'")
        
        # Normalizacja tytułów do lowercase
        try:
            df_copy['title_lower'] = df_copy['title'].astype(str).str.lower()
        except Exception as e:
            logger.error(f"BŁĄD konwersji kolumny 'title': {e}")
            df_copy['title_lower'] = ''
        
        # Ograniczenie długości tekstu
        df_copy['title_lower'] = df_copy['title_lower'].str.slice(0, MAX_TITLE_LENGTH)
        
        # Wykluczenie zgłoszeń z frazą "telefon do"
        telefon_do_mask = df_copy['title_lower'].str.contains('telefon do', case=False, na=False)
        excluded_count = telefon_do_mask.sum()
        
        if excluded_count > 0:
            logger.info(f"🔇 Wykluczono {excluded_count} zgłoszeń zawierających 'telefon do' z klasyfikacji")
        
        df_copy['category'] = 'inne'
        df_copy['confidence'] = 0.5

        # Wczytanie reguł z JSON
        try:
            self.rules_manager.reload_rules()
            rules_dict = self.rules_manager.get_rules()
            
            # Limit maksymalnej liczby reguł
            if len(rules_dict) > MAX_RULES_LIMIT:
                logger.warning(f"Przekroczono limit reguł ({len(rules_dict)} > {MAX_RULES_LIMIT}). Ograniczam.")
                rules_dict = dict(list(rules_dict.items())[:MAX_RULES_LIMIT])
            
            logger.info(f"🔄 Wczytano {len(rules_dict)} reguł z JSON")
        except (RulesSecurityError, RulesValidationError) as e:
            logger.error(f"❌ Błąd podczas ładowania reguł: {e}")
            return df_copy
        except Exception as e:
            logger.exception(f"❌ Błąd podczas ładowania reguł klasyfikacji: {e}")
            return df_copy

        classified_count = 0
        for category, rule in rules_dict.items():
            # Walidacja nazwy kategorii
            if not self._validate_category_name(category):
                logger.warning(f"Pominięto kategorię z niedozwolonymi znakami: {category}")
                continue
                
            for idx, row in df_copy.iterrows():
                # Pomiń zgłoszenia z frazą "telefon do"
                if telefon_do_mask.iloc[idx]:
                    continue
                
                # Walidacja title_lower
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
        """Waliduje nazwę kategorii - dozwolone: litery, cyfry, podkreślenie, myślnik."""
        if not category_name or not isinstance(category_name, str):
            return False
        
        for char in category_name:
            if char not in ALLOWED_CATEGORY_CHARS:
                return False
        
        if len(category_name) > 100:
            return False
            
        return True

    def _calculate_rule_score(self, title_lower, rule):
        """
        Oblicza wynik dopasowania tytułu do reguły.
        
        Mechanizm dopasowywania:
        - Keywords: dopasowanie częściowe ("zawiesz" → "zawieszony")
        - Combinations: wszystkie słowa muszą wystąpić jako podciągi
        - Forbidden: jeśli znajdzie - odrzuca regułę
        - Normalizacja polskich znaków ("zużycie" → "zuzycie")
        
        Punktacja: keyword=1pkt, kombinacja 2słów=3pkt, 3słów=4pkt
        """
        # Walidacja danych wejściowych
        if not isinstance(title_lower, str):
            logger.warning(f"title_lower nie jest stringiem: {type(title_lower)}")
            return 0
        
        if not isinstance(rule, dict):
            logger.warning(f"reguła nie jest słownikiem: {type(rule)}")
            return 0
        
        # Ograniczenie długości tekstu
        if len(title_lower) > MAX_TITLE_LENGTH:
            title_lower = title_lower[:MAX_TITLE_LENGTH]
            logger.warning(f"Obcięto tytuł do {MAX_TITLE_LENGTH} znaków")
        
        # Normalizacja tekstu (polskie znaki)
        title_normalized = self._normalize_text(title_lower)
        logger.debug(f"🔤 Znormalizowano: '{title_lower}' → '{title_normalized}'")
        
        score = 0
        
        # Sprawdzenie zabronionych słów
        try:
            if 'forbidden' in rule and isinstance(rule['forbidden'], list):
                for forbidden in rule['forbidden']:
                    if isinstance(forbidden, str):
                        forbidden_normalized = self._normalize_text(forbidden)
                        if (forbidden in title_lower or 
                            forbidden_normalized in title_normalized or
                            forbidden in title_normalized):
                            logger.debug(f"🚫 Forbidden '{forbidden}' - odrzucam regułę")
                            return 0
        except Exception as e:
            logger.error(f"Błąd sprawdzania forbidden: {e}")
        
        # Sprawdzenie wymaganych kombinacji
        try:
            if 'required_combinations' in rule and isinstance(rule['required_combinations'], list):
                for combination in rule['required_combinations']:
                    if isinstance(combination, list):
                        # Dopasowanie częściowe z normalizacją
                        all_words_found = True
                        for word in combination:
                            if not isinstance(word, str):
                                all_words_found = False
                                break
                            
                            word_normalized = self._normalize_text(word)
                            word_found = (word in title_lower or 
                                        word_normalized in title_normalized or
                                        word in title_normalized)
                            
                            if not word_found:
                                all_words_found = False
                                break
                        
                        if all_words_found:
                            if len(combination) == 2:
                                score += 3
                                logger.debug(f"🎯 Kombinacja 2-słowna: {combination}")
                            elif len(combination) == 3:
                                score += 4
                                logger.debug(f"🎯 Kombinacja 3-słowna: {combination}")
                            else:
                                score += len(combination)
                                logger.debug(f"🎯 Kombinacja {len(combination)}-słowna: {combination}")
        except Exception as e:
            logger.error(f"Błąd sprawdzania kombinacji: {e}")

        # Sprawdzenie keywords
        try:
            if 'keywords' in rule and isinstance(rule['keywords'], list):
                for keyword in rule['keywords']:
                    if isinstance(keyword, str):
                        try:
                            # Dopasowanie częściowe z normalizacją
                            escaped_keyword = re.escape(keyword)
                            keyword_normalized = self._normalize_text(keyword)
                            escaped_keyword_normalized = re.escape(keyword_normalized)
                            
                            original_match = re.search(escaped_keyword, title_lower)
                            normalized_match = re.search(escaped_keyword_normalized, title_normalized)
                            cross_match = re.search(escaped_keyword, title_normalized)
                            
                            if original_match or normalized_match or cross_match:
                                score += 1
                                logger.debug(f"🎯 Keyword '{keyword}'")
                        except re.error as regex_err:
                            logger.warning(f"Błąd regex dla '{keyword}': {regex_err}")
        except Exception as e:
            logger.error(f"Błąd sprawdzania keywords: {e}")
        
        return score
