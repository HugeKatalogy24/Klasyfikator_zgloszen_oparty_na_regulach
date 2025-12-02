#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# rules_manager.py
# Bezpieczny moduł zarządzania regułami klasyfikacji w formacie JSON

import json
import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import re

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RulesSecurityError(Exception):
    """Wyjątek dla problemów bezpieczeństwa w regułach"""
    pass

class RulesValidationError(Exception):
    """Wyjątek dla błędów walidacji reguł"""
    pass

class SecureRulesManager:
    """
    Bezpieczny menedżer reguł klasyfikacji.
    Wczytuje reguły z pliku JSON i zapewnia bezpieczny dostęp do nich.
    """
    
    def __init__(self, rules_file: str = "rules.json"):
        self.rules_file = rules_file
        self.rules = {}
        self.last_modified = None
        
        # BEZPIECZEŃSTWO: Walidacja ścieżki pliku reguł
        self._validate_rules_file_path()
        self._load_rules()
    
    def _validate_rules_file_path(self) -> None:
        """Waliduje ścieżkę pliku reguł pod kątem bezpieczeństwa"""
        import re
        from pathlib import Path
        
        # Niebezpieczne wzorce w ścieżkach
        dangerous_patterns = [
            r'\.\.[\\/]',  # Path traversal
            r'[\\/]\.\.[\\/]',  # Path traversal
            r'^[\\/]',  # Absolute paths (w niektórych przypadkach)
            r'[A-Za-z]:[\\/]',  # Windows drive paths
            r'~[\\/]',  # Home directory
            r'\$\{.*\}',  # Variable expansion
            r'%.*%',  # Windows environment variables
            r'<.*>',  # XML/HTML-like patterns
            r'[\x00-\x1f\x7f-\x9f]',  # Control characters
        ]
        
        # Sprawdź niebezpieczne wzorce
        for pattern in dangerous_patterns:
            if re.search(pattern, self.rules_file, re.IGNORECASE):
                raise RulesSecurityError(f"Niebezpieczny wzorzec w ścieżce pliku reguł: {pattern}")
        
        # Sprawdź rozszerzenie pliku
        path_obj = Path(self.rules_file)
        if path_obj.suffix.lower() != '.json':
            raise RulesSecurityError(f"Niedozwolone rozszerzenie pliku reguł: {path_obj.suffix}")
        
        # Sprawdź długość ścieżki
        if len(self.rules_file) > 255:
            raise RulesSecurityError("Ścieżka pliku reguł zbyt długa")
    
    def _load_rules(self) -> None:
        """Wczytuje reguły z pliku JSON z pełną walidacją bezpieczeństwa"""
        try:
            if not os.path.exists(self.rules_file):
                logger.warning(f"Plik reguł {self.rules_file} nie istnieje. Tworzę pusty zestaw reguł.")
                self.rules = {}
                return
            
            # Sprawdź rozmiar pliku (maksymalnie 10MB)
            file_size = os.path.getsize(self.rules_file)
            if file_size > 10 * 1024 * 1024:  # 10MB
                raise RulesSecurityError(f"Plik reguł zbyt duży: {file_size} bajtów")
            
            # Sprawdź czas modyfikacji
            self.last_modified = os.path.getmtime(self.rules_file)
            
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Walidacja zawartości przed parsowaniem
                self._validate_file_content(content)
                
                # Parsuj JSON
                raw_data = json.loads(content)
                
                # Walidacja struktury
                self._validate_rules_structure(raw_data)
                
                # Sanityzacja i walidacja każdej reguły
                self.rules = self._sanitize_rules(raw_data.get('classification_rules', {}))
                
                logger.info(f"Wczytano {len(self.rules)} reguł z {self.rules_file}")
                
        except json.JSONDecodeError as e:
            raise RulesValidationError(f"Błąd parsowania JSON: {e}")
        except Exception as e:
            logger.exception(f"Błąd wczytywania reguł z pliku {self.rules_file}: {e}")
            raise RulesSecurityError(f"Błąd wczytywania reguł: {e}")
    
    def _validate_file_content(self, content: str) -> None:
        """Waliduje zawartość pliku pod kątem potencjalnych zagrożeń"""
        # Sprawdź rozmiar zawartości
        if len(content) > 5 * 1024 * 1024:  # 5MB
            raise RulesSecurityError("Zawartość pliku zbyt duża")
        
        # Lista potencjalnie niebezpiecznych wzorców
        dangerous_patterns = [
            r'__import__',
            r'exec\s*\(',
            r'eval\s*\(',
            r'compile\s*\(',
            r'open\s*\(',
            r'file\s*\(',
            r'input\s*\(',
            r'raw_input\s*\(',
            r'subprocess',
            r'os\.system',
            r'os\.popen',
            r'os\.spawn',
            r'importlib',
            r'\.\./',
            r'<script',
            r'javascript:',
            r'vbscript:',
            r'function\s*\(',
            r'=>',
            r'lambda\s*:',
        ]
        
        content_lower = content.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, content_lower):
                raise RulesSecurityError(f"Znaleziono potencjalnie niebezpieczny wzorzec: {pattern}")
    
    def _validate_rules_structure(self, data: Dict[str, Any]) -> None:
        """Waliduje strukturę danych reguł"""
        if not isinstance(data, dict):
            raise RulesValidationError("Główna struktura musi być obiektem JSON")
        
        if 'classification_rules' not in data:
            raise RulesValidationError("Brak wymaganego klucza 'classification_rules'")
        
        rules = data['classification_rules']
        if not isinstance(rules, dict):
            raise RulesValidationError("'classification_rules' musi być obiektem")
        
        # Sprawdź liczbę reguł
        if len(rules) > 1000:
            raise RulesSecurityError("Zbyt wiele reguł (maksymalnie 1000)")
        
        # Waliduj każdą regułę
        for rule_name, rule_data in rules.items():
            self._validate_single_rule(rule_name, rule_data)
    
    def _validate_single_rule(self, rule_name: str, rule_data: Dict[str, Any]) -> None:
        """Waliduje pojedynczą regułę"""
        if not isinstance(rule_name, str):
            raise RulesValidationError(f"Nazwa reguły musi być stringiem")
        
        if len(rule_name) > 200:
            raise RulesValidationError(f"Nazwa reguły zbyt długa: {rule_name}")
        
        if not isinstance(rule_data, dict):
            raise RulesValidationError(f"Dane reguły '{rule_name}' muszą być obiektem")
        
        # Wymagane pola
        required_fields = ['keywords', 'min_score']
        for field in required_fields:
            if field not in rule_data:
                raise RulesValidationError(f"Brak wymaganego pola '{field}' w regule '{rule_name}'")
        
        # Waliduj keywords
        keywords = rule_data['keywords']
        if not isinstance(keywords, list):
            raise RulesValidationError(f"'keywords' w regule '{rule_name}' musi być listą")
        
        if len(keywords) > 100:
            raise RulesValidationError(f"Zbyt wiele słów kluczowych w regule '{rule_name}'")
        
        for keyword in keywords:
            if not isinstance(keyword, str):
                raise RulesValidationError(f"Słowo kluczowe w regule '{rule_name}' musi być stringiem")
            if len(keyword) > 100:
                raise RulesValidationError(f"Słowo kluczowe zbyt długie w regule '{rule_name}'")
        
        # Waliduj min_score
        min_score = rule_data['min_score']
        if not isinstance(min_score, int):
            raise RulesValidationError(f"'min_score' w regule '{rule_name}' musi być liczbą całkowitą")
        
        if min_score < 1 or min_score > 20:
            raise RulesValidationError(f"'min_score' w regule '{rule_name}' musi być między 1 a 20")
        
        # Waliduj opcjonalne pola
        if 'required_combinations' in rule_data:
            self._validate_combinations(rule_name, rule_data['required_combinations'])
        
        if 'forbidden' in rule_data:
            self._validate_forbidden(rule_name, rule_data['forbidden'])
    
    def _validate_combinations(self, rule_name: str, combinations: List[List[str]]) -> None:
        """Waliduje kombinacje wymagane"""
        if not isinstance(combinations, list):
            raise RulesValidationError(f"'required_combinations' w regule '{rule_name}' musi być listą")
        
        if len(combinations) > 50:
            raise RulesValidationError(f"Zbyt wiele kombinacji w regule '{rule_name}'")
        
        for i, combination in enumerate(combinations):
            if not isinstance(combination, list):
                raise RulesValidationError(f"Kombinacja {i} w regule '{rule_name}' musi być listą")
            
            if len(combination) > 10:
                raise RulesValidationError(f"Kombinacja {i} w regule '{rule_name}' zbyt długa")
            
            for word in combination:
                if not isinstance(word, str):
                    raise RulesValidationError(f"Słowo w kombinacji {i} w regule '{rule_name}' musi być stringiem")
                if len(word) > 100:
                    raise RulesValidationError(f"Słowo w kombinacji {i} w regule '{rule_name}' zbyt długie")
    
    def _validate_forbidden(self, rule_name: str, forbidden: List[str]) -> None:
        """Waliduje słowa zabronione"""
        if not isinstance(forbidden, list):
            raise RulesValidationError(f"'forbidden' w regule '{rule_name}' musi być listą")
        
        if len(forbidden) > 100:
            raise RulesValidationError(f"Zbyt wiele zabronionych słów w regule '{rule_name}'")
        
        for word in forbidden:
            if not isinstance(word, str):
                raise RulesValidationError(f"Zabronione słowo w regule '{rule_name}' musi być stringiem")
            if len(word) > 100:
                raise RulesValidationError(f"Zabronione słowo w regule '{rule_name}' zbyt długie")
    
    def _sanitize_rules(self, raw_rules: Dict[str, Any]) -> Dict[str, Any]:
        """Sanityzuje reguły usuwając potencjalnie niebezpieczne elementy"""
        sanitized = {}
        
        for rule_name, rule_data in raw_rules.items():
            # Sanityzuj nazwę reguły
            clean_name = self._sanitize_string(rule_name)
            if not clean_name:
                continue
            
            # Sanityzuj dane reguły
            sanitized_rule = {
                'keywords': [self._sanitize_string(kw) for kw in rule_data.get('keywords', []) if self._sanitize_string(kw)],
                'min_score': int(rule_data.get('min_score', 1))
            }
            
            # Sanityzuj kombinacje
            if 'required_combinations' in rule_data:
                sanitized_combinations = []
                for combo in rule_data['required_combinations']:
                    sanitized_combo = [self._sanitize_string(word) for word in combo if self._sanitize_string(word)]
                    if len(sanitized_combo) >= 2:  # Kombinacja musi mieć co najmniej 2 słowa
                        sanitized_combinations.append(sanitized_combo)
                
                if sanitized_combinations:
                    sanitized_rule['required_combinations'] = sanitized_combinations
            
            # Sanityzuj słowa zabronione
            if 'forbidden' in rule_data:
                sanitized_forbidden = [self._sanitize_string(word) for word in rule_data['forbidden'] if self._sanitize_string(word)]
                if sanitized_forbidden:
                    sanitized_rule['forbidden'] = sanitized_forbidden
            
            # Dodaj regułę tylko jeśli ma słowa kluczowe
            if sanitized_rule['keywords']:
                sanitized[clean_name] = sanitized_rule
        
        return sanitized
    
    def _sanitize_string(self, text: str) -> str:
        """Sanityzuje string usuwając potencjalnie niebezpieczne znaki"""
        if not isinstance(text, str):
            return ""
        
        # Usuń znaki kontrolne i specjalne
        text = re.sub(r'[^\w\s\-\ąćęłńóśźżĄĆĘŁŃÓŚŹŻ./+%()]', '', text)
        
        # Ogranicz długość
        text = text[:100]
        
        # Usuń leading/trailing whitespace
        text = text.strip()
        
        return text
    
    def get_rules(self) -> Dict[str, Any]:
        """Zwraca kopię reguł (bezpieczne dla zewnętrznego dostępu)"""
        return self.rules.copy()
    
    def get_rule(self, rule_name: str) -> Optional[Dict[str, Any]]:
        """Zwraca konkretną regułę"""
        return self.rules.get(rule_name)
    
    def reload_rules(self) -> bool:
        """Przeładowuje reguły z pliku"""
        try:
            old_count = len(self.rules)
            self._load_rules()
            new_count = len(self.rules)
            
            logger.info(f"Przeładowano reguły: {old_count} -> {new_count}")
            return True
            
        except Exception as e:
            logger.exception(f"Błąd przeładowania reguł z pliku {self.rules_file}: {e}")
            return False
    
    def save_rules(self, new_rules: Dict[str, Any]) -> bool:
        """Zapisuje reguły do pliku JSON z walidacją"""
        try:
            # Przygotuj strukturę danych
            data_to_save = {
                "classification_rules": new_rules,
                "metadata": {
                    "last_updated": datetime.now().isoformat(),
                    "version": "2.0",
                    "rules_count": len(new_rules)
                }
            }
            
            # Waliduj przed zapisaniem
            self._validate_rules_structure(data_to_save)
            
            # Utwórz kopię zapasową w folderze backups
            if os.path.exists(self.rules_file):
                # Upewnij się, że folder backups istnieje
                os.makedirs('backups', exist_ok=True)
                
                # Nazwij backup z timestampem
                backup_name = f"backups/rules.json_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                # Skopiuj istniejący plik
                with open(self.rules_file, 'r', encoding='utf-8') as src:
                    with open(backup_name, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                logger.info(f"Utworzono kopię zapasową: {backup_name}")
                
                # Wyczyść stare backupy (zachowaj ostatnie 10)
                self._cleanup_old_json_backups()
            
            # Zapisz nowe reguły
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(data_to_save, f, indent=2, ensure_ascii=False)
            
            # Przeładuj do pamięci
            self._load_rules()
            
            logger.info(f"Zapisano {len(new_rules)} reguł do {self.rules_file}")
            return True
            
        except Exception as e:
            logger.exception(f"Błąd zapisywania reguł do pliku {self.rules_file}: {e}")
            return False
    
    def add_rule(self, rule_name: str, rule_data: Dict[str, Any]) -> bool:
        """Dodaje nową regułę"""
        try:
            # Waliduj regułę
            self._validate_single_rule(rule_name, rule_data)
            
            # Dodaj do aktualnych reguł
            updated_rules = self.rules.copy()
            updated_rules[rule_name] = rule_data
            
            # Zapisz
            return self.save_rules(updated_rules)
            
        except Exception as e:
            logger.exception(f"Błąd dodawania nowej reguły '{rule_name}': {e}")
            return False
    
    def update_rule(self, rule_name: str, rule_data: Dict[str, Any]) -> bool:
        """Aktualizuje istniejącą regułę"""
        try:
            # Waliduj regułę
            self._validate_single_rule(rule_name, rule_data)
            
            # Aktualizuj reguły
            updated_rules = self.rules.copy()
            updated_rules[rule_name] = rule_data
            
            # Zapisz
            return self.save_rules(updated_rules)
            
        except Exception as e:
            logger.exception(f"Błąd aktualizacji reguły klasyfikacji '{rule_name}': {e}")
            return False
    
    def delete_rule(self, rule_name: str) -> bool:
        """Usuwa regułę"""
        try:
            if rule_name not in self.rules:
                logger.warning(f"Reguła '{rule_name}' nie istnieje")
                return False
            
            # Usuń regułę
            updated_rules = self.rules.copy()
            del updated_rules[rule_name]
            
            # Zapisz
            return self.save_rules(updated_rules)
            
        except Exception as e:
            logger.exception(f"Błąd usuwania reguły klasyfikacji '{rule_name}': {e}")
            return False
    
    def get_rules_count(self) -> int:
        """Zwraca liczbę reguł"""
        return len(self.rules)
    
    def get_rules_summary(self) -> Dict[str, Any]:
        """Zwraca podsumowanie reguł"""
        return {
            'total_rules': len(self.rules),
            'rule_names': list(self.rules.keys()),
            'last_modified': self.last_modified,
            'file_path': self.rules_file
        }
    
    def _cleanup_old_json_backups(self, keep=10):
        """Usuwa stare backupy plików JSON, zachowując najnowsze"""
        try:
            backup_dir = 'backups'
            if not os.path.exists(backup_dir):
                return
                
            # Znajdź wszystkie backupy rules.json
            backups = []
            for file in os.listdir(backup_dir):
                if file.startswith('rules.json_backup_') and file.endswith('.json'):
                    path = os.path.join(backup_dir, file)
                    backups.append((os.path.getmtime(path), path))
            
            # Sortuj według czasu modyfikacji (najnowsze pierwsze)
            backups.sort(reverse=True)
            
            # Usuń stare backupy
            for _, path in backups[keep:]:
                os.remove(path)
                logger.info(f"Usunięto stary backup: {path}")
                
        except Exception as e:
            logger.exception(f"Błąd czyszczenia starych kopii zapasowych JSON: {e}")

# Globalna instancja menedżera reguł
rules_manager = SecureRulesManager()

# Funkcja kompatybilności z starym systemem
def get_classification_rules() -> Dict[str, Any]:
    """Funkcja kompatybilności zwracająca reguły w starym formacie"""
    return rules_manager.get_rules()

# Stała kompatybilności
CLASSIFICATION_RULES = get_classification_rules()
