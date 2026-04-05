"""Moduł filtrów i heurystyk spamowych dla gmfwi.

Aby dodać nową heurystykę spamu, wystarczy napisać funkcję z dekoratorem
@_heuristic — zostanie automatycznie zarejestrowana i uruchamiana przez
check_spam(). Kolejność dekoratorów w pliku = kolejność sprawdzania.
"""

from __future__ import annotations

import logging
import os
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Callable, List

logger = logging.getLogger("gmfwi")

# ---------------------------------------------------------------------------
# Rejestr heurystyk spamowych
# ---------------------------------------------------------------------------

# Typ heurystyki: sparsowany EmailMessage + lista keywords → (is_spam, reason)
SpamHeuristic = Callable[[EmailMessage, List[str]], tuple[bool, str]]

_HEURISTICS: list[SpamHeuristic] = []


def _heuristic(fn: SpamHeuristic) -> SpamHeuristic:
    """Dekorator rejestrujący heurystykę spamu."""
    _HEURISTICS.append(fn)
    return fn


# ---------------------------------------------------------------------------
# Parsowanie filtrów z konfiguracji
# ---------------------------------------------------------------------------

def parse_filters_from_config(filter_str: str) -> List[dict]:
    """Parsuje filtry z config.ini.

    Format: field:value:label1,label2:never_spam
    Przykład: to:kuj4@o2.pl:kuj4@o2.pl:true
    """
    filters = []
    if not filter_str:
        logger.info("Brak zdefiniowanych filtrów")
        return filters

    logger.debug("Parsowanie filtrów z config: '%s'", filter_str[:100])

    for line in filter_str.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':', 3)
        if len(parts) >= 3:
            field = parts[0].strip().lower()
            value = parts[1].strip()
            labels = [l.strip() for l in parts[2].split(',') if l.strip()]
            never_spam = parts[3].strip().lower() == 'true' if len(parts) > 3 else False
            is_regex = any(c in value for c in '.[](){}*+?^$|\\')
            if is_regex:
                try:
                    re.compile(value)
                except re.error as e:
                    logger.warning("  ✗ Pominięto filtr — niepoprawny regex '%s': %s", value, e)
                    continue
            filters.append({
                'field': field,
                'value': value,
                'labels': labels,
                'never_spam': never_spam
            })
            logger.info("  ✓ Filtr: [%s] zawiera '%s' → etykiety: %s, never_spam: %s", field, value, labels, never_spam)
    return filters


# ---------------------------------------------------------------------------
# Ładowanie słów kluczowych spamu z pliku
# ---------------------------------------------------------------------------

def load_spam_keywords(filepath: str) -> List[str]:
    """Wczytuje słownik słów kluczowych/wyrażeń regularnych spamu z pliku.

    Jeden wpis na linię; linie zaczynające się od '#' są komentarzami.
    Zwraca pustą listę jeśli plik nie istnieje lub jest pusty.
    """
    if not filepath:
        return []
    if not os.path.exists(filepath):
        logger.warning("Plik spam_keywords_file nie istnieje: %s", filepath)
        return []
    keywords = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            is_regex = any(c in line for c in '.[](){}*+?^$|\\')
            if is_regex:
                try:
                    re.compile(line)
                except re.error as e:
                    logger.warning("  ✗ Pominięto spam keyword — niepoprawny regex '%s': %s", line, e)
                    continue
            keywords.append(line)
    logger.info("Wczytano %d spam keyword(s) z %s", len(keywords), filepath)
    return keywords


# ---------------------------------------------------------------------------
# Pomocnicze funkcje prywatne
# ---------------------------------------------------------------------------

def _extract_domain(addr: str) -> str:
    """Wyciąga domenę z adresu email (np. 'Foo <a@b.com>' -> 'b.com')."""
    m = re.search(r'@([\w.-]+)', addr)
    return m.group(1).lower() if m else ""


def _subject_has_unicode_math(subject: str) -> bool:
    """Sprawdza czy Subject zawiera znaki Unicode Mathematical Alphanumeric Symbols.

    Zakres U+1D400–U+1D7FF to litery bold/italic/script/fraktur/monospace używane
    przez spamerów do omijania filtrów tekstowych. Legitymne maile ich nie stosują.
    """
    for ch in subject:
        if 0x1D400 <= ord(ch) <= 0x1D7FF:
            return True
    return False


def _html_has_trailing_content(html: str) -> bool:
    """Sprawdza czy HTML zawiera treść (URL-e lub znaczniki) po zamykającym </html>.

    Spam często wkleja treść legalnego emaila jako body HTML, a własne linki
    i obrazki trackingowe dopisuje po tagu zamykającym </html>. To silny wskaźnik spamu.
    """
    m = re.search(r'</html\s*>', html, re.IGNORECASE)
    if not m:
        return False
    trailing = html[m.end():].strip()
    return bool(trailing and (
        re.search(r'https?://', trailing, re.IGNORECASE) or
        re.search(r'<[a-zA-Z]', trailing)
    ))


def _html_has_multiple_documents(html: str) -> bool:
    """Sprawdza czy w jednej części MIME text/html są osadzone dwa dokumenty HTML.

    Spam osadza legalny szablon (Poczta Polska, InPost itp.) jako "przykrywkę",
    a właściwą treść phishingową jako drugi dokument zaczynający się od <!DOCTYPE
    lub <html>. Legitymne emaile nigdy nie mają dwóch dokumentów HTML w jednej części MIME.
    """
    return (
        len(re.findall(r'<!DOCTYPE\b', html, re.IGNORECASE)) > 1 or
        len(re.findall(r'<html[\s>]', html, re.IGNORECASE)) > 1
    )


def message_has_attachments(raw_message: bytes) -> bool:
    """Sprawdza czy wiadomość zawiera załączniki."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        for part in msg.walk():
            if part.get_filename():
                return True
            cd = part.get("Content-Disposition", "")
            if cd.strip().lower().startswith("attachment"):
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Heurystyki spamowe (kolejność = priorytet)
# ---------------------------------------------------------------------------

@_heuristic
def _check_dkim_status(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """X-WP-DKIM-Status: bad — sfałszowany podpis DKIM."""
    dkim_status = msg.get("X-WP-DKIM-Status", "").lower()
    if dkim_status.startswith("bad"):
        return (True, f"X-WP-DKIM-Status: {msg.get('X-WP-DKIM-Status', '').strip()}")
    return (False, "")


@_heuristic
def _check_sender_domain_mismatch(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Sender vs From — różne domeny = ktoś podszywa się pod innego nadawcę."""
    sender = msg.get("Sender", "")
    from_addr = msg.get("From", "")
    if sender:
        sender_domain = _extract_domain(sender)
        from_domain = _extract_domain(from_addr)
        if sender_domain and from_domain and sender_domain != from_domain:
            return (True, f"Sender domain '{sender_domain}' ≠ From domain '{from_domain}'")
    return (False, "")


@_heuristic
def _check_unicode_math_subject(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Unicode Mathematical Alphanumeric Symbols w Subject — technika spamerów."""
    subject = msg.get("Subject", "")
    if _subject_has_unicode_math(subject):
        return (True, "[Unicode math letters w Subject]")
    return (False, "")


@_heuristic
def _check_non_ascii_message_id(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Non-ASCII znaki w Message-ID — malformed nagłówek, typowy dla spamu."""
    mid = msg.get("Message-ID", "").strip().strip('<>').strip()
    if mid and not mid.isascii():
        return (True, f"non-ASCII Message-ID: '{mid}'")
    return (False, "")


@_heuristic
def _check_html_trailing_content(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Treść (URL-e lub znaczniki) po zamykającym </html>."""
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            try:
                content = part.get_content() or ""
                if _html_has_trailing_content(content):
                    return (True, "[treść po </html>]")
            except Exception:
                pass
    return (False, "")


@_heuristic
def _check_html_multiple_documents(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Wiele dokumentów HTML (<!DOCTYPE> / <html>) w jednej części MIME."""
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            try:
                content = part.get_content() or ""
                if _html_has_multiple_documents(content):
                    return (True, "[wiele dokumentów HTML w jednej części MIME]")
            except Exception:
                pass
    return (False, "")


@_heuristic
def _check_body_keywords(msg: EmailMessage, keywords: List[str]) -> tuple[bool, str]:
    """Dopasowanie słów kluczowych/regex w treści wiadomości."""
    if not keywords:
        return (False, "")
    body_text = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct in ('text/plain', 'text/html'):
            try:
                content = part.get_content() or ""
                body_text += content
            except Exception:
                pass
    if not body_text:
        return (False, "")
    body_lower = body_text.lower()
    for kw in keywords:
        is_regex = any(c in kw for c in '.[](){}*+?^$|\\')
        if is_regex:
            m = re.search(kw, body_text, re.IGNORECASE)
            if m:
                return (True, m.group())
        else:
            if kw.lower() in body_lower:
                return (True, kw)
    return (False, "")


# ---------------------------------------------------------------------------
# Publiczne API — orchestrator spamu
# ---------------------------------------------------------------------------

def check_spam(raw_message: bytes, keywords: List[str]) -> tuple[bool, str]:
    """Uruchamia wszystkie zarejestrowane heurystyki spamu.

    Parsuje wiadomość raz i przekazuje do każdej heurystyki.
    Zwraca przy pierwszym trafieniu: (True, reason).
    Jeśli żadna nie trafi: (False, "").
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        for heuristic in _HEURISTICS:
            is_spam, reason = heuristic(msg, keywords)
            if is_spam:
                return (True, reason)
    except Exception:
        logger.exception("Błąd podczas sprawdzania wiadomości pod kątem spamu")
    return (False, "")


# ---------------------------------------------------------------------------
# Sprawdzanie wiadomości względem filtrów konfiguracyjnych
# ---------------------------------------------------------------------------

def check_message_against_filters(raw_message: bytes, filters: List[dict]) -> tuple[List[str], bool]:
    """Sprawdza wiadomość względem filtrów i zwraca (etykiety, never_spam).

    Wartość filtru obsługuje:
    - Prosty tekst (case-insensitive): 'gmail.com'
    - Regex (automatycznie wykrywany jeśli zawiera znaki regex): '.*@facebookmail\\.com'
    """
    labels_to_apply = set()
    never_spam = False

    if not filters:
        logger.debug("Brak filtrów do sprawdzenia")
        return ([], False)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_message)
        msg_to = msg.get('To', '')
        msg_from = msg.get('From', '')
        msg_subject = msg.get('Subject', '')

        logger.debug("Sprawdzanie filtrów dla wiadomości:")
        logger.debug("  To: %s", msg_to)
        logger.debug("  From: %s", msg_from)
        logger.debug("  Subject: %s", msg_subject)

        for filter_rule in filters:
            field = filter_rule['field']
            pattern = filter_rule['value']

            # Pobierz wartość pola z wiadomości
            if field == 'attach':
                # Wartość pola jest ignorowana — filtr pasuje gdy wiadomość ma dowolny załącznik
                if message_has_attachments(raw_message):
                    labels_to_apply.update(filter_rule['labels'])
                    never_spam = never_spam or filter_rule['never_spam']
                    logger.info("  ✓ DOPASOWANO! Wiadomość ma załączniki. Dodaję etykiety: %s",
                                filter_rule['labels'])
                else:
                    logger.debug("  ✗ Nie pasuje (brak załączników)")
                continue  # pomiń dalszą logikę pattern-matching
            elif field == 'to':
                header_value = msg_to
            elif field == 'from':
                header_value = msg_from
            elif field == 'subject':
                header_value = msg_subject
            else:
                continue

            # Sprawdzenie czy pattern jest regex czy zwykły tekst
            is_regex = any(c in pattern for c in '.[](){}*+?^$|\\')

            if is_regex:
                logger.debug("  Sprawdzanie: czy [%s] pasuje do regex '%s'?", field, pattern)
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    labels_to_apply.update(filter_rule['labels'])
                    never_spam = never_spam or filter_rule['never_spam']
                    logger.info("  ✓ REGEX DOPASOWANY: '%s'! Dodaję etykiety: %s", match.group(), filter_rule['labels'])
                else:
                    logger.debug("  ✗ Regex nie pasuje")
            else:
                value = pattern.lower()
                header_lower = header_value.lower()
                logger.debug("  Sprawdzanie: czy [%s]='%s' zawiera '%s'?", field, header_lower[:50], value)
                if value in header_lower:
                    labels_to_apply.update(filter_rule['labels'])
                    never_spam = never_spam or filter_rule['never_spam']
                    logger.info("  ✓ DOPASOWANO! Dodaję etykiety: %s, never_spam: %s", filter_rule['labels'], filter_rule['never_spam'])
                else:
                    logger.debug("  ✗ Nie pasuje")

        if labels_to_apply or never_spam:
            logger.info("Wynik sprawdzania: etykiety=%s, never_spam=%s", list(labels_to_apply), never_spam)
        else:
            logger.debug("Żaden filtr nie pasuje do tej wiadomości")

        return (list(labels_to_apply), never_spam)
    except Exception:
        logger.exception("Błąd podczas sprawdzania filtrów")
        return ([], False)
