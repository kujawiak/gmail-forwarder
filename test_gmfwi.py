"""Testy jednostkowe dla gmfwi.py.

Uruchom wszystkie testy:
    pytest test_gmfwi.py -v

Uruchom konkretną klasę:
    pytest test_gmfwi.py::TestParseFilters -v

# JAK DZIAŁAJĄ TESTY JEDNOSTKOWE?
# =================================
# Każda funkcja "test_*" to jeden test. pytest uruchamia je automatycznie.
# Wewnątrz testu sprawdzamy wynik przez `assert` — jeśli warunek jest
# fałszywy, test kończy się błędem z czytelnym komunikatem.
#
# Trzy etapy każdego testu (wzorzec AAA):
#   Arrange  — przygotuj dane wejściowe
#   Act      — wywołaj testowaną funkcję
#   Assert   — sprawdź wynik
"""

import textwrap
from email.message import EmailMessage

import pytest

from filters import check_message_against_filters, check_spam, parse_filters_from_config
from gmfwi import _kr_gmail_key, _kr_source_key, load_accounts


# ---------------------------------------------------------------------------
# Pomocnicze — budowanie surowych bajtów RFC822
# ---------------------------------------------------------------------------
# Zamiast prawdziwego serwera IMAP, budujemy wiadomości ręcznie w pamięci.
# `email.message.EmailMessage` to standardowa biblioteka Pythona — tworzy
# poprawne bajty RFC822, identyczne z tym co wysyła serwer pocztowy.

def make_raw_email(
    to: str = "",
    from_: str = "",
    subject: str = "",
    body: str = "plain text",
) -> bytes:
    """Tworzy minimalne surowe bajty RFC822 do użycia w testach."""
    msg = EmailMessage()
    msg["To"] = to
    msg["From"] = from_
    msg["Subject"] = subject
    msg["Message-ID"] = "<test@example.com>"
    msg.set_content(body)
    return bytes(msg)


# ---------------------------------------------------------------------------
# parse_filters_from_config
# ---------------------------------------------------------------------------
# Testujemy czystą funkcję — tylko string na wejściu, lista na wyjściu.
# Nie potrzebujemy żadnych mocków ani plików.

class TestParseFilters:

    def test_empty_string_returns_empty_list(self):
        # Arrange + Act
        result = parse_filters_from_config("")
        # Assert
        assert result == []

    def test_single_valid_filter(self):
        result = parse_filters_from_config("to:user@example.com:Label:true")

        assert len(result) == 1
        assert result[0] == {
            "field": "to",
            "value": "user@example.com",
            "labels": ["Label"],
            "never_spam": True,
        }

    def test_never_spam_defaults_to_false_when_missing(self):
        # Tylko 3 kolumny — bez never_spam
        result = parse_filters_from_config("from:boss@work.com:Boss")
        assert result[0]["never_spam"] is False

    def test_never_spam_false_explicit(self):
        result = parse_filters_from_config("from:news@press.com:News:false")
        assert result[0]["never_spam"] is False

    def test_multiple_labels_split_by_comma(self):
        result = parse_filters_from_config("from:news@example.com:News,Promo:false")
        assert result[0]["labels"] == ["News", "Promo"]

    def test_comment_lines_are_ignored(self):
        result = parse_filters_from_config("# to:skip@example.com:Label:true")
        assert result == []

    def test_empty_lines_are_ignored(self):
        config = "\n\nto:user@example.com:Label:true\n\n"
        result = parse_filters_from_config(config)
        assert len(result) == 1

    def test_multiple_filters_parsed_in_order(self):
        config = textwrap.dedent("""\
            to:user1@example.com:Label1:true
            from:user2@example.com:Label2:false
        """)
        result = parse_filters_from_config(config)
        assert len(result) == 2
        assert result[0]["field"] == "to"
        assert result[1]["field"] == "from"

    def test_field_name_is_lowercased(self):
        # Upewniamy się że "TO" działa tak samo jak "to"
        result = parse_filters_from_config("TO:user@example.com:Label:true")
        assert result[0]["field"] == "to"

    # @pytest.mark.parametrize — uruchamia TEN SAM test z różnymi danymi.
    # Zamiast pisać 3 oddzielne testy dla true/True/1, piszemy jeden.
    # pytest pokaże je osobno w raporcie: test_never_spam_true_values[true] itd.
    @pytest.mark.parametrize("never_spam_str", ["true", "True", "TRUE"])
    def test_never_spam_true_values(self, never_spam_str):
        result = parse_filters_from_config(f"from:x@x.com:Label:{never_spam_str}")
        assert result[0]["never_spam"] is True


# ---------------------------------------------------------------------------
# check_message_against_filters
# ---------------------------------------------------------------------------
# Tutaj wejściem są surowe bajty wiadomości — używamy make_raw_email().
# Ważna zasada kodu: wartość filtru jest regexem jeśli zawiera znaki
# specjalne (.[](){}*+?^$|\) — inaczej traktowana jak plain substring.

class TestCheckMessageAgainstFilters:

    def test_empty_filters_returns_no_labels(self):
        raw = make_raw_email(to="user@example.com")
        labels, never_spam = check_message_against_filters(raw, [])
        assert labels == []
        assert never_spam is False

    # Testy substring (wartości bez znaków specjalnych regex)

    def test_substring_match_on_to_field(self):
        raw = make_raw_email(to="user@mycompany.com")
        filters = [{"field": "to", "value": "mycompany", "labels": ["Work"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Work" in labels

    def test_substring_match_on_from_field(self):
        raw = make_raw_email(from_="boss@work.com")
        filters = [{"field": "from", "value": "boss", "labels": ["Boss"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Boss" in labels

    def test_substring_match_on_subject_field(self):
        raw = make_raw_email(subject="Invoice 2024")
        filters = [{"field": "subject", "value": "invoice", "labels": ["Invoices"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Invoices" in labels

    def test_substring_match_is_case_insensitive(self):
        raw = make_raw_email(subject="INVOICE 2024")
        filters = [{"field": "subject", "value": "invoice", "labels": ["Invoices"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Invoices" in labels

    def test_no_match_returns_empty_labels(self):
        raw = make_raw_email(subject="Hello")
        filters = [{"field": "subject", "value": "xyz_not_present", "labels": ["Label"], "never_spam": False}]
        labels, never_spam = check_message_against_filters(raw, filters)
        assert labels == []
        assert never_spam is False

    def test_never_spam_propagates_on_match(self):
        raw = make_raw_email(from_="boss@work.com")
        filters = [{"field": "from", "value": "boss", "labels": [], "never_spam": True}]
        _, never_spam = check_message_against_filters(raw, filters)
        assert never_spam is True

    def test_never_spam_false_when_no_match(self):
        raw = make_raw_email(from_="nobody@nowhere.com")
        filters = [{"field": "from", "value": "boss", "labels": [], "never_spam": True}]
        _, never_spam = check_message_against_filters(raw, filters)
        assert never_spam is False

    # Testy regex (wartości ze znakami specjalnymi — auto-detected)

    def test_regex_match(self):
        raw = make_raw_email(from_="user@facebookmail.com")
        filters = [{"field": "from", "value": r".*@facebookmail\.com", "labels": ["Facebook"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Facebook" in labels

    def test_regex_no_match(self):
        raw = make_raw_email(from_="user@gmail.com")
        filters = [{"field": "from", "value": r".*@facebookmail\.com", "labels": ["Facebook"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert labels == []

    def test_regex_alternation(self):
        # "Invoice|FV" to regex z "|" — pasuje do obu wariantów
        filters = [{"field": "subject", "value": "Invoice|FV", "labels": ["Invoices"], "never_spam": False}]

        raw_invoice = make_raw_email(subject="Invoice #123")
        labels, _ = check_message_against_filters(raw_invoice, filters)
        assert "Invoices" in labels

        raw_fv = make_raw_email(subject="FV 2024/01")
        labels, _ = check_message_against_filters(raw_fv, filters)
        assert "Invoices" in labels

    # Testy zachowania przy wielu filtrach

    def test_multiple_matching_filters_merge_labels(self):
        raw = make_raw_email(from_="boss@work.com", subject="Invoice")
        filters = [
            {"field": "from", "value": "boss", "labels": ["Boss"], "never_spam": False},
            {"field": "subject", "value": "invoice", "labels": ["Invoices"], "never_spam": False},
        ]
        labels, _ = check_message_against_filters(raw, filters)
        assert "Boss" in labels
        assert "Invoices" in labels

    def test_never_spam_is_true_when_any_matching_filter_sets_it(self):
        raw = make_raw_email(from_="boss@work.com", subject="Invoice")
        filters = [
            {"field": "from", "value": "boss", "labels": [], "never_spam": False},
            {"field": "subject", "value": "invoice", "labels": [], "never_spam": True},
        ]
        _, never_spam = check_message_against_filters(raw, filters)
        assert never_spam is True

    def test_unknown_field_is_silently_skipped(self):
        raw = make_raw_email()
        filters = [{"field": "cc", "value": "someone", "labels": ["Label"], "never_spam": False}]
        labels, _ = check_message_against_filters(raw, filters)
        assert labels == []

    def test_invalid_regex_does_not_crash(self):
        # "[invalid(regex" to nieprawidłowy regex — funkcja powinna obsłużyć
        # wyjątek re.error i po prostu nie dopasować filtru
        raw = make_raw_email(from_="user@example.com")
        filters = [{"field": "from", "value": "[invalid(regex", "labels": ["Label"], "never_spam": False}]
        labels, never_spam = check_message_against_filters(raw, filters)
        assert labels == []
        assert never_spam is False


# ---------------------------------------------------------------------------
# check_spam
# ---------------------------------------------------------------------------
# Testujemy zunifikowane API spamowe — jedno wywołanie zamiast osobnych
# check_header_for_spam + check_body_for_spam + inline checks.

def _make_raw_email_with_headers(**extra_headers) -> bytes:
    """Tworzy surowe bajty RFC822 z dodatkowymi nagłówkami."""
    msg = EmailMessage()
    msg["To"] = "user@example.com"
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<test@example.com>"
    for key, value in extra_headers.items():
        msg[key] = value
    msg.set_content("plain text")
    return bytes(msg)


class TestCheckSpam:

    def test_clean_message_is_not_spam(self):
        raw = make_raw_email(from_="boss@work.com", subject="Meeting")
        is_spam, reason = check_spam(raw, [])
        assert is_spam is False
        assert reason == ""

    def test_bad_dkim_detected(self):
        raw = _make_raw_email_with_headers(**{"X-WP-DKIM-Status": "bad (testing)"})
        is_spam, reason = check_spam(raw, [])
        assert is_spam is True
        assert "DKIM" in reason

    def test_sender_domain_mismatch_detected(self):
        msg = EmailMessage()
        msg["To"] = "user@example.com"
        msg["From"] = "legit@bank.com"
        msg["Sender"] = "spammer@evil.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"
        msg.set_content("hello")
        raw = bytes(msg)
        is_spam, reason = check_spam(raw, [])
        assert is_spam is True
        assert "evil.com" in reason

    def test_unicode_math_in_subject_detected(self):
        # U+1D400 = Mathematical Bold Capital A (𝐀)
        raw = make_raw_email(subject="Free \U0001D400 offer!")
        is_spam, reason = check_spam(raw, [])
        assert is_spam is True
        assert "Unicode math" in reason

    def test_non_ascii_message_id_detected(self):
        # Biblioteka email nie pozwala na non-ASCII w Message-ID,
        # więc budujemy surowe bajty ręcznie (symulacja malformed wiadomości)
        raw = (
            b"To: user@example.com\r\n"
            b"From: sender@example.com\r\n"
            b"Subject: Test\r\n"
            b"Message-ID: <t\xc3\xabst@example.com>\r\n"
            b"\r\n"
            b"hello\r\n"
        )
        is_spam, reason = check_spam(raw, [])
        assert is_spam is True
        assert "non-ASCII Message-ID" in reason

    def test_body_keyword_match(self):
        raw = make_raw_email(body="Click here to claim your FREE PRIZE")
        is_spam, reason = check_spam(raw, ["free prize"])
        assert is_spam is True
        assert reason == "free prize"

    def test_body_keyword_no_match(self):
        raw = make_raw_email(body="Meeting at 3pm")
        is_spam, reason = check_spam(raw, ["free prize"])
        assert is_spam is False

    def test_body_regex_keyword_match(self):
        raw = make_raw_email(body="Visit http://evil.example.com now!")
        is_spam, reason = check_spam(raw, [r"http://evil\.example\.com"])
        assert is_spam is True


# ---------------------------------------------------------------------------
# load_accounts
# ---------------------------------------------------------------------------
# `tmp_path` to wbudowany "fixture" pytest — automatycznie tworzy tymczasowy
# katalog na czas testu i usuwa go po zakończeniu. Idealne do testowania
# funkcji, które czytają pliki.
# Przekazujemy go jako argument funkcji — pytest wstrzykuje go automatycznie.

class TestLoadAccounts:

    def test_missing_config_file_returns_empty_list(self, tmp_path):
        result = load_accounts(str(tmp_path / "nonexistent.ini"))
        assert result == []

    def test_valid_account_is_loaded(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            host = imap.work.example.com
            user = worker@example.com
            gmail_user = worker@gmail.com
        """))
        accounts = load_accounts(str(config))
        assert len(accounts) == 1
        assert accounts[0]["name"] == "work"
        assert accounts[0]["host"] == "imap.work.example.com"
        assert accounts[0]["user"] == "worker@example.com"

    def test_section_without_host_is_skipped(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            user = worker@example.com
            gmail_user = worker@gmail.com
        """))
        assert load_accounts(str(config)) == []

    def test_section_without_gmail_user_is_skipped(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            host = imap.example.com
            user = worker@example.com
        """))
        assert load_accounts(str(config)) == []

    def test_defaults_section_provides_fallback_values(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [defaults]
            gmail_user = shared@gmail.com

            [work]
            host = imap.work.example.com
            user = worker@example.com
        """))
        accounts = load_accounts(str(config))
        assert accounts[0]["gmail_user"] == "shared@gmail.com"

    def test_defaults_section_is_not_an_account(self, tmp_path):
        # [defaults] nie powinien być zwracany jako konto
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [defaults]
            host = imap.example.com
            user = user@example.com
            gmail_user = user@gmail.com
        """))
        assert load_accounts(str(config)) == []

    def test_mark_source_as_read_parsed_as_bool(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            host = imap.work.example.com
            user = worker@example.com
            gmail_user = worker@gmail.com
            mark_source_as_read = true
        """))
        accounts = load_accounts(str(config))
        assert accounts[0]["mark_source_as_read"] is True

    def test_ssl_is_true_by_default(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            host = imap.work.example.com
            user = worker@example.com
            gmail_user = worker@gmail.com
        """))
        accounts = load_accounts(str(config))
        assert accounts[0]["ssl"] is True

    def test_multiple_accounts_all_loaded(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [work]
            host = imap.work.com
            user = w@work.com
            gmail_user = w@gmail.com

            [personal]
            host = imap.personal.com
            user = p@personal.com
            gmail_user = p@gmail.com
        """))
        accounts = load_accounts(str(config))
        assert len(accounts) == 2
        assert {a["name"] for a in accounts} == {"work", "personal"}

    def test_account_section_overrides_default(self, tmp_path):
        config = tmp_path / "config.ini"
        config.write_text(textwrap.dedent("""\
            [defaults]
            gmail_folder = INBOX

            [work]
            host = imap.work.com
            user = w@work.com
            gmail_user = w@gmail.com
            gmail_folder = Work
        """))
        accounts = load_accounts(str(config))
        assert accounts[0]["gmail_folder"] == "Work"


# ---------------------------------------------------------------------------
# Keyring key helpers
# ---------------------------------------------------------------------------
# Trywialne testy — ale dokumentują kontrakt: jak wyglądają klucze w keyring.
# Gdyby ktoś zmienił format klucza, te testy złapią regresję.

class TestKeyringKeys:

    def test_source_key_format(self):
        key = _kr_source_key("work", "user@example.com", "imap.example.com")
        assert key == "imap:work:user@example.com@imap.example.com"

    def test_gmail_key_format(self):
        key = _kr_gmail_key("work", "user@gmail.com")
        assert key == "gmail:work:user@gmail.com"
