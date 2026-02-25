"""GMail Forwarder IMAP — kopiuje wiadomości na Gmail przez IMAP APPEND.

Różnica względem gmfw.py: zamiast wysyłać przez SMTP, wiadomość jest
kopiowana bezpośrednio do skrzynki Gmail przez IMAP APPEND.
Zalety:
  - zachowana oryginalna data, nadawca i cała struktura wiadomości (HTML, załączniki)
  - brak ograniczeń SMTP serwera macierzystego
  - wiadomość trafia "czysto", identycznie jak oryginał

Wymaga Hasła do aplikacji Gmail (App Password):
  https://myaccount.google.com/apppasswords

Uruchom: python gmfwi.py --config config.ini --account kuj4 --autoforward
"""

from __future__ import annotations

import argparse
import configparser
import getpass
import imaplib
import logging
import os
import re
import sys
import time
from email.parser import BytesParser
from email import policy
from email.utils import parsedate_to_datetime
from imaplib import IMAP4, IMAP4_SSL
from typing import List, Optional

try:
	import keyring
except Exception:
	keyring = None

SERVICE_NAME = "gmfwi"
GMAIL_HOST = "imap.gmail.com"
GMAIL_PORT = 993

logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("gmfwi")


# ---------------------------------------------------------------------------
# IMAP — serwer źródłowy
# ---------------------------------------------------------------------------

def connect_imap(host: str, user: str, password: str, port: int | None = None, use_ssl: bool = True, timeout: int = 10) -> IMAP4:
	"""Nawiązuje połączenie z serwerem IMAP i loguje użytkownika."""
	logger.info("Łączenie z %s (ssl=%s, port=%s)", host, use_ssl, port)
	if use_ssl:
		server = IMAP4_SSL(host, port or 993, timeout=timeout)
	else:
		server = IMAP4(host, port or 143, timeout=timeout)
	server.login(user, password)
	logger.info("Zalogowano jako %s", user)
	return server


def get_uid_list(server: IMAP4, folder: str = "INBOX") -> List[int]:
	"""Zwraca listę trwałych UID wiadomości w folderze IMAP (przez UID SEARCH)."""
	try:
		server.select(folder, readonly=True)
	except Exception:
		logger.warning("Nie udało się wybrać folderu %s", folder)
		return []
	resp, data = server.uid("SEARCH", "ALL")
	if resp != "OK" or not data:
		return []
	try:
		return [int(uid) for uid in data[0].split()] if data[0] else []
	except Exception:
		return []


def fetch_full_message(server: IMAP4, uid: int, folder: str = "INBOX") -> bytes:
	"""Pobiera pełną wiadomość (RFC822) z IMAP przez UID FETCH."""
	try:
		server.select(folder, readonly=True)
		resp, data = server.uid("FETCH", str(uid), "(RFC822)")
		if resp != "OK":
			logger.warning("UID FETCH uid=%s zwróciło odpowiedź: %s", uid, resp)
			return b""
		if not data or data[0] is None:
			logger.warning("UID FETCH uid=%s: pusta odpowiedź (data=%r)", uid, data)
			return b""
		if not isinstance(data[0], tuple):
			logger.warning("UID FETCH uid=%s: nieoczekiwany format odpowiedzi (data[0]=%r)", uid, data[0])
			return b""
		return data[0][1]
	except Exception:
		logger.exception("Błąd pobierania wiadomości UID=%s", uid)
	return b""


def _uid_store(server: IMAP4, uid: int, folder: str, op: str, flags: str) -> tuple:
	"""Wybiera folder i wykonuje UID STORE na podanym UID."""
	server.select(folder, readonly=False)
	return server.uid("STORE", str(uid), op, flags)


def move_to_trash(server: IMAP4, uid: int, source_folder: str = "INBOX", trash_folder: str = "Trash") -> bool:
	"""Przenosi wiadomość do folderu Trash (przez UID COPY + UID STORE + EXPUNGE)."""
	try:
		server.select(source_folder, readonly=False)
		resp, _ = server.uid("COPY", str(uid), trash_folder)
		if resp == "OK":
			resp, _ = _uid_store(server, uid, source_folder, "+FLAGS", "(\\Deleted)")
			if resp == "OK":
				server.expunge()
				logger.debug("Wiadomość UID=%s przeniesiona do %s", uid, trash_folder)
				return True
	except Exception as e:
		logger.debug("Błąd przenoszenia wiadomości UID=%s: %s", uid, e)
	return False


def mark_as_read(server: IMAP4, uid: int, folder: str = "INBOX") -> bool:
	"""Oznacza wiadomość jako przeczytaną (flaga \\Seen)."""
	try:
		resp, _ = _uid_store(server, uid, folder, "+FLAGS", "(\\Seen)")
		if resp == "OK":
			logger.info("Wiadomość UID=%s oznaczona jako przeczytana", uid)
			return True
		logger.warning("Nie udało się oznaczyć UID=%s jako przeczytanej: %s", uid, resp)
		return False
	except Exception as e:
		logger.debug("Błąd oznaczania wiadomości UID=%s: %s", uid, e)
	return False


def fetch_message_info(server: IMAP4, uid: int, folder: str = "INBOX") -> dict:
	"""Pobiera nagłówki i krótki podgląd treści wiadomości (bez pobierania załączników)."""
	try:
		server.select(folder, readonly=True)

		# Pobierz tylko potrzebne nagłówki — bez treści i załączników
		resp, data = server.uid("FETCH", str(uid), "(BODY.PEEK[HEADER.FIELDS (Subject From Date)])")
		if resp != "OK" or not data or not isinstance(data[0], tuple):
			return {"subject": "(błąd odczytu)", "from": "", "date": "", "preview": ""}
		msg = BytesParser(policy=policy.default).parsebytes(data[0][1])

		# Pobierz pierwsze 2000 bajtów treści bez ustawiania flagi \Seen
		preview = ""
		resp, text_data = server.uid("FETCH", str(uid), "(BODY.PEEK[TEXT]<0.2000>)")
		if resp == "OK" and text_data and isinstance(text_data[0], tuple):
			try:
				raw = text_data[0][1].decode("utf-8", errors="replace")
				# Dla wiadomości multipart pomiń nagłówki części MIME (do pierwszej pustej linii)
				sep = raw.find("\r\n\r\n")
				preview = raw[sep + 4:].strip()[:1000] if sep != -1 else raw.strip()[:1000]
			except Exception:
				pass

		return {
			"subject": msg.get("Subject", "(brak tematu)"),
			"from": msg.get("From", "(brak nadawcy)"),
			"date": msg.get("Date", ""),
			"preview": preview,
		}
	except Exception:
		logger.exception("Błąd podczas pobierania podglądu wiadomości UID=%s", uid)
		return {"subject": "(błąd)", "from": "", "date": "", "preview": ""}


# ---------------------------------------------------------------------------
# Gmail IMAP APPEND
# ---------------------------------------------------------------------------

def connect_gmail(gmail_user: str, gmail_password: str, timeout: int = 10) -> IMAP4_SSL:
	"""Łączy się z Gmail przez IMAP SSL."""
	return connect_imap(GMAIL_HOST, gmail_user, gmail_password, port=GMAIL_PORT, timeout=timeout)


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
			filters.append({
				'field': field,
				'value': value,
				'labels': labels,
				'never_spam': never_spam
			})
			logger.info("  ✓ Filtr: [%s] zawiera '%s' → etykiety: %s, never_spam: %s", field, value, labels, never_spam)
	return filters


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
		
		logger.info("Sprawdzanie filtrów dla wiadomości:")
		logger.info("  To: %s", msg_to)
		logger.info("  From: %s", msg_from)
		logger.info("  Subject: %s", msg_subject)
		
		for filter_rule in filters:
			field = filter_rule['field']
			pattern = filter_rule['value']
			
			# Pobierz wartość pola z wiadomości
			if field == 'to':
				header_value = msg_to
			elif field == 'from':
				header_value = msg_from
			elif field == 'subject':
				header_value = msg_subject
			else:
				continue
			
			# Sprawdzenie czy pattern jest regex czy zwykły tekst
			# Regex to tekst zawierający znaki specjalne: . * + ^ $ [ ] ( ) | \
			is_regex = any(c in pattern for c in '.[](){}*+?^$|\\')
			
			try:
				if is_regex:
					logger.info("  Sprawdzanie: czy [%s] pasuje do regex '%s'?", field, pattern)
					match = re.search(pattern, header_value, re.IGNORECASE)
					if match:
						labels_to_apply.update(filter_rule['labels'])
						never_spam = never_spam or filter_rule['never_spam']
						logger.info("  ✓ REGEX DOPASOWANY: '%s'! Dodaję etykiety: %s", match.group(), filter_rule['labels'])
					else:
						logger.info("  ✗ Regex nie pasuje")
				else:
					value = pattern.lower()
					header_lower = header_value.lower()
					logger.info("  Sprawdzanie: czy [%s]='%s' zawiera '%s'?", field, header_lower[:50], value)
					if value in header_lower:
						labels_to_apply.update(filter_rule['labels'])
						never_spam = never_spam or filter_rule['never_spam']
						logger.info("  ✓ DOPASOWANO! Dodaję etykiety: %s, never_spam: %s", filter_rule['labels'], filter_rule['never_spam'])
					else:
						logger.info("  ✗ Nie pasuje")
			except re.error as e:
				logger.error("  ✗ Błąd w regex '%s': %s", pattern, e)
		
		if labels_to_apply or never_spam:
			logger.info("Wynik sprawdzania: etykiety=%s, never_spam=%s", list(labels_to_apply), never_spam)
		else:
			logger.info("Żaden filtr nie pasuje do tej wiadomości")
		
		return (list(labels_to_apply), never_spam)
	except Exception:
		logger.exception("Błąd podczas sprawdzania filtrów")
		return ([], False)


def apply_gmail_labels(gmail_server: IMAP4_SSL, message_id: str, labels: List[str],
                       remove_from_spam: bool = False, gmail_folder: str = "INBOX") -> bool:
	"""Znajduje wiadomość po Message-ID i aplikuje etykiety Gmail przez X-GM-LABELS."""
	if not message_id:
		logger.warning("Brak Message-ID, nie można zastosować etykiet")
		return False

	try:
		# Ustal kolejność folderów do przeszukania: najpierw skonfigurowany folder docelowy
		folders_to_try = [gmail_folder]
		if gmail_folder != "[Gmail]/All Mail":
			folders_to_try.append("[Gmail]/All Mail")

		# Gmail potrzebuje chwili po APPEND zanim wiadomość będzie widoczna przez SEARCH
		uid = None
		for attempt in range(5):
			if attempt > 0:
				time.sleep(1)

			for folder in folders_to_try:
				try:
					gmail_server.select(folder)
					resp, data = gmail_server.uid('SEARCH', None, f'HEADER Message-ID "{message_id}"')
					if resp == "OK" and data[0]:
						uid = data[0].split()[-1]  # ostatni UID (najnowszy)
						break
				except Exception:
					pass

			if uid:
				break
		
		if not uid:
			logger.warning("❌ Nie znaleziono wiadomości na Gmail (Message-ID: %s)", message_id)
			return False
		
		logger.info("✓ Znaleziono wiadomość na Gmail (UID: %s, Message-ID: %s)", uid, message_id)
		
		# Dodaj etykiety
		if labels:
			labels_str = ' '.join([f'"{label}"' for label in labels])
			logger.info("Aplikowanie etykiet: %s", labels)
			logger.debug("  Komenda: UID STORE %s +X-GM-LABELS (%s)", uid, labels_str)
			resp, data = gmail_server.uid('STORE', uid, '+X-GM-LABELS', f'({labels_str})')
			logger.debug("  Odpowiedź: %s, data: %s", resp, data)
			if resp == "OK":
				logger.info("✓ Dodano etykiety %s do wiadomości", labels)
			else:
				logger.warning("❌ Nie udało się dodać etykiet: %s", resp)
		
		# Usuń ze SPAM jeśli trzeba
		if remove_from_spam:
			logger.info("Usuwanie wiadomości z SPAM...")
			resp, data = gmail_server.uid('STORE', uid, '-X-GM-LABELS', '("\\\\Spam")')
			logger.debug("  Odpowiedź: %s, data: %s", resp, data)
			if resp == "OK":
				logger.info("✓ Usunięto wiadomość z SPAM")
			else:
				logger.debug("Nie udało się usunąć z SPAM (prawdopodobnie nie była w SPAM): %s", resp)
		
		return True
	except Exception:
		logger.exception("Błąd podczas aplikowania etykiet")
		return False


def append_to_gmail(raw_message: bytes, gmail_server: IMAP4_SSL, gmail_folder: str = "INBOX", 
                    mark_as_seen: bool = False) -> tuple[bool, str]:
	"""Kopiuje wiadomość na Gmail przez IMAP APPEND z zachowaniem oryginalnej daty.
	
	Zwraca tuple: (sukces, message_id)
	"""
	try:
		msg = BytesParser(policy=policy.default).parsebytes(raw_message)
		message_id = msg.get("Message-ID", "").strip('<>')
		
		date_str = msg.get("Date", "")
		internal_date = None
		if date_str:
			try:
				dt = parsedate_to_datetime(date_str)
				internal_date = imaplib.Time2Internaldate(dt.timestamp())
			except Exception:
				logger.debug("Nie udało się sparsować daty '%s', użyję bieżącego czasu", date_str)

		# Flagi - domyślnie NIE oznaczaj jako przeczytane (większa szansa że Gmail zauważy)
		flags = "(\\Seen)" if mark_as_seen else None
		
		resp, _ = gmail_server.append(gmail_folder, flags, internal_date, raw_message)
		if resp == "OK":
			logger.debug("Wiadomość skopiowana na Gmail (%s)", gmail_folder)
			return (True, message_id)
		logger.warning("Gmail APPEND zwróciło: %s", resp)
		return (False, message_id)
	except Exception:
		logger.exception("Błąd podczas kopiowania wiadomości na Gmail")
		return (False, "")


# ---------------------------------------------------------------------------
# Konfiguracja
# ---------------------------------------------------------------------------

def load_accounts(config_path: str) -> List[dict]:
	"""Wczytuje konfigurację INI. Każda sekcja (poza [defaults]) to jedno konto.

	Wymagane pola konta: host, user, gmail_user
	Opcjonalne: password, port, ssl, limit, folder, gmail_folder
	"""
	if not os.path.exists(config_path):
		logger.error("Plik konfiguracyjny nie istnieje: %s", config_path)
		return []

	cfg = configparser.ConfigParser()
	cfg.read(config_path, encoding="utf-8")
	defaults = dict(cfg["defaults"]) if "defaults" in cfg else {}

	def getbool(sec: configparser.SectionProxy, key: str, fallback: bool) -> bool:
		raw = sec.get(key, fallback=defaults.get(key))
		if raw is None:
			return fallback
		if isinstance(raw, bool):
			return raw
		return raw.strip().lower() in ("1", "true", "yes", "on")

	accounts: List[dict] = []
	for section in cfg.sections():
		if section.lower() == "defaults":
			continue
		sec = cfg[section]
		host = sec.get("host", fallback=defaults.get("host"))
		user = sec.get("user", fallback=defaults.get("user"))
		gmail_user = sec.get("gmail_user", fallback=defaults.get("gmail_user"))
		if not host or not user:
			logger.warning("Pominięto sekcję %s — brak host/user", section)
			continue
		if not gmail_user:
			logger.warning("Pominięto sekcję %s — brak gmail_user", section)
			continue
		filters_str = sec.get("filters", fallback=defaults.get("filters", ""))
		mark_source_as_read = getbool(sec, "mark_source_as_read", fallback=False)
		trash_folder = sec.get("trash_folder", fallback=defaults.get("trash_folder", "Trash"))
		
		accounts.append({
			"name": section,
			"host": host,
			"user": user,

			"port": sec.getint("port", fallback=None),
			"ssl": getbool(sec, "ssl", fallback=True),
			"limit": sec.getint("limit", fallback=10),
			"gmail_user": gmail_user,
			"gmail_folder": sec.get("gmail_folder", fallback=defaults.get("gmail_folder", "INBOX")),
			"trash_folder": trash_folder,
			"filters": filters_str,
			"mark_source_as_read": mark_source_as_read,
		})
	return accounts


# ---------------------------------------------------------------------------
# Keyring — bezpieczne przechowywanie haseł
# ---------------------------------------------------------------------------

def _kr_source_key(account_name: str, user: str, host: str) -> str:
	return f"imap:{account_name}:{user}@{host}"


def _kr_gmail_key(account_name: str, gmail_user: str) -> str:
	return f"gmail:{account_name}:{gmail_user}"


def _kr_get(key: str) -> Optional[str]:
	if not keyring:
		return None
	try:
		return keyring.get_password(SERVICE_NAME, key)
	except Exception:
		return None


def _kr_set(key: str, pwd: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.set_password(SERVICE_NAME, key, pwd)
		return True
	except Exception:
		logger.exception("Nie udało się zapisać hasła w keyring (key=%s)", key)
		return False


def _kr_del(key: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.delete_password(SERVICE_NAME, key)
		return True
	except Exception:
		return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
	parser = argparse.ArgumentParser(description="IMAP-to-Gmail forwarder — kopiuje wiadomości przez IMAP APPEND")
	parser.add_argument("--config", default="config.ini", help="ścieżka do pliku konfiguracyjnego (INI)")
	parser.add_argument("--account", help="nazwa sekcji konta; jeśli pominięte — wszystkie konta")
	parser.add_argument("--limit", type=int, help="nadpisuje limit wiadomości dla podglądu")
	parser.add_argument("--store-password", action="store_true", help="zapisz hasło źródłowe IMAP w keyring")
	parser.add_argument("--forget-password", action="store_true", help="usuń hasło źródłowe z keyring")
	parser.add_argument("--store-gmail-password", action="store_true", help="zapisz hasło Gmail (App Password) w keyring")
	parser.add_argument("--forget-gmail-password", action="store_true", help="usuń hasło Gmail z keyring")
	parser.add_argument("--autoforward", action="store_true", help="skopiuj wiadomości na Gmail i przenieś oryginały do Trash")
	parser.add_argument("--folder", default="INBOX", help="folder źródłowy IMAP (domyślnie INBOX)")
	args = parser.parse_args()

	accounts = load_accounts(args.config)
	if not accounts:
		logger.error("Brak kont w konfiguracji.")
		return

	if args.account:
		accounts = [a for a in accounts if a["name"] == args.account]
		if not accounts:
			logger.error("Nie znaleziono konta: %s", args.account)
			return

	for acc in accounts:
		name = acc["name"]
		host, user = acc["host"], acc["user"]
		gmail_user = acc["gmail_user"]

		print(f"=== Konto: {name} — {user}@{host} → Gmail: {gmail_user}")
		sys.stdout.flush()

		# --- obsługa usuwania haseł z keyring ---
		if args.forget_password:
			if _kr_del(_kr_source_key(name, user, host)):
				logger.info("[%s] Usunięto hasło źródłowe z keyring.", name)
		if args.forget_gmail_password:
			if _kr_del(_kr_gmail_key(name, gmail_user)):
				logger.info("[%s] Usunięto hasło Gmail z keyring.", name)

		# --- hasło źródłowe: keyring → prompt ---
		password = _kr_get(_kr_source_key(name, user, host))
		if password:
			logger.info("[%s] Użyto hasła źródłowego z keyring.", name)
		else:
			try:
				password = getpass.getpass(prompt=f"Hasło IMAP dla {user} ({name}): ")
			except Exception:
				password = None

		# --- hasło Gmail: keyring → prompt ---
		gmail_password = _kr_get(_kr_gmail_key(name, gmail_user))
		if gmail_password:
			logger.info("[%s] Użyto hasła Gmail z keyring.", name)
		else:
			try:
				gmail_password = getpass.getpass(prompt=f"Gmail App Password dla {gmail_user} ({name}): ")
			except Exception:
				gmail_password = None

		source_server = None
		gmail_server = None
		try:
			source_server = connect_imap(host, user, password, port=acc["port"], use_ssl=acc["ssl"])

			if args.store_password and password:
				if _kr_set(_kr_source_key(name, user, host), password):
					logger.info("[%s] Hasło źródłowe zapisane w keyring.", name)

			if args.store_gmail_password and gmail_password:
				if _kr_set(_kr_gmail_key(name, gmail_user), gmail_password):
					logger.info("[%s] Hasło Gmail zapisane w keyring.", name)

			if args.autoforward:
				gmail_server = connect_gmail(gmail_user, gmail_password)
				_run_autoforward(source_server, gmail_server, acc, args.folder)
			else:
				_run_preview(source_server, acc, args.folder, args.limit)

		except imaplib.IMAP4.error as e:
			logger.error("[%s] Błąd IMAP: %s", name, e)
		except Exception:
			logger.exception("[%s] Nieoczekiwany błąd.", name)
		finally:
			for srv in (source_server, gmail_server):
				if srv:
					try:
						srv.close()
					except Exception:
						pass


def _run_autoforward(source: IMAP4, gmail: IMAP4_SSL, acc: dict, folder: str) -> None:
	name = acc["name"]
	gmail_folder = acc["gmail_folder"]
	filters = parse_filters_from_config(acc.get("filters", ""))
	mark_source_as_read = acc.get("mark_source_as_read", False)

	uid_list = get_uid_list(source, folder)
	logger.info("[%s] Wiadomości do skopiowania na Gmail: %d", name, len(uid_list))
	if filters:
		logger.info("[%s] Załadowano %d filtrów", name, len(filters))
	if mark_source_as_read:
		logger.info("[%s] Wiadomości będą oznaczane jako przeczytane na serwerze źródłowym", name)

	copied = 0
	failed = 0

	for uid in uid_list:
		try:
			logger.info("[%s] Przetwarzanie wiadomości UID=%s", name, uid)

			raw = fetch_full_message(source, uid, folder)
			if not raw:
				logger.warning("[%s] Nie udało się pobrać wiadomości UID=%s", name, uid)
				failed += 1
				continue

			# Sprawdź filtry przed skopiowaniem
			labels, never_spam = check_message_against_filters(raw, filters)

			# Kopiuj na Gmail (zwraca tuple: sukces, message_id)
			success, message_id = append_to_gmail(raw, gmail, gmail_folder, mark_as_seen=False)

			if success:
				copied += 1
				logger.info("[%s] ✓ Wiadomość skopiowana na Gmail (Message-ID: %s)", name, message_id[:30] + "..." if len(message_id) > 30 else message_id)
				# Aplikuj etykiety jeśli są filtry
				if labels or never_spam:
					logger.info("[%s] Aplikowanie filtrów: etykiety=%s, never_spam=%s", name, labels, never_spam)
					apply_gmail_labels(gmail, message_id, labels, never_spam, gmail_folder=gmail_folder)
				else:
					logger.info("[%s] Brak etykiet do zastosowania", name)

				# Oznacz jako przeczytaną na serwerze źródłowym jeśli włączone
				if mark_source_as_read:
					if mark_as_read(source, uid, folder):
						logger.info("[%s] ✓ Wiadomość UID=%s oznaczona jako przeczytana", name, uid)
					else:
						logger.warning("[%s] ✗ Nie udało się oznaczyć wiadomości UID=%s jako przeczytanej", name, uid)

				if move_to_trash(source, uid, folder, acc.get("trash_folder", "Trash")):
					logger.info("[%s] ✓ Wiadomość UID=%s przeniesiona do %s", name, uid, acc.get("trash_folder", "Trash"))
				else:
					logger.warning("[%s] ✗ Nie udało się przenieść wiadomości UID=%s do %s", name, uid, acc.get("trash_folder", "Trash"))
			else:
				failed += 1
				logger.warning("[%s] ✗ Nie udało się skopiować wiadomości UID=%s na Gmail", name, uid)
		except Exception:
			failed += 1
			logger.exception("[%s] Błąd przy przetwarzaniu wiadomości UID=%s", name, uid)

	logger.info("[%s] Zakończono: skopiowano %d, błędy %d (łącznie %d)", name, copied, failed, len(uid_list))


def _run_preview(server: IMAP4, acc: dict, folder: str, limit_override: Optional[int]) -> None:
	name = acc["name"]
	uid_list = get_uid_list(server, folder)
	total = len(uid_list)
	limit = limit_override if limit_override is not None else acc["limit"]
	logger.info("[%s] Znaleziono %d wiadomości w folderze %s", name, total, folder)

	for idx, uid in enumerate(uid_list[:limit], start=1):
		info = fetch_message_info(server, uid, folder)
		print(f"--- [{idx}/{min(limit, total)}] UID:{uid} ---")
		print(f"Temat: {info['subject']}")
		print(f"Od:    {info['from']}")
		print(f"Data:  {info['date']}")
		if info["preview"]:
			print("Podgląd:")
			for line in info["preview"].splitlines()[:10]:
				print(line)
		print()


if __name__ == "__main__":
	main()
