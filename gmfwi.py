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


def move_to_trash(server: IMAP4, uid: int, source_folder: str = "INBOX", trash_folder: str = "Trash") -> bool:
	"""Przenosi wiadomość do folderu Trash (przez UID COPY + UID STORE + EXPUNGE)."""
	try:
		server.select(source_folder, readonly=False)
		resp, _ = server.uid("COPY", str(uid), trash_folder)
		if resp == "OK":
			resp, _ = server.uid("STORE", str(uid), "+FLAGS", "(\\Deleted)")
			if resp == "OK":
				server.expunge()
				logger.debug("Wiadomość UID=%s przeniesiona do %s", uid, trash_folder)
				return True
	except Exception as e:
		logger.debug("Błąd przenoszenia wiadomości UID=%s: %s", uid, e)
	return False


def fetch_message_info(server: IMAP4, uid: int, folder: str = "INBOX") -> dict:
	"""Pobiera nagłówki i krótki podgląd treści wiadomości."""
	try:
		raw = fetch_full_message(server, uid, folder)
		if not raw:
			return {"subject": "(błąd odczytu)", "from": "", "date": "", "preview": ""}
		msg = BytesParser(policy=policy.default).parsebytes(raw)
		preview = ""
		if msg.is_multipart():
			for part in msg.walk():
				if part.get_content_type() == "text/plain":
					try:
						preview = part.get_content().strip()[:1000]
					except Exception:
						pass
					break
		else:
			try:
				preview = msg.get_content().strip()[:1000]
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
	logger.info("Łączenie z Gmail IMAP (%s)", gmail_user)
	server = IMAP4_SSL(GMAIL_HOST, GMAIL_PORT, timeout=timeout)
	server.login(gmail_user, gmail_password)
	logger.info("Zalogowano do Gmail jako %s", gmail_user)
	return server


def append_to_gmail(raw_message: bytes, gmail_server: IMAP4_SSL, gmail_folder: str = "INBOX") -> bool:
	"""Kopiuje wiadomość na Gmail przez IMAP APPEND z zachowaniem oryginalnej daty."""
	try:
		msg = BytesParser(policy=policy.default).parsebytes(raw_message)
		date_str = msg.get("Date", "")
		internal_date = None
		if date_str:
			try:
				dt = parsedate_to_datetime(date_str)
				internal_date = imaplib.Time2Internaldate(dt.timestamp())
			except Exception:
				logger.debug("Nie udało się sparsować daty '%s', użyję bieżącego czasu", date_str)

		resp, _ = gmail_server.append(gmail_folder, None, internal_date, raw_message)
		if resp == "OK":
			logger.debug("Wiadomość skopiowana na Gmail (%s)", gmail_folder)
			return True
		logger.warning("Gmail APPEND zwróciło: %s", resp)
		return False
	except Exception:
		logger.exception("Błąd podczas kopiowania wiadomości na Gmail")
		return False


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
		accounts.append({
			"name": section,
			"host": host,
			"user": user,

			"port": sec.getint("port", fallback=None),
			"ssl": getbool(sec, "ssl", fallback=True),
			"limit": sec.getint("limit", fallback=10),
			"gmail_user": gmail_user,
			"gmail_folder": sec.get("gmail_folder", fallback=defaults.get("gmail_folder", "INBOX")),
		})
	return accounts


# ---------------------------------------------------------------------------
# Keyring — bezpieczne przechowywanie haseł
# ---------------------------------------------------------------------------

def _kr_source_key(account_name: str, user: str, host: str) -> str:
	return f"imap:{account_name}:{user}@{host}"


def _kr_gmail_key(account_name: str, gmail_user: str) -> str:
	return f"gmail:{account_name}:{gmail_user}"


def get_stored_password(account_name: str, user: str, host: str) -> Optional[str]:
	if not keyring:
		return None
	try:
		return keyring.get_password(SERVICE_NAME, _kr_source_key(account_name, user, host))
	except Exception:
		return None


def set_stored_password(account_name: str, user: str, host: str, password: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.set_password(SERVICE_NAME, _kr_source_key(account_name, user, host), password)
		return True
	except Exception:
		logger.exception("Nie udało się zapisać hasła źródłowego dla %s", account_name)
		return False


def delete_stored_password(account_name: str, user: str, host: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.delete_password(SERVICE_NAME, _kr_source_key(account_name, user, host))
		return True
	except Exception:
		return False


def get_stored_gmail_password(account_name: str, gmail_user: str) -> Optional[str]:
	if not keyring:
		return None
	try:
		return keyring.get_password(SERVICE_NAME, _kr_gmail_key(account_name, gmail_user))
	except Exception:
		return None


def set_stored_gmail_password(account_name: str, gmail_user: str, password: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.set_password(SERVICE_NAME, _kr_gmail_key(account_name, gmail_user), password)
		return True
	except Exception:
		logger.exception("Nie udało się zapisać hasła Gmail dla %s", account_name)
		return False


def delete_stored_gmail_password(account_name: str, gmail_user: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.delete_password(SERVICE_NAME, _kr_gmail_key(account_name, gmail_user))
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

		# --- obsługa usuwania haseł z keyring ---
		if args.forget_password:
			if delete_stored_password(name, user, host):
				logger.info("[%s] Usunięto hasło źródłowe z keyring.", name)
		if args.forget_gmail_password:
			if delete_stored_gmail_password(name, gmail_user):
				logger.info("[%s] Usunięto hasło Gmail z keyring.", name)

		# --- hasło źródłowe: keyring → prompt ---
		password = get_stored_password(name, user, host)
		if password:
			logger.info("[%s] Użyto hasła źródłowego z keyring.", name)
		else:
			try:
				password = getpass.getpass(prompt=f"Hasło IMAP dla {user} ({name}): ")
			except Exception:
				password = None

		# --- hasło Gmail: keyring → prompt ---
		gmail_password = get_stored_gmail_password(name, gmail_user)
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
				if set_stored_password(name, user, host, password):
					logger.info("[%s] Hasło źródłowe zapisane w keyring.", name)

			if args.store_gmail_password and gmail_password:
				if set_stored_gmail_password(name, gmail_user, gmail_password):
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

	uid_list = get_uid_list(source, folder)
	logger.info("[%s] Wiadomości do skopiowania na Gmail: %d", name, len(uid_list))

	for uid in uid_list:
		try:
			raw = fetch_full_message(source, uid, folder)
			if not raw:
				logger.warning("[%s] Nie udało się pobrać wiadomości UID=%s", name, uid)
				continue
			if append_to_gmail(raw, gmail, gmail_folder):
				if move_to_trash(source, uid, folder):
					logger.info("[%s] Wiadomość UID=%s skopiowana na Gmail i przeniesiona do Trash.", name, uid)
				else:
					logger.warning("[%s] Wiadomość UID=%s skopiowana na Gmail, ale przeniesienie do Trash nie powiodło się.", name, uid)
			else:
				logger.warning("[%s] Nie udało się skopiować wiadomości UID=%s na Gmail.", name, uid)
		except Exception:
			logger.exception("[%s] Błąd przy przetwarzaniu wiadomości UID=%s", name, uid)


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
