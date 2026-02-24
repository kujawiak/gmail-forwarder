"""GMail Forwarder - prosty moduł IMAP do podglądu i forwardowania wiadomości.

Funkcjonalność w tym pliku:
- połączenie z serwerem IMAP
- wylistowanie dostępnych wiadomości z folderu
- podgląd nagłówków i krótkiego fragmentu treści
- automatyczne forwardowanie nowych wiadomości na Gmail
- przenoszenie forwarded wiadomości do Trash

Uruchom: python gmfw.py --config config.ini --account kuj4 --autoforward
"""

# OBSOLETE

from __future__ import annotations

import argparse
import configparser
import getpass
import logging
import os
import imaplib
from imaplib import IMAP4, IMAP4_SSL
from email import policy
from email.parser import BytesParser
from typing import List, Optional
import smtplib


from email.message import EmailMessage

logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("gmfw")


# ---------------------------------------------------------------------------
# Keyring — bezpieczne przechowywanie haseł
# ---------------------------------------------------------------------------

def _kr_imap_key(account_name: str, user: str, host: str) -> str:
	return f"imap:{account_name}:{user}@{host}"


def get_stored_password(account_name: str, user: str, host: str) -> Optional[str]:
	if not keyring:
		return None
	try:
		return keyring.get_password(SERVICE_NAME, _kr_imap_key(account_name, user, host))
	except Exception:
		return None


def set_stored_password(account_name: str, user: str, host: str, password: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.set_password(SERVICE_NAME, _kr_imap_key(account_name, user, host), password)
		return True
	except Exception:
		logger.exception("Nie udało się zapisać hasła dla %s", account_name)
		return False


def delete_stored_password(account_name: str, user: str, host: str) -> bool:
	if not keyring:
		return False
	try:
		keyring.delete_password(SERVICE_NAME, _kr_imap_key(account_name, user, host))
		return True
	except Exception:
		return False


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

def connect_imap(host: str, user: str, password: str, port: int | None = None, use_ssl: bool = True, timeout: int = 10) -> IMAP4:
	"""Nawiązuje połączenie z serwerem IMAP i loguje użytkownika.

	Zwraca obiekt `imaplib.IMAP4` (lub `IMAP4_SSL`).
	"""
	logger.info("Łączenie z %s (ssl=%s, port=%s)", host, use_ssl, port)
	if use_ssl:
		port = port or 993
		server = IMAP4_SSL(host, port, timeout=timeout)
	else:
		port = port or 143
		server = IMAP4(host, port, timeout=timeout)

	server.login(user, password)
	logger.info("Zalogowano jako %s", user)
	return server


def fetch_headers_and_preview_imap(server: IMAP4, msg_uid: int, folder: str = "INBOX") -> dict:
	"""Pobiera nagłówki i krótki fragment treści wiadomości z IMAP.

	Zwraca słownik z kluczami: `subject`, `from`, `date`, `preview`.
	Fetch RFC822 i parsuje pełny komunikat — najprostsze i najbardziej niezawodne.
	"""
	try:
		raw = fetch_full_message(server, msg_uid, folder)
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
		logger.exception("Błąd podczas pobierania wiadomości %s", msg_uid)
		return {"subject": "(błąd)", "from": "", "date": "", "preview": ""}


def load_accounts(config_path: str) -> List[dict]:
	"""Wczytuje konfigurację INI z wieloma sekcjami-kontami.

	Sekcja `defaults` (opcjonalna) może dostarczyć wartości domyślne.
	Każda sekcja konta powinna zawierać `host` i `user`.
	Dopuszczalne opcje na poziomie konta: password, port, ssl (true/false), limit
	"""
	if not os.path.exists(config_path):
		logger.error("Plik konfiguracyjny nie istnieje: %s", config_path)
		return []

	cfg = configparser.ConfigParser()
	cfg.read(config_path, encoding="utf-8")

	# Pobierz mapę wartości domyślnych (SectionProxy -> dict) jeśli istnieje
	defaults = dict(cfg["defaults"]) if "defaults" in cfg else {}

	accounts: List[dict] = []
	for section in cfg.sections():
		if section.lower() == "defaults":
			continue
		sec = cfg[section]
		host = sec.get("host", fallback=defaults.get("host"))
		user = sec.get("user", fallback=defaults.get("user"))
		if not host or not user:
			logger.warning("Pominięto sekcję %s — brak host/user", section)
			continue

		port = sec.getint("port", fallback=None)
		ssl = sec.getboolean("ssl", fallback=True)
		limit = sec.getint("limit", fallback=10)
		forward_to = sec.get("forward_to", fallback=defaults.get("forward_to", None))
		smtp_host = sec.get("smtp_host", fallback=defaults.get("smtp_host", None))
		smtp_port = sec.getint("smtp_port", fallback=None)
		_smtp_ssl_raw = sec.get("smtp_ssl", fallback=defaults.get("smtp_ssl", None))
		smtp_ssl = _smtp_ssl_raw.strip().lower() in ("1", "true", "yes", "on") if isinstance(_smtp_ssl_raw, str) else bool(_smtp_ssl_raw) if _smtp_ssl_raw is not None else True

		accounts.append({
			"name": section,
			"host": host,
			"user": user,
			"port": port,
			"ssl": ssl,
			"limit": limit,
			"forward_to": forward_to,
			"smtp_host": smtp_host or host,  # domyślnie = serwer macierzysty
			"smtp_port": smtp_port,
			"smtp_ssl": smtp_ssl,
		})

	return accounts


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
		uids = data[0].split() if data[0] else []
		return [int(uid) for uid in uids]
	except Exception:
		return []


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


def forward_message(raw_message: bytes, forward_to: str, smtp_host: str, smtp_port: Optional[int], smtp_user: str, smtp_password: str, smtp_ssl: bool = True, subject_tag: str = "") -> bool:
	"""Wysyła wiadomość na adres forward_to jako zwykły forward (bez attachment)."""
	try:
		parser = BytesParser(policy=policy.default)
		try:
			orig = parser.parsebytes(raw_message)
		except Exception:
			orig = None

		if orig is None:
			logger.warning("Nie udało się sparsować oryginalnej wiadomości")
			return False

		# Pobierz metadane z oryginału
		orig_subj = orig.get("Subject", "(brak tematu)")
		orig_from = orig.get("From", "unknown@example.com")
		orig_date = orig.get("Date", "")
		orig_to = orig.get("To", "")
		orig_cc = orig.get("Cc", "")

		# Skomponuj nową wiadomość
		em = EmailMessage()
		prefix = f"[{subject_tag}] " if subject_tag else ""
		em["Subject"] = f"{prefix}Fwd: {orig_subj}"
		em["To"] = forward_to
		em["From"] = smtp_user

		# Zbuduj nagłówek forwarda (wspólny dla plain i HTML)
		header_plain = (
			"---------- Forwarded message ---------\n"
			f"From: {orig_from}\n"
			f"Date: {orig_date}\n"
			f"Subject: {orig_subj}\n"
			f"To: {orig_to}\n"
		)
		if orig_cc:
			header_plain += f"Cc: {orig_cc}\n"
		header_plain += "\n"

		header_html = (
			"<div style='border-left:2px solid #ccc;padding-left:8px;color:#555;margin-bottom:8px'>"
			f"<b>---------- Forwarded message ---------</b><br>"
			f"<b>From:</b> {orig_from}<br>"
			f"<b>Date:</b> {orig_date}<br>"
			f"<b>Subject:</b> {orig_subj}<br>"
			f"<b>To:</b> {orig_to}<br>"
		)
		if orig_cc:
			header_html += f"<b>Cc:</b> {orig_cc}<br>"
		header_html += "</div>"

		# Wyciągnij plain i HTML z oryginału
		body_plain = ""
		body_html = ""
		if orig.is_multipart():
			for part in orig.walk():
				ct = part.get_content_type()
				if ct == "text/plain" and not body_plain:
					try:
						body_plain = part.get_content()
					except Exception:
						pass
				elif ct == "text/html" and not body_html:
					try:
						body_html = part.get_content()
					except Exception:
						pass
		else:
			ct = orig.get_content_type()
			try:
				if ct == "text/html":
					body_html = orig.get_content()
				else:
					body_plain = orig.get_content()
			except Exception:
				pass

		em.set_content(header_plain + body_plain)
		if body_html:
			em.add_alternative(header_html + body_html, subtype="html")

		# Wyślij SMTP
		port_eff = smtp_port or (465 if smtp_ssl else 587)
		if smtp_ssl:
			server = smtplib.SMTP_SSL(smtp_host, port_eff, timeout=30)
		else:
			server = smtplib.SMTP(smtp_host, port_eff, timeout=30)
			server.ehlo()
			try:
				server.starttls()
				server.ehlo()
			except Exception:
				pass

		try:
			if smtp_user and smtp_password:
				server.login(smtp_user, smtp_password)
			server.send_message(em)
			logger.debug("Wiadomość wysłana na %s przez %s:%s", forward_to, smtp_host, port_eff)
			return True
		finally:
			try:
				server.quit()
			except Exception:
				try:
					server.close()
				except Exception:
					pass
	except Exception:
		logger.exception("Błąd podczas wysyłania wiadomości na %s", forward_to)
		return False


def main() -> None:
	parser = argparse.ArgumentParser(description="IMAP forwarder — przekazuje nowe wiadomości na Gmail przez SMTP serwera macierzystego")
	parser.add_argument("--config", default="config.ini", help="ścieżka do pliku konfiguracyjnego (INI)")
	parser.add_argument("--account", help="nazwa sekcji konta; jeśli pominięte — wszystkie konta")
	parser.add_argument("--limit", type=int, help="nadpisuje limit wiadomości dla podglądu")
	parser.add_argument("--store-password", action="store_true", help="zapisz hasło IMAP w keyring")
	parser.add_argument("--forget-password", action="store_true", help="usuń hasło z keyring")
	parser.add_argument("--autoforward", action="store_true", help="przekaż nowe wiadomości na forward_to i przenieś do Trash")
	parser.add_argument("--folder", default="INBOX", help="folder IMAP (domyślnie INBOX)")
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

		print(f"=== Konto: {name} — {user}@{host}")

		# --- obsługa usuwania hasła z keyring ---
		if args.forget_password:
			if delete_stored_password(name, user, host):
				logger.info("[%s] Usunięto hasło z keyring.", name)

		# --- hasło: keyring → prompt ---
		password = get_stored_password(name, user, host)
		if password:
			logger.info("[%s] Użyto hasła z keyring.", name)
		else:
			try:
				password = getpass.getpass(prompt=f"Hasło dla {user} ({name}): ")
			except Exception:
				password = None

		server = None
		try:
			server = connect_imap(host, user, password, port=acc["port"], use_ssl=acc["ssl"])

			if args.store_password and password:
				if set_stored_password(name, user, host, password):
					logger.info("[%s] Hasło zapisane w keyring.", name)

			if args.autoforward and acc.get("forward_to"):
				_run_autoforward(server, acc, args.folder, password)
			else:
				_run_preview(server, acc, args.folder, args.limit)

		except imaplib.IMAP4.error as e:
			logger.error("[%s] Błąd IMAP: %s", name, e)
		except Exception:
			logger.exception("[%s] Nieoczekiwany błąd.", name)
		finally:
			if server:
				try:
					server.close()
				except Exception:
					pass


def _run_autoforward(server: IMAP4, acc: dict, folder: str, password: Optional[str]) -> None:
	name = acc["name"]
	uid_list = get_uid_list(server, folder)
	logger.info("[%s] Wiadomości do przekazania: %d", name, len(uid_list))

	# dane SMTP — niezmienne dla wszystkich wiadomości, wyciągamy raz przed pętlą
	forward_to = acc["forward_to"]
	smtp_host = acc["smtp_host"]
	smtp_port = acc["smtp_port"]
	smtp_ssl = acc["smtp_ssl"]
	smtp_user = acc["user"]
	smtp_password = password or ""

	for uid in uid_list:
		try:
			raw = fetch_full_message(server, uid, folder)
			if not raw:
				logger.warning("[%s] Nie udało się pobrać wiadomości %s", name, uid)
				continue
			if forward_message(raw, forward_to, smtp_host, smtp_port, smtp_user, smtp_password, smtp_ssl, subject_tag=smtp_user):
				if move_to_trash(server, uid, folder):
					logger.info("[%s] Wiadomość %s przesłana i przeniesiona do Trash.", name, uid)
				else:
					logger.warning("[%s] Wiadomość %s przesłana, ale przeniesienie do Trash nie powiodło się.", name, uid)
			else:
				logger.warning("[%s] Nie udało się wysłać wiadomości %s.", name, uid)
		except Exception:
			logger.exception("[%s] Błąd przy przekazywaniu wiadomości %s", name, uid)


def _run_preview(server: IMAP4, acc: dict, folder: str, limit_override: Optional[int]) -> None:
	name = acc["name"]
	uid_list = get_uid_list(server, folder)
	total = len(uid_list)
	limit = limit_override if limit_override is not None else acc["limit"]
	logger.info("[%s] Znaleziono %d wiadomości w folderze %s", name, total, folder)

	for idx, uid in enumerate(uid_list[:limit], start=1):
		info = fetch_headers_and_preview_imap(server, uid, folder)
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

