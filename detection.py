"""Pure text detection and OCR helper."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

from PIL import Image
import pytesseract

URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>()]+")


def normalize(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def matched_term(text: str, terms: list[str]) -> str | None:
    content = normalize(text)
    for item in terms:
        term = normalize(str(item).strip())
        if term and re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", content):
            return str(item)
    return None


def matched_domain(text: str, domains: list[str]) -> str | None:
    configured = {str(domain).strip().lower().strip(".").encode("idna").decode("ascii")
                  for domain in domains if str(domain).strip()}
    for found in URL_RE.findall(text):
        try:
            url = found.rstrip(".,!?;:]")
            if url.lower().startswith("www."):
                url = "https://" + url
            hostname = (urlsplit(url).hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
            for domain in configured:
                if hostname == domain or hostname.endswith("." + domain):
                    return domain
        except (UnicodeError, ValueError):
            continue
    return None


def check_text(text: str, scam_keywords: list[str], scam_domains: list[str],
               bad_words: list[str]) -> str | None:
    if match := matched_term(text, scam_keywords):
        return f"scam phrase: {match}"
    if match := matched_domain(text, scam_domains):
        return f"scam domain: {match}"
    if match := matched_term(text, bad_words):
        return f"prohibited word: {match}"
    return None


def read_image_text(image: Image.Image) -> str:
    return pytesseract.image_to_string(image)
