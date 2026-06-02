from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request


_CACHE: dict[str, str] = {}


def lookup_vendor(mac: str, timeout: float = 2.0) -> str:
    normalized = mac.strip().lower().replace("-", ":")
    if not normalized:
        return ""

    if normalized in _CACHE:
        return _CACHE[normalized]

    url = "https://api.macvendors.com/" + urllib.parse.quote(normalized)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            vendor = response.read(160).decode("utf-8", errors="replace").strip()
    except (OSError, urllib.error.URLError, urllib.error.HTTPError):
        vendor = ""

    _CACHE[normalized] = vendor
    return vendor
