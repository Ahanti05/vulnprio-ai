"""Small HTTP helper with retries and a polite User-Agent."""
from __future__ import annotations

import time

import requests

from ..config import USER_AGENT

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})


def get_json(url: str, params: dict | None = None, headers: dict | None = None,
             retries: int = 5, timeout: int = 60) -> dict:
    """GET a JSON document, retrying on rate limits and server errors."""
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            resp = _session.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code in (403, 429, 500, 502, 503, 504):
                raise requests.HTTPError(f"HTTP {resp.status_code}", response=resp)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_error = exc
            time.sleep(min(60, 6 * (attempt + 1)))
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_error}")
