"""
discovery.py — Attack surface discovery via crawling.

Tries external tools first (gospider, hakrawler), then falls back to
a lightweight built-in Python spider using requests + BeautifulSoup.
"""

import subprocess
import re
import logging
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from typing import List, Set

logger = logging.getLogger(__name__)


def discover_endpoints(base_url: str, max_depth: int = 2, max_pages: int = 50) -> List[dict]:
    """
    Discover endpoints for the given base URL.
    Returns a list of {"url": ..., "method": ...} dicts.
    """
    logger.info(f"[Discovery] Starting for {base_url}")

    endpoints = _try_gospider(base_url)
    if not endpoints:
        endpoints = _try_hakrawler(base_url)
    if not endpoints:
        endpoints = _python_spider(base_url, max_depth=max_depth, max_pages=max_pages)

    # Always include the base URL itself
    base = {"url": base_url.rstrip("/"), "method": "GET"}
    if base not in endpoints:
        endpoints.insert(0, base)

    logger.info(f"[Discovery] Found {len(endpoints)} endpoints")
    return endpoints


def _try_gospider(base_url: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["gospider", "-s", base_url, "-d", "2", "-q"],
            capture_output=True, text=True, timeout=60
        )
        urls = _extract_urls(result.stdout, base_url)
        if urls:
            logger.info(f"[Discovery] gospider found {len(urls)} URLs")
            return [{"url": u, "method": "GET"} for u in urls]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def _try_hakrawler(base_url: str) -> List[dict]:
    try:
        result = subprocess.run(
            ["hakrawler", "-url", base_url, "-depth", "2"],
            capture_output=True, text=True, timeout=60
        )
        urls = _extract_urls(result.stdout, base_url)
        if urls:
            logger.info(f"[Discovery] hakrawler found {len(urls)} URLs")
            return [{"url": u, "method": "GET"} for u in urls]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def _python_spider(base_url: str, max_depth: int = 2, max_pages: int = 50) -> List[dict]:
    """Simple BFS crawler using requests + regex link extraction."""
    logger.info("[Discovery] Using built-in Python spider")
    visited: Set[str] = set()
    queue = deque([(base_url, 0)])
    found: List[dict] = []
    base_domain = urlparse(base_url).netloc
    headers = {"User-Agent": "ScanX-Crawler/1.0"}

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
            found.append({"url": url, "method": "GET"})
            if depth < max_depth and "text/html" in resp.headers.get("content-type", ""):
                for link in _parse_links(resp.text, url):
                    if urlparse(link).netloc == base_domain and link not in visited:
                        queue.append((link, depth + 1))
        except Exception:
            pass

    return found


def _parse_links(html: str, base_url: str) -> List[str]:
    links = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', html):
        try:
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.scheme in ("http", "https"):
                links.append(full.split("#")[0])
        except Exception:
            pass
    return list(set(links))


def _extract_urls(text: str, base_url: str) -> List[str]:
    base_domain = urlparse(base_url).netloc
    urls = re.findall(r'https?://[^\s"\'<>]+', text)
    return list({u for u in urls if urlparse(u).netloc == base_domain})
