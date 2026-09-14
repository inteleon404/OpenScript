#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures
import logging
import os
import re
import sys
import threading
from urllib.parse import urljoin, urlparse, urlunparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ReconUtility")

JS_PATTERNS = [
    re.compile(r"""(?P<quote>["'`])(?P<url>(?:https?://|//)[^"'#\s]+)(?P=quote)""", re.VERBOSE),
    re.compile(r"""(?P<quote>["'`])(?P<url>(?:/|\./|\.\./)[^"'#\s<>]+)(?P=quote)""", re.VERBOSE),
    re.compile(r"""(?P<quote>["'`])(?P<url>[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|jsp|json|action|html|txt|xml|js)(?:\?[^"'#\s]*)?)(?P=quote)""", re.VERBOSE),
    re.compile(r"""(?P<quote>["'`])(?P<url>[a-zA-Z0-9_\-]+\.(?:php|asp|aspx|jsp|json|action|html|txt|xml|js)(?:\?[^"'#\s]*)?)(?P=quote)""", re.VERBOSE)
]

STATIC_ASSETS_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mp3", ".wav",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf", ".doc", ".docx"
}

UNSUPPORTED_SCHEMES = {
    "javascript", "data", "mailto", "tel", "blob", "ftp", "file", "ws", "wss"
}

MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB

thread_local = threading.local()


def create_session(cookie: str | None, headers: dict | None, insecure: bool) -> requests.Session:
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    if cookie:
        default_headers["Cookie"] = cookie
    if headers:
        default_headers.update(headers)
    session.headers.update(default_headers)
    if insecure:
        session.verify = False
    return session


def get_session(cookie: str | None, headers: dict | None, insecure: bool) -> requests.Session:
    if not hasattr(thread_local, "session"):
        thread_local.session = create_session(cookie, headers, insecure)
    return thread_local.session


class ScopeManager:
    def __init__(self, scopes: list[str], initial_urls: list[str]):
        self.scopes = set()
        for s in scopes:
            clean = s.strip().lower().lstrip("*.")
            if clean:
                self.scopes.add(clean)
        
        if not self.scopes:
            for u in initial_urls:
                try:
                    parsed = urlparse(u)
                    if parsed.hostname:
                        self.scopes.add(parsed.hostname.lower())
                except Exception:
                    pass

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False
            hostname = hostname.lower()
            for scope in self.scopes:
                if hostname == scope or hostname.endswith("." + scope):
                    return True
            return False
        except Exception:
            return False


class TargetNormalizer:
    def __init__(self, scope_manager: ScopeManager):
        self.scope_manager = scope_manager

    def normalize(self, base_url: str, raw_url: str) -> str | None:
        if not raw_url:
            return None
        raw_url = raw_url.strip()
        for char in ['"', "'", '`', '>', '<', ' ']:
            raw_url = raw_url.rstrip(char)

        if any(raw_url.lower().startswith(f"{scheme}:") for scheme in UNSUPPORTED_SCHEMES):
            return None

        try:
            full_url = urljoin(base_url, raw_url)
            parsed = urlparse(full_url)
            if parsed.scheme.lower() not in ("http", "https"):
                return None

            normalized = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                ""
            ))
            return normalized
        except Exception:
            return None


def is_static_asset(url: str) -> bool:
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    return any(path_lower.endswith(ext) for ext in STATIC_ASSETS_EXTENSIONS)


class JavaScriptAnalyzer:
    @staticmethod
    def extract_endpoints(js_content: str, source_url: str, normalizer: TargetNormalizer, scope_manager: ScopeManager) -> set[str]:
        found = set()
        for pattern in JS_PATTERNS:
            for match in pattern.finditer(js_content):
                endpoint = match.group("url")
                if endpoint:
                    normalized = normalizer.normalize(source_url, endpoint)
                    if normalized and scope_manager.is_in_scope(normalized):
                        found.add(normalized)
        return found


class HTMLAnalyzer:
    @staticmethod
    def analyze(html_text: str) -> tuple[list[str], list[str], list[str]]:
        soup = BeautifulSoup(html_text, "html.parser")
        scripts = []
        inline_scripts = []
        endpoints = []

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                scripts.append(src)
            else:
                text = script.get_text()
                if text:
                    inline_scripts.append(text)

        for tag, attr in [("a", "href"), ("form", "action"), ("iframe", "src"), ("frame", "src")]:
            for element in soup.find_all(tag):
                val = element.get(attr)
                if val:
                    endpoints.append(val)

        for link in soup.find_all("link", href=True):
            rel = link.get("rel", [])
            if isinstance(rel, str):
                rel = [rel]
            rel_str = " ".join(rel).lower()
            if any(r in rel_str for r in ["canonical", "alternate", "author", "help", "search", "next", "prev"]):
                endpoints.append(link["href"])

        return scripts, inline_scripts, endpoints


class ReconEngine:
    def __init__(
        self,
        urls: list[str],
        scopes: list[str],
        cookie: str = None,
        headers: dict = None,
        timeout: int = 10,
        insecure: bool = False,
        threads: int = 10,
        depth: int = 1,
        js_only: bool = False,
        deep: bool = False,
        quiet: bool = False
    ):
        self.initial_urls = [u.strip() for u in urls if u.strip()]
        self.cookie = cookie
        self.custom_headers = headers or {}
        self.timeout = timeout
        self.insecure = insecure
        self.threads = threads
        self.depth = depth if (deep or depth > 1) else (2 if deep else 1)
        self.js_only = js_only
        self.quiet = quiet

        self.scope_manager = ScopeManager(scopes, self.initial_urls)
        self.normalizer = TargetNormalizer(self.scope_manager)

        if self.quiet:
            logger.setLevel(logging.WARNING)

        self.lock = threading.Lock()
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.discovered_js = set()

    def fetch_url(self, url: str) -> tuple[str | None, str | None, str]:
        session = get_session(self.cookie, self.custom_headers, self.insecure)
        try:
            with session.get(url, timeout=self.timeout, allow_redirects=True, stream=True) as response:
                final_url = response.url
                content_type = response.headers.get("Content-Type", "")
                
                if response.status_code >= 400:
                    return None, None, final_url

                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                    return None, None, final_url

                chunks = []
                downloaded = 0
                for chunk in response.iter_content(chunk_size=8192):
                    downloaded += len(chunk)
                    if downloaded > MAX_RESPONSE_SIZE:
                        break
                    chunks.append(chunk)
                raw_content = b"".join(chunks)

                encoding = response.encoding or "utf-8"
                try:
                    text = raw_content.decode(encoding, errors="ignore")
                except Exception:
                    text = raw_content.decode("utf-8", errors="ignore")

                return text, content_type, final_url
        except requests.exceptions.RequestException:
            return None, None, url

    def process_target(self, url: str) -> tuple[set[str], set[str], set[str]]:
        local_endpoints = set()
        local_js = set()
        next_crawl_targets = set()

        with self.lock:
            if url in self.visited_urls:
                return local_endpoints, local_js, next_crawl_targets
            self.visited_urls.add(url)

        text, content_type, final_url = self.fetch_url(url)
        if not text:
            return local_endpoints, local_js, next_crawl_targets

        with self.lock:
            if self.scope_manager.is_in_scope(final_url):
                local_endpoints.add(final_url)

        if self.js_only or "javascript" in content_type.lower() or final_url.endswith(".js") or url.endswith(".js"):
            with self.lock:
                local_js.add(final_url)
            extracted = JavaScriptAnalyzer.extract_endpoints(text, final_url, self.normalizer, self.scope_manager)
            local_endpoints.update(extracted)
            return local_endpoints, local_js, next_crawl_targets

        scripts, inline_scripts, raw_endpoints = HTMLAnalyzer.analyze(text)

        for src in scripts:
            js_url = self.normalizer.normalize(final_url, src)
            if js_url and self.scope_manager.is_in_scope(js_url):
                with self.lock:
                    local_js.add(js_url)
                next_crawl_targets.add(js_url)

        for raw_ep in raw_endpoints:
            norm = self.normalizer.normalize(final_url, raw_ep)
            if norm and self.scope_manager.is_in_scope(norm):
                local_endpoints.add(norm)
                if not is_static_asset(norm):
                    next_crawl_targets.add(norm)

        for inline_js in inline_scripts:
            extracted = JavaScriptAnalyzer.extract_endpoints(inline_js, final_url, self.normalizer, self.scope_manager)
            local_endpoints.update(extracted)

        return local_endpoints, local_js, next_crawl_targets

    def run(self) -> tuple[list[str], list[str]]:
        current_level_urls = set(self.initial_urls)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for current_depth in range(self.depth):
                if not current_level_urls:
                    break

                futures = {
                    executor.submit(self.process_target, url): url 
                    for url in current_level_urls 
                }
                
                next_level_urls = set()
                for future in concurrent.futures.as_completed(futures):
                    try:
                        eps, jss, next_targets = future.result()
                        with self.lock:
                            self.discovered_endpoints.update(eps)
                            self.discovered_js.update(jss)
                            if current_depth + 1 < self.depth:
                                for nt in next_targets:
                                    if nt not in self.visited_urls:
                                        next_level_urls.add(nt)
                    except Exception:
                        pass
                current_level_urls = next_level_urls

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            unvisited_js = [js for js in self.discovered_js if js not in self.visited_urls]
            if unvisited_js:
                futures = {executor.submit(self.process_target, js): js for js in unvisited_js}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        eps, jss, _ = future.result()
                        with self.lock:
                            self.discovered_endpoints.update(eps)
                            self.discovered_js.update(jss)
                    except Exception:
                        pass

        sorted_endpoints = sorted(list(self.discovered_endpoints))
        sorted_js = sorted(list(self.discovered_js))
        return sorted_endpoints, sorted_js


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Production-quality URL and JavaScript endpoint reconnaissance utility.",
        epilog="Example: python3 recon_utility.py -u https://example.com --scope example.com --deep"
    )
    parser.add_argument("-u", "--url", action="append", help="Target URL (can be specified multiple times)")
    parser.add_argument("-f", "--file", help="File containing target URLs or JS endpoints (one per line)")
    parser.add_argument("--js", action="store_true", help="Treat input targets strictly as JavaScript files")
    parser.add_argument("--deep", action="store_true", help="Enable deep crawling (shortcut for depth=2)")
    parser.add_argument("--depth", type=int, default=1, help="Crawling depth (default: 1)")
    parser.add_argument("--scope", action="append", help="Allowed domain scope (e.g. target.com, can be multiple)")
    parser.add_argument("-c", "--cookie", help="Cookie header value for authenticated requests")
    parser.add_argument("-o", "--output", help="Output file path for discovered endpoints")
    parser.add_argument("--output-js", help="Output file path for discovered JavaScript resources")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL/TLS certificate verification")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential log output")
    return parser.parse_args()


def load_urls_from_file(file_path: str) -> list[str]:
    urls = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
    return urls


def main():
    args = parse_arguments()

    targets = []
    if args.url:
        targets.extend(args.url)
    if args.file:
        targets.extend(load_urls_from_file(args.file))

    if not targets:
        logger.error("No valid targets provided via -u/--url or -f/--file.")
        sys.exit(1)

    valid_targets = []
    for t in targets:
        if not t.startswith("http://") and not t.startswith("https://"):
            t = "http://" + t
        parsed = urlparse(t)
        if parsed.netloc:
            valid_targets.append(t)
        else:
            logger.warning(f"Skipping malformed URL: {t}")

    if not valid_targets:
        logger.error("No valid URLs found after validation.")
        sys.exit(1)

    scopes = args.scope if args.scope else []

    if not args.quiet:
        print(f"\n[+] Target Count: {len(valid_targets)}")
        print(f"[+] Scopes Defined: {scopes if scopes else 'Auto-derived from targets'}")
        print(f"[+] Threads: {args.threads} | Depth: {args.depth} | JS-Only Mode: {args.js}\n")

    engine = ReconEngine(
        urls=valid_targets,
        scopes=scopes,
        cookie=args.cookie,
        timeout=args.timeout,
        insecure=args.insecure,
        threads=args.threads,
        depth=args.depth,
        js_only=args.js,
        deep=args.deep,
        quiet=args.quiet
    )

    endpoints, js_files = engine.run()

    if not args.quiet:
        print(f"\n[+] Discovered Endpoints ({len(endpoints)}):")
        for ep in endpoints:
            print(ep)

        print(f"\n[+] Discovered JavaScript Resources ({len(js_files)}):")
        for js in js_files:
            print(js)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(endpoints) + "\n")
            logger.info(f"Endpoints successfully written to {args.output}")
        except Exception as e:
            logger.error(f"Failed to write endpoints to output file: {e}")
            sys.exit(1)

    if args.output_js:
        try:
            with open(args.output_js, "w", encoding="utf-8") as f:
                f.write("\n".join(js_files) + "\n")
            logger.info(f"JavaScript URLs successfully written to {args.output_js}")
        except Exception as e:
            logger.error(f"Failed to write JavaScript URLs to output file: {e}")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
