#!/usr/bin/env python3

import argparse
import concurrent.futures
import logging
import os
import re
import sys
import threading
import urllib.parse
import urllib3
from typing import List, Set, Tuple
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
logger = logging.getLogger("jsextract")

# Endpoints inside JS source: absolute (scheme://), protocol-relative (//)
# and relative (/path/...) URLs.
ENDPOINT_REGEX = re.compile(
    r'(?:"|\')('
    r'(?:[a-zA-Z]{1,10}://|//)'
    r'[^"\s\'`]{2,}'
    r'|'
    r'/(?:[a-zA-Z0-9_.\-]+/)*[a-zA-Z0-9_.\-]+\.[a-zA-Z0-9]{2,4}(?:\?[^"\s\'`]*)?'
    r'|'
    r'/(?:[a-zA-Z0-9_.\-]+/)+[a-zA-Z0-9_.\-]*(?:\?[^"\s\'`]*)?'
    r'|'
    r'/api/v[0-9]+/[a-zA-Z0-9_.\-/]+(?:\?[^"\s\'`]*)?'
    r')(?:"|\')',
    re.IGNORECASE
)

# JavaScript resources ONLY: .js, .mjs, .cjs (with optional query string).
JS_FILE_REGEX = re.compile(
    r'(?:src|href)=["\']([^"\']+\.(?:js|mjs|cjs)(?:\?[^"\']*)?)["\']'
    r'|(?:"|\')([^"\']+\.(?:js|mjs|cjs)(?:\?[^"\']*)?)(?:"|\')',
    re.IGNORECASE
)

# Non-JavaScript extensions are never treated as resources.
JS_EXTENSIONS = (".js", ".mjs", ".cjs")

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".exe",
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".xml", ".json"
}

MAX_RESPONSE_SIZE = 10 * 1024 * 1024
MAX_REDIRECTS = 5


class ScopeManager:
    """Strict hostname-boundary scope: root domain (+ subdomains by default)."""

    def __init__(self, target_url: str, include_subs: bool = True):
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or ""
        self.raw_host = hostname.lower()
        self.include_subs = include_subs

        if self.raw_host.startswith("www."):
            self.base_domain = self.raw_host[4:]
        else:
            self.base_domain = self.raw_host

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc and not parsed.hostname:
                return True

            hostname = parsed.hostname
            if not hostname:
                return False
            hostname = hostname.lower()

            if self.include_subs:
                # Strict boundary: exact host or a subdomain of the base domain.
                return hostname == self.base_domain or hostname.endswith("." + self.base_domain)
            else:
                # Root domain and its www variant only.
                return hostname == self.base_domain or hostname == f"www.{self.base_domain}"
        except Exception:
            return False


class URLNormalizer:
    @staticmethod
    def is_static_asset(url: str) -> bool:
        try:
            path = urllib.parse.urlparse(url).path.lower()
            return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)
        except Exception:
            return False

    @staticmethod
    def is_js_file(url: str) -> bool:
        try:
            path = urllib.parse.urlparse(url).path.lower()
            return path.endswith(JS_EXTENSIONS)
        except Exception:
            return False

    @staticmethod
    def normalize(url: str, base_url: str = "") -> str:
        if base_url:
            try:
                url = urllib.parse.urljoin(base_url, url)
            except Exception:
                return ""

        try:
            parsed = urllib.parse.urlparse(url)
            scheme = parsed.scheme.lower() if parsed.scheme else "http"
            hostname = (parsed.hostname or "").lower()

            try:
                port = parsed.port
            except ValueError:
                port = None

            if ":" in hostname and not hostname.startswith("["):
                formatted_host = f"[{hostname}]"
            else:
                formatted_host = hostname

            if port:
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    netloc = formatted_host
                else:
                    netloc = f"{formatted_host}:{port}"
            else:
                netloc = formatted_host

            path = parsed.path if parsed.path else "/"

            # Query string: sort parameters with case-insensitive keys so
            # permutations / casing differences deduplicate after normalization.
            query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            # Parameter names are case-insensitive; values keep their case.
            query_tuples = [(k.lower(), v) for k, v in query_tuples]
            query_tuples.sort(key=lambda kv: (kv[0], kv[1]))
            sorted_query = urllib.parse.urlencode(query_tuples)

            return urllib.parse.urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))
        except Exception:
            return url


class ProgressLine:
    """One live terminal line for the entire scan (thread-safe)."""

    def __init__(self, quiet: bool = False, prefix: str = "JS-SCAN", width: int = 18):
        self.quiet = quiet
        self.prefix = prefix
        self.width = width
        self.lock = threading.Lock()
        self.finished = False

    def update(self, completed: int, total: int, js_count: int, endpoint_count: int):
        if self.quiet or self.finished or total <= 0:
            return
        with self.lock:
            ratio = min(completed / total, 1.0)
            filled = int(self.width * ratio)
            bar = "●" * filled + "○" * (self.width - filled)
            sys.stdout.write(
                f"\r[{self.prefix}] [{bar}] {int(ratio * 100):3d}% | "
                f"{completed}/{total} | JS: {js_count} | EP: {endpoint_count}"
            )
            sys.stdout.flush()

    def finish(self):
        if self.quiet or self.finished:
            return
        with self.lock:
            sys.stdout.write("\n")
            sys.stdout.flush()
            self.finished = True


class JSExtractorEngine:
    def __init__(self, target: str, threads: int = 10, depth: int = 2, include_subs: bool = True,
                 headers: dict = None, cookie: str = None, verify_ssl: bool = True, quiet: bool = False):
        self.target = URLNormalizer.normalize(target)
        self.scope = ScopeManager(self.target, include_subs=include_subs)
        self.threads = threads
        self.max_depth = depth
        self.verify_ssl = verify_ssl
        self.quiet = quiet

        self.session = requests.Session()

        no_retry_adapter = HTTPAdapter(
            max_retries=urllib3.util.retry.Retry(
                total=0, connect=0, read=0, status=0, redirect=0
            )
        )
        self.session.mount("http://", no_retry_adapter)
        self.session.mount("https://", no_retry_adapter)

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) JSExtractor/1.0",
            "Accept": "*/*"
        })
        if headers:
            self.session.headers.update(headers)
        if cookie:
            self.session.headers.update({"Cookie": cookie})

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_js_files: Set[str] = set()
        self.lock = threading.Lock()
        self.progress = ProgressLine(quiet=quiet)

    def fetch_url(self, url: str) -> Tuple[str, str]:
        current_url = url

        for _ in range(MAX_REDIRECTS):
            # Validate every hop against scope; out-of-scope redirects are dropped.
            if not self.scope.is_in_scope(current_url):
                return "", ""

            try:
                response = self.session.get(
                    current_url,
                    timeout=10,
                    verify=self.verify_ssl,
                    stream=True,
                    allow_redirects=False
                )
            except Exception:
                return "", ""

            if response.is_redirect or response.is_permanent_redirect or (300 <= response.status_code < 400):
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return "", ""
                current_url = URLNormalizer.normalize(location, base_url=current_url)
                continue

            try:
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_RESPONSE_SIZE:
                            response.close()
                            return "", ""
                    except (ValueError, TypeError):
                        pass

                raw_chunks = []
                byte_size = 0

                for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                    if chunk:
                        byte_size += len(chunk)
                        if byte_size > MAX_RESPONSE_SIZE:
                            response.close()
                            return "", ""
                        raw_chunks.append(chunk)

                raw_data = b"".join(raw_chunks)
                content_type = response.headers.get("Content-Type", "")

                encoding = response.encoding or "utf-8"
                try:
                    text_content = raw_data.decode(encoding, errors="replace")
                except Exception:
                    text_content = raw_data.decode("utf-8", errors="replace")

                return text_content, content_type
            finally:
                response.close()

        return "", ""

    def process_html_content(self, url: str, html_text: str, current_depth: int) -> List[Tuple[str, int]]:
        """HTML is crawled ONLY to locate JavaScript resources and deeper pages.

        No HTML/PHP/CSS/XML/JSON/PDF/media/etc. link is ever registered as
        a resource, and no endpoint is extracted from HTML.
        """
        next_targets = []

        # 1. Extract JavaScript resources (.js / .mjs / .cjs) only.
        js_matches = JS_FILE_REGEX.findall(html_text)
        for match in js_matches:
            js_link = match[0] or match[1]
            if js_link:
                norm_js = URLNormalizer.normalize(js_link, base_url=url)
                if self.scope.is_in_scope(norm_js) and URLNormalizer.is_js_file(norm_js):
                    with self.lock:
                        self.discovered_js_files.add(norm_js)

        # 2. Follow HTML links purely for depth crawling — never as resources.
        raw_hrefs = re.findall(r'href=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
        for href in raw_hrefs:
            norm_url = URLNormalizer.normalize(href, base_url=url)
            if self.scope.is_in_scope(norm_url) and not URLNormalizer.is_static_asset(norm_url):
                with self.lock:
                    if norm_url not in self.visited_urls:
                        if current_depth < self.max_depth:
                            next_targets.append((norm_url, current_depth + 1))

        return next_targets

    def process_js_content(self, js_url: str, js_text: str):
        """Extract nested JS references and endpoints from JavaScript source."""
        # 1. Nested JavaScript files.
        js_matches = JS_FILE_REGEX.findall(js_text)
        for match in js_matches:
            js_link = match[0] or match[1]
            if js_link:
                norm_js = URLNormalizer.normalize(js_link, base_url=js_url)
                if self.scope.is_in_scope(norm_js) and URLNormalizer.is_js_file(norm_js):
                    with self.lock:
                        self.discovered_js_files.add(norm_js)

        # 2. Endpoints (absolute / protocol-relative / relative) from JS only.
        endpoints = ENDPOINT_REGEX.findall(js_text)
        for ep in endpoints:
            norm_ep = URLNormalizer.normalize(ep, base_url=js_url)
            if self.scope.is_in_scope(norm_ep) and not URLNormalizer.is_static_asset(norm_ep):
                with self.lock:
                    self.discovered_endpoints.add(norm_ep)

    def run(self):
        # ---- Phase 1: crawl pages within depth/scope to find JS resources ----
        queue: List[Tuple[str, int]] = [(self.target, 0)]
        self.visited_urls.add(self.target)

        progress_total = 0
        progress_done = 0

        while queue:
            progress_total += len(queue)
            next_queue = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.fetch_url, u): (u, d) for u, d in queue
                }

                for future in concurrent.futures.as_completed(future_to_url):
                    u, d = future_to_url[future]
                    html_content, _ = future.result()

                    if html_content:
                        new_links = self.process_html_content(u, html_content, d)
                        for link, depth in new_links:
                            if link not in self.visited_urls:
                                self.visited_urls.add(link)
                                next_queue.append((link, depth))

                    progress_done += 1
                    self.progress.update(
                        progress_done, progress_total,
                        len(self.discovered_js_files), len(self.discovered_endpoints)
                    )

            queue = next_queue

        # ---- Phase 2: fetch JS sources for nested JS + endpoint extraction ----
        js_list = list(self.discovered_js_files)
        progress_total += len(js_list)

        if js_list:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_js = {executor.submit(self.fetch_url, js_url): js_url for js_url in js_list}

                for future in concurrent.futures.as_completed(future_to_js):
                    js_url = future_to_js[future]
                    js_content, _ = future.result()

                    if js_content:
                        self.process_js_content(js_url, js_content)

                    progress_done += 1
                    self.progress.update(
                        progress_done, progress_total,
                        len(self.discovered_js_files), len(self.discovered_endpoints)
                    )

        self.progress.finish()


def main():
    parser = argparse.ArgumentParser(description="Strict JavaScript-Only Scanner (.js / .mjs / .cjs)")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-l", "--list", help="Target URLs file")
    parser.add_argument("-o", "--output", help="Output file for discovered JavaScript resources")
    parser.add_argument("--js", action="store_true",
                        help="Accepted for compatibility; the scanner is always JS-only")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (Default: 10)")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawl depth limit (Default: 1)")
    parser.add_argument("--deep", action="store_true", help="Set depth limit to 5")
    parser.add_argument("--no-sub", action="store_true", help="Exclude subdomains from scope")
    parser.add_argument("-H", "--header", action="append", help="Custom Header (e.g. -H 'Authorization: Bearer token')")
    parser.add_argument("-c", "--cookie", help="Custom cookie string")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output except errors")

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("At least one target (-u or -l) must be specified.")

    if args.threads < 1:
        parser.error("--threads must be at least 1")

    if args.depth < 0:
        parser.error("--depth cannot be negative")

    if args.quiet:
        logger.setLevel(logging.ERROR)

    custom_headers = {}
    if args.header:
        for header_str in args.header:
            if ":" not in header_str:
                continue
            k, v = header_str.split(":", 1)
            k_clean, v_clean = k.strip(), v.strip()
            if k_clean:
                custom_headers[k_clean] = v_clean

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        if not os.path.isfile(args.list):
            parser.error(f"Target list not found: {args.list}")
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    depth = 5 if args.deep else args.depth

    all_js_files = set()

    if not args.quiet:
        print(f"[+] Target Count: {len(targets)}")
        print(f"[+] Mode: JavaScript-Only (.js/.mjs/.cjs) | Subdomains: {'excluded' if args.no_sub else 'included'}")
        print(f"[+] Threads: {args.threads} | Depth: {depth}")

    for target in targets:
        engine = JSExtractorEngine(
            target=target,
            threads=args.threads,
            depth=depth,
            include_subs=not args.no_sub,
            headers=custom_headers,
            cookie=args.cookie,
            verify_ssl=not args.insecure,
            quiet=args.quiet
        )
        engine.run()
        all_js_files.update(engine.discovered_js_files)

    # Final resource output: JavaScript files ONLY, deduplicated post-normalization.
    results = sorted(all_js_files)

    if not args.quiet:
        print(f"\n[+] JavaScript Files ({len(results)}):")
        for item in results:
            print(item)

    if args.output:
        with open(args.output, "w") as f:
            for item in results:
                f.write(f"{item}\n")
        if not args.quiet:
            logger.info(f"Saved {len(results)} JavaScript resources to {args.output}")


if __name__ == "__main__":
    main()
