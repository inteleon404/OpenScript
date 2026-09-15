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
from typing import Dict, List, Set, Tuple
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
logger = logging.getLogger("recon")

ENDPOINT_REGEX = re.compile(
    r'(?:"|\')('
    r'(?:[a-zA-Z]{1,10}://|//)'
    r'[^"\s\'`]{2,}'
    r'|'
    r'/(?:[a-zA-Z0-9_.\-]+/)*[a-zA-Z0-9_.\-]+\.[a-zA-Z0-9]{2,4}(?:\?[^"\s\'`]*)?'
    r'|'
    r'/(?:[a-zA-Z0-9_.\-]+/)+[a-zA-Z0-9_.\-]*'
    r'|'
    r'/api/v[0-9]+/[a-zA-Z0-9_.\-/]+'
    r')(?:"|\')',
    re.IGNORECASE
)

JS_FILE_REGEX = re.compile(
    r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']|(?:"|\')([^"\']+\.js(?:\?[^"\']*)?)(?:"|\')',
    re.IGNORECASE
)

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".exe"
}

MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB Limit
MAX_REDIRECTS = 5


class ScopeManager:
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
                return True  # Relative URL
            
            hostname = parsed.hostname
            if not hostname:
                return False
            hostname = hostname.lower()

            if self.include_subs:
                return hostname == self.base_domain or hostname.endswith("." + self.base_domain)
            else:
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
    def normalize(url: str, base_url: str = "") -> str:
        if base_url:
            url = urllib.parse.urljoin(base_url, url)
        
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        
        hostname = parsed.hostname or ""
        port = parsed.port
        
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
        
        query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_tuples.sort()
        sorted_query = urllib.parse.urlencode(query_tuples)
        
        return urllib.parse.urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))


def render_progress(completed: int, total: int, js_count: int, endpoint_count: int, prefix: str = "SCAN", quiet: bool = False):
    if quiet or total <= 0:
        return
    width = 18
    ratio = min(completed / total, 1.0)
    filled = int(width * ratio)
    empty = width - filled
    percent = int(ratio * 100)
    bar = "●" * filled + "○" * empty

    sys.stdout.write(
        f"\r[{prefix}] [{bar}] {percent:3d}% | "
        f"{completed}/{total} | JS: {js_count} | EP: {endpoint_count}"
    )
    sys.stdout.flush()
    if completed >= total:
        sys.stdout.write("\n")


class ReconEngine:
    def __init__(self, target: str, threads: int = 10, depth: int = 2, include_subs: bool = True,
                 headers: dict = None, cookie: str = None, verify_ssl: bool = True, quiet: bool = False):
        self.target = URLNormalizer.normalize(target)
        self.scope = ScopeManager(self.target, include_subs=include_subs)
        self.threads = threads
        self.max_depth = depth
        self.verify_ssl = verify_ssl
        self.quiet = quiet

        # HTTP Session Setup
        self.session = requests.Session()
        
        no_retry_adapter = HTTPAdapter(
            max_retries=urllib3.util.retry.Retry(
                total=0, connect=0, read=0, status=0, redirect=0
            )
        )
        self.session.mount("http://", no_retry_adapter)
        self.session.mount("https://", no_retry_adapter)

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconEngine/1.0",
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

    def fetch_url(self, url: str) -> Tuple[str, str]:
        """মেমরি ও সকেট লিকেজ মুক্ত, বাইট-নির্ভুল এবং ম্যানুয়াল রিডাইরেক্ট ফিল্টারিং সহ HTTP Request পাঠায়"""
        current_url = url
        
        for _ in range(MAX_REDIRECTS):
            if not self.scope.is_in_scope(current_url):
                logger.debug(f"Redirect target out of scope blocked: {current_url}")
                return "", ""
            
            try:
                response = self.session.get(
                    current_url,
                    timeout=10,
                    verify=self.verify_ssl,
                    stream=True,
                    allow_redirects=False
                )
            except requests.RequestException as e:
                logger.debug(f"Request failed for {current_url}: {e}")
                return "", ""
            except Exception as e:
                logger.debug(f"Unexpected error fetching {current_url}: {e}")
                return "", ""

            # 1. Manual Hop-by-Hop Redirect Validation
            if response.is_redirect or response.is_permanent_redirect or (300 <= response.status_code < 400):
                location = response.headers.get("Location")
                response.close()
                if not location:
                    return "", ""
                current_url = URLNormalizer.normalize(location, base_url=current_url)
                continue

            # 2. Content Handling for Final Destination
            try:
                # Header based Content-Length check
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
                
                # Raw Bytes Read (Decode Unicode Disabled for Byte-Accurate Sizing)
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                    if chunk:
                        byte_size += len(chunk)
                        if byte_size > MAX_RESPONSE_SIZE:
                            response.close()
                            return "", ""
                        raw_chunks.append(chunk)

                raw_data = b"".join(raw_chunks)
                content_type = response.headers.get("Content-Type", "")
                
                # Safe Encoding Fallback
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
        next_targets = []
        
        # 1. Extract Links/HTML endpoints
        raw_hrefs = re.findall(r'href=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
        for href in raw_hrefs:
            norm_url = URLNormalizer.normalize(href, base_url=url)
            if self.scope.is_in_scope(norm_url) and not URLNormalizer.is_static_asset(norm_url):
                with self.lock:
                    if norm_url not in self.visited_urls:
                        if current_depth < self.max_depth:
                            next_targets.append((norm_url, current_depth + 1))
                        self.discovered_endpoints.add(norm_url)

        # 2. Extract JS files
        js_matches = JS_FILE_REGEX.findall(html_text)
        for match in js_matches:
            js_link = match[0] or match[1]
            if js_link:
                norm_js = URLNormalizer.normalize(js_link, base_url=url)
                if self.scope.is_in_scope(norm_js):
                    with self.lock:
                        self.discovered_js_files.add(norm_js)

        # 3. Extract Inline Endpoints
        endpoints = ENDPOINT_REGEX.findall(html_text)
        for ep in endpoints:
            norm_ep = URLNormalizer.normalize(ep, base_url=url)
            if self.scope.is_in_scope(norm_ep) and not URLNormalizer.is_static_asset(norm_ep):
                with self.lock:
                    self.discovered_endpoints.add(norm_ep)

        return next_targets

    def run(self):
        # Phase 1: Crawling
        queue: List[Tuple[str, int]] = [(self.target, 0)]
        self.visited_urls.add(self.target)

        while queue:
            total_items = len(queue)
            completed_items = 0
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

                    completed_items += 1
                    render_progress(
                        completed_items, total_items,
                        len(self.discovered_js_files), len(self.discovered_endpoints),
                        prefix="SCAN", quiet=self.quiet
                    )

            queue = next_queue

        # Phase 2: JS Deep Parsing
        js_list = list(self.discovered_js_files)
        total_js = len(js_list)
        if total_js > 0:
            completed_js = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_js = {executor.submit(self.fetch_url, js_url): js_url for js_url in js_list}

                for future in concurrent.futures.as_completed(future_to_js):
                    js_url = future_to_js[future]
                    js_content, _ = future.result()

                    if js_content:
                        endpoints = ENDPOINT_REGEX.findall(js_content)
                        for ep in endpoints:
                            norm_ep = URLNormalizer.normalize(ep, base_url=js_url)
                            if self.scope.is_in_scope(norm_ep) and not URLNormalizer.is_static_asset(norm_ep):
                                with self.lock:
                                    self.discovered_endpoints.add(norm_ep)

                    completed_js += 1
                    render_progress(
                        completed_js, total_js,
                        len(self.discovered_js_files), len(self.discovered_endpoints),
                        prefix="JS-SCAN", quiet=self.quiet
                    )


def main():
    parser = argparse.ArgumentParser(description="Production-Grade Security Recon Engine")
    parser.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-l", "--list", help="Target URLs file")
    parser.add_argument("-o", "--output", help="Output file for endpoints")
    parser.add_argument("--js-output", help="Output file for discovered JS files")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (Default: 10)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth limit (Default: 2)")
    parser.add_argument("--deep", action="store_true", help="Set depth limit to 5")
    parser.add_argument("--no-sub", action="store_true", help="Exclude subdomains from scope (default: subdomains included)")
    parser.add_argument("-H", "--header", action="append", help="Custom Header (e.g. -H 'Authorization: Bearer token')")
    parser.add_argument("-c", "--cookie", help="Custom cookie string")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output except errors")

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("At least one target (-u or -l) must be specified.")

    # Quiet mode enforcement
    if args.quiet:
        logger.setLevel(logging.ERROR)

    # Custom Header Parsing with Warnings
    custom_headers = {}
    if args.header:
        for header_str in args.header:
            if ":" not in header_str:
                logger.warning(f"Invalid header format ignored: '{header_str}' (Must be 'Key: Value')")
                continue
            k, v = header_str.split(":", 1)
            k_clean, v_clean = k.strip(), v.strip()
            if k_clean:
                custom_headers[k_clean] = v_clean

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list and os.path.exists(args.list):
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    depth = 5 if args.deep else args.depth

    all_endpoints = set()
    all_js_files = set()

    for target in targets:
        logger.info(f"Starting Recon on target: {target}")
        
        engine = ReconEngine(
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

        all_endpoints.update(engine.discovered_endpoints)
        all_js_files.update(engine.discovered_js_files)

    # Save Output
    if args.output:
        with open(args.output, "w") as f:
            for ep in sorted(all_endpoints):
                f.write(f"{ep}\n")
        logger.info(f"Saved {len(all_endpoints)} endpoints to {args.output}")

    if args.js_output:
        with open(args.js_output, "w") as f:
            for js in sorted(all_js_files):
                f.write(f"{js}\n")
        logger.info(f"Saved {len(all_js_files)} JS URLs to {args.js_output}")


if __name__ == "__main__":
    main()
