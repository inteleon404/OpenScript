#!/usr/bin/env python3
"""
Author: Rushbruh 
"""

import argparse
import concurrent.futures
import http.cookiejar
import posixpath
import re
import ssl
import sys
import threading
import urllib.parse
import urllib.request
from collections import deque

# --- CONSTANTS & REGEX PATTERNS ---
JS_EXTENSIONS = ('.js', '.mjs', '.cjs')

# Matches script tags pointing to JS files in HTML
HTML_SCRIPT_SRC_REGEX = re.compile(
    r'''<script\s+[^>]*?src=["']([^"']+\.(?:js|mjs|cjs)(?:\?[^"']*)?)["']''',
    re.IGNORECASE
)

# Extracts endpoints from JavaScript content (absolute, protocol-relative, relative)
JS_ENDPOINT_REGEX = re.compile(
    r'''(?:"|')('''
    r'''(?:https?://|//)[^\s"'`<>]+'''           # Absolute or protocol-relative
    r'''|/(?:[^\s"'`<>]+)'''                     # Relative starting with /
    r'''|\.\./(?:[^\s"'`<>]+)'''                 # Relative starting with ../
    r'''|\./(?:[^\s"'`<>]+)'''                   # Relative starting with ./
    r''')(?:"|')''',
    re.IGNORECASE
)

# Extensions to strictly ignore when extracting endpoints
NON_JS_EXT_IGNORE = re.compile(
    r'\.(?:html?|php|css|xml|json|pdf|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|mp3|zip|gz|tar)(?:\?.*)?$',
    re.IGNORECASE
)

class JSScanner:
    def __init__(self, targets, depth=2, threads=10, no_sub=False, headers=None, 
                 cookie=None, insecure=False, max_size=5*1024*1024, timeout=10):
        self.depth = depth
        self.threads = threads
        self.no_sub = no_sub
        self.headers = headers or {}
        self.cookie = cookie
        self.insecure = insecure
        self.max_size = max_size
        self.timeout = timeout

        self.visited_urls = set()
        self.discovered_js = set()
        self.extracted_endpoints = set()
        self.lock = threading.Lock()

        # Stats for progress tracking
        self.processed_count = 0
        self.total_queued = 0

        # Scope initializations
        self.target_scopes = []
        for target in targets:
            url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            
            # Derive root domain
            parts = hostname.split('.')
            root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            allowed_hosts = {root_domain, f"www.{root_domain}"} if no_sub else set()
            
            self.target_scopes.append({
                'seed': url,
                'root_domain': root_domain,
                'allowed_hosts': allowed_hosts
            })

    def is_in_scope(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return False
        
        hostname = parsed.hostname.lower()
        for scope in self.target_scopes:
            root_domain = scope['root_domain']
            if self.no_sub:
                if hostname in scope['allowed_hosts']:
                    return True
            else:
                if hostname == root_domain or hostname.endswith('.' + root_domain):
                    return True
        return False

    def is_js_url(self, url):
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in JS_EXTENSIONS)

    def normalize_url(self, url, base_url=None):
        if base_url:
            url = urllib.parse.urljoin(base_url, url)
            
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = posixpath.normpath(parsed.path) if parsed.path else '/'
        
        # Case-insensitive query string normalization & deduplication
        query = ''
        if parsed.query:
            params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            params_lower = sorted([(k.lower(), v.lower()) for k, v in params])
            query = urllib.parse.urlencode(params_lower)

        return urllib.parse.urlunparse((scheme, netloc, path, '', query, ''))

    def update_progress(self):
        with self.lock:
            msg = (f"\r[+] Scanning... Queued: {self.total_queued} | "
                   f"Processed: {self.processed_count} | "
                   f"JS Files: {len(self.discovered_js)} | "
                   f"Endpoints: {len(self.extracted_endpoints)}")
            sys.stdout.write(msg)
            sys.stdout.flush()

    def fetch(self, url):
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        for h_key, h_val in self.headers.items():
            req.add_header(h_key, h_val)
        if self.cookie:
            req.add_header('Cookie', self.cookie)

        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                # Handle redirect validation & response limits
                final_url = resp.geturl()
                if not self.is_in_scope(final_url):
                    return None, None

                content_type = resp.headers.get('Content-Type', '').lower()
                content = resp.read(self.max_size + 1)
                if len(content) > self.max_size:
                    return None, None # Exceeds response size limit

                return content.decode('utf-8', errors='ignore'), final_url
        except Exception:
            return None, None

    def process_url(self, item):
        url, current_depth = item
        
        with self.lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)

        content, final_url = self.fetch(url)
        
        with self.lock:
            self.processed_count += 1
            self.update_progress()

        if not content or not final_url:
            return

        # Handle JS Resource
        if self.is_js_url(final_url):
            with self.lock:
                self.discovered_js.add(final_url)

            # Extract endpoints ONLY from JavaScript content
            raw_endpoints = JS_ENDPOINT_REGEX.findall(content)
            for ep_tuple in raw_endpoints:
                ep = ep_tuple[0] if isinstance(ep_tuple, tuple) else ep_tuple
                
                # Filter out obvious non-JS static assets
                if NON_JS_EXT_IGNORE.search(ep):
                    continue

                normalized_ep = self.normalize_url(ep, base_url=final_url)
                if normalized_ep:
                    with self.lock:
                        self.extracted_endpoints.add(normalized_ep)
                    
                    # If endpoint is a JS resource and depth allows, queue it
                    if self.is_js_url(normalized_ep) and self.is_in_scope(normalized_ep) and current_depth < self.depth:
                        self.add_to_queue(normalized_ep, current_depth + 1)

        # Handle Seed HTML page (ONLY to extract .js, .mjs, .cjs script links)
        elif current_depth < self.depth:
            script_srcs = HTML_SCRIPT_SRC_REGEX.findall(content)
            for src in script_srcs:
                js_url = self.normalize_url(src, base_url=final_url)
                if js_url and self.is_js_url(js_url) and self.is_in_scope(js_url):
                    self.add_to_queue(js_url, current_depth + 1)

    def add_to_queue(self, url, depth):
        with self.lock:
            if url not in self.visited_urls:
                self.queue.append((url, depth))
                self.total_queued += 1

    def run(self):
        self.queue = deque()
        for scope in self.target_scopes:
            seed_norm = self.normalize_url(scope['seed'])
            if seed_norm:
                self.queue.append((seed_norm, 1))
                self.total_queued += 1

        self.update_progress()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = set()
            while True:
                with self.lock:
                    while self.queue and len(futures) < self.threads * 2:
                        item = self.queue.popleft()
                        futures.add(executor.submit(self.process_url, item))

                if not futures:
                    break

                # Wait for at least one future to complete
                done, futures = concurrent.futures.wait(
                    futures, return_when=concurrent.futures.FIRST_COMPLETED
                )

        # Print single newline after complete scan
        sys.stdout.write("\n")
        sys.stdout.flush()

# --- MAIN CLI EXECUTION ---
def main():
    parser = argparse.ArgumentParser(
        description="Strict JavaScript Scanner and Endpoint Extractor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--list", help="File containing list of targets")

    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--no-sub", action="store_true", help="Disallow subdomains (only root domain & www)")
    parser.add_argument("-H", "--header", action="append", help="Custom header (e.g. 'Header: Value')")
    parser.add_argument("-c", "--cookie", help="Custom Cookie string")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--max-size", type=int, default=5242880, help="Max response size limit in bytes (default: 5MB)")
    parser.add_argument("-o", "--output", help="File path to save discovered JS resources")
    parser.add_argument("-e", "--endpoints", help="File path to save extracted endpoints")

    args = parser.parse_args()

    targets = []
    if args.url:
        targets.append(args.url.strip())
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)

    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    scanner = JSScanner(
        targets=targets,
        depth=args.depth,
        threads=args.threads,
        no_sub=args.no_sub,
        headers=headers,
        cookie=args.cookie,
        insecure=args.insecure,
        max_size=args.max_size
    )

    scanner.run()

    # Output discovered JS Files
    if scanner.discovered_js:
        print(f"\n[+] Discovered JavaScript Resources ({len(scanner.discovered_js)}):")
        for js in sorted(scanner.discovered_js):
            print(js)
        
        if args.output:
            with open(args.output, 'w') as f:
                for js in sorted(scanner.discovered_js):
                    f.write(f"{js}\n")
            print(f"[+] Saved JS resources to: {args.output}")

    # Output Extracted Endpoints
    if scanner.extracted_endpoints:
        print(f"\n[+] Extracted Endpoints from JS ({len(scanner.extracted_endpoints)}):")
        for ep in sorted(scanner.extracted_endpoints):
            print(ep)

        if args.endpoints:
            with open(args.endpoints, 'w') as f:
                for ep in sorted(scanner.extracted_endpoints):
                    f.write(f"{ep}\n")
            print(f"[+] Saved endpoints to: {args.endpoints}")

if __name__ == "__main__":
    main()
