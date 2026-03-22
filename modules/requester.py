"""
modules/requester.py
HTTP Client untuk GetParam
Menangani semua request dengan built-in retry, UA rotation, dan bypass mode
"""

import requests
import time
import random
from typing import Optional, Dict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Requester:

    # User-Agent pool untuk rotasi
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0',
        'python-requests/2.31.0',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'PostmanRuntime/7.36.0',
        'curl/7.88.1',
    ]

    # Header variation untuk bypass fingerprinting
    BYPASS_HEADERS = [
        {'X-Forwarded-For'   : '127.0.0.1'},
        {'X-Forwarded-For'   : '8.8.8.8'},
        {'X-Real-IP'         : '127.0.0.1'},
        {'X-Originating-IP'  : '127.0.0.1'},
        {'CF-Connecting-IP'  : '127.0.0.1'},
        {'X-Client-IP'       : '127.0.0.1'},
        {'Forwarded'         : 'for=127.0.0.1'},
        {},   # no extra header
    ]

    def __init__(self, url, method='GET', headers=None,
                 proxy=None, timeout=10, delay=0,
                 bypass=None, verbose=False):
        self.url     = url
        self.method  = method.upper()
        self.timeout = timeout
        self.delay   = delay
        self.bypass  = bypass
        self.verbose = verbose
        self.session = self._build_session(headers or {}, proxy)
        self._req_count = 0

    def _build_session(self, custom_headers: dict, proxy: Optional[str]) -> requests.Session:
        session = requests.Session()
        retry   = Retry(total=2, backoff_factor=0.3,
                        status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Base headers
        session.headers.update({
            'Accept'         : 'text/html,application/xhtml+xml,application/json,*/*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection'     : 'keep-alive',
        })

        # Tambahkan custom headers (auth, cookie, dll)
        if custom_headers:
            session.headers.update(custom_headers)

        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}

        return session

    def _apply_bypass(self):
        """Rotasi UA dan header untuk menghindari rate limiting dan fingerprinting"""
        if not self.bypass or not self.bypass.enabled:
            return

        # Rotasi User-Agent setiap beberapa request
        if self._req_count % 15 == 0:
            ua = random.choice(self.USER_AGENTS)
            self.session.headers['User-Agent'] = ua

        # Rotasi bypass header setiap beberapa request
        if self._req_count % 10 == 0:
            # Hapus bypass header lama
            for h in ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
                      'CF-Connecting-IP', 'X-Client-IP', 'Forwarded']:
                self.session.headers.pop(h, None)
            # Tambah yang baru
            extra = random.choice(self.BYPASS_HEADERS)
            self.session.headers.update(extra)

        # Delay adaptif dari bypass engine
        delay = self.bypass.get_delay()
        if delay > 0:
            time.sleep(delay)

    def send(self, params: dict) -> Optional[dict]:
        """
        Kirim request dengan params yang diberikan.
        Return dict berisi status, size, time, body — atau None jika gagal.
        """
        self._req_count += 1
        self._apply_bypass()

        # Tambahkan delay manual jika diset
        if self.delay > 0:
            time.sleep(self.delay)

        start = time.time()
        try:
            if self.method == 'GET':
                resp = self.session.get(
                    self.url, params=params,
                    timeout=self.timeout, verify=False,
                    allow_redirects=True
                )
            elif self.method == 'POST':
                resp = self.session.post(
                    self.url, data=params,
                    timeout=self.timeout, verify=False,
                    allow_redirects=True
                )
            elif self.method == 'JSON':
                resp = self.session.post(
                    self.url, json=params,
                    headers={'Content-Type': 'application/json'},
                    timeout=self.timeout, verify=False,
                    allow_redirects=True
                )
            elif self.method == 'HEADER':
                extra = {k: v for k, v in params.items()}
                resp = self.session.get(
                    self.url, headers=extra,
                    timeout=self.timeout, verify=False,
                    allow_redirects=True
                )
            else:
                return None

            elapsed = time.time() - start
            body    = resp.text or ''

            return {
                'status'  : resp.status_code,
                'size'    : len(body),
                'time'    : elapsed,
                'body'    : body,
                'headers' : dict(resp.headers),
            }

        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"      [timeout] {params}")
            return {'status': 0, 'size': 0, 'time': self.timeout, 'body': '', 'headers': {}}
        except Exception as e:
            if self.verbose:
                print(f"      [error] {e}")
            return None
