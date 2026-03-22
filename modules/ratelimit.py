"""
modules/ratelimit.py
Rate Limit Bypass Engine
Strategi adaptif untuk menghindari rate limiting dan blocking
"""

import random
import time


class RateLimitBypass:

    # Strategi berdasarkan WAF yang terdeteksi
    WAF_STRATEGIES = {
        'Cloudflare': {
            'min_delay'  : 0.3,
            'max_delay'  : 0.8,
            'ua_rotate'  : 5,     # rotate UA setiap N request
            'chunk_mult' : 0.5,   # kurangi chunk size 50%
        },
        'ModSecurity': {
            'min_delay'  : 0.1,
            'max_delay'  : 0.4,
            'ua_rotate'  : 10,
            'chunk_mult' : 0.7,
        },
        'Akamai': {
            'min_delay'  : 0.5,
            'max_delay'  : 1.2,
            'ua_rotate'  : 3,
            'chunk_mult' : 0.4,
        },
        'Wordfence': {
            'min_delay'  : 0.2,
            'max_delay'  : 0.6,
            'ua_rotate'  : 8,
            'chunk_mult' : 0.6,
        },
        'default': {
            'min_delay'  : 0.05,
            'max_delay'  : 0.2,
            'ua_rotate'  : 15,
            'chunk_mult' : 1.0,
        },
    }

    def __init__(self, enabled=True):
        self.enabled    = enabled
        self.strategy   = self.WAF_STRATEGIES['default']
        self._req_count = 0
        self._429_count = 0       # jumlah rate limit hit
        self._backoff   = 1.0     # current backoff multiplier

    def set_waf_mode(self, waf_name: str):
        """Set strategi bypass berdasarkan WAF yang terdeteksi"""
        for key in self.WAF_STRATEGIES:
            if key.lower() in waf_name.lower():
                self.strategy = self.WAF_STRATEGIES[key]
                return
        self.strategy = self.WAF_STRATEGIES['default']

    def get_delay(self) -> float:
        """
        Hitung delay untuk request berikutnya.
        Delay bervariasi secara acak dalam range min-max strategy.
        Jika ada hit 429, backoff dinaikkan otomatis.
        """
        if not self.enabled:
            return 0.0

        base_delay = random.uniform(
            self.strategy['min_delay'],
            self.strategy['max_delay']
        )

        # Jitter kecil agar tidak terlalu predictable
        jitter = random.uniform(0, 0.05)

        total = (base_delay + jitter) * self._backoff
        return round(total, 3)

    def on_rate_limited(self):
        """
        Dipanggil ketika server return 429 Too Many Requests.
        Naikkan backoff secara exponential, max 10x.
        """
        self._429_count += 1
        self._backoff    = min(self._backoff * 2, 10.0)
        wait             = self._backoff * 2
        time.sleep(wait)

    def on_success(self):
        """
        Dipanggil setelah request sukses.
        Turunkan backoff perlahan.
        """
        if self._backoff > 1.0:
            self._backoff = max(1.0, self._backoff * 0.9)

    def get_chunk_multiplier(self) -> float:
        """Return multiplier untuk ukuran chunk berdasarkan WAF strategy"""
        return self.strategy.get('chunk_mult', 1.0)

    @property
    def total_rate_limited(self) -> int:
        return self._429_count
