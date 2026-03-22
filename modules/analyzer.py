"""
modules/analyzer.py
Response Analyzer — Multi-Signal Detection
Membandingkan response dengan baseline menggunakan 5 sinyal berbeda
"""

import re
import time


class Analyzer:

    # Threshold untuk menentukan "perbedaan signifikan"
    SIZE_THRESHOLD   = 0.05   # 5% perubahan ukuran
    TIME_THRESHOLD   = 2.0    # 2x lebih lambat dari baseline
    MIN_SIZE_DIFF    = 30     # minimal 30 byte berbeda (abaikan noise kecil)

    def __init__(self, requester, verbose=False):
        self.req     = requester
        self.verbose = verbose
        self._baseline = None

    def get_baseline(self) -> dict:
        """
        Kirim beberapa request baseline untuk mendapatkan nilai rata-rata.
        Menggunakan 3 request untuk mengurangi noise.
        """
        samples = []
        for _ in range(3):
            r = self.req.send({})
            if r:
                samples.append(r)
            time.sleep(0.1)

        if not samples:
            return None

        # Ambil rata-rata
        avg_size = sum(s['size'] for s in samples) / len(samples)
        avg_time = sum(s['time'] for s in samples) / len(samples)

        self._baseline = {
            'status'  : samples[0]['status'],
            'size'    : avg_size,
            'size_raw': [s['size'] for s in samples],
            'time'    : avg_time,
            'body'    : samples[0]['body'],
        }

        # Hitung noise tolerance dari variasi baseline
        sizes = [s['size'] for s in samples]
        self._baseline['size_variance'] = max(sizes) - min(sizes)

        return self._baseline

    def compare(self, param_name: str, response: dict) -> dict:
        """
        Bandingkan response dengan baseline menggunakan 5 sinyal.

        Return:
            {
                'found'      : bool,
                'signal'     : str,   # sinyal yang mendeteksi
                'confidence' : str,   # high / medium / low
                'detail'     : str,   # penjelasan
            }
        """
        if not response or not self._baseline:
            return {'found': False, 'signal': None, 'confidence': None, 'detail': ''}

        result = self._check_status(response)
        if result['found']:
            return result

        result = self._check_reflection(param_name, response)
        if result['found']:
            return result

        result = self._check_size(response)
        if result['found']:
            return result

        result = self._check_error(param_name, response)
        if result['found']:
            return result

        result = self._check_time(response)
        if result['found']:
            return result

        return {'found': False, 'signal': None, 'confidence': None, 'detail': ''}

    # ── Sinyal 1: Status code berubah ─────────────────────────────────
    def _check_status(self, resp: dict) -> dict:
        baseline_status = self._baseline['status']
        resp_status     = resp['status']

        if resp_status == baseline_status:
            return {'found': False, 'signal': 'status', 'confidence': None, 'detail': ''}

        # Status berubah = parameter ditemukan (bisa 401, 403, 202, dll)
        return {
            'found'     : True,
            'signal'    : 'status',
            'confidence': 'high',
            'detail'    : f"Status: {baseline_status} → {resp_status}",
        }

    # ── Sinyal 2: Reflection — value parameter muncul di response ─────
    def _check_reflection(self, param_name: str, resp: dict) -> dict:
        """
        Inject nilai unik sebagai value dan cek apakah muncul di response.
        Nilai: getparam_probe_<nama_param>
        """
        probe_val = f'getparam_probe_{param_name}'
        body      = resp.get('body', '')

        if probe_val in body:
            return {
                'found'     : True,
                'signal'    : 'reflection',
                'confidence': 'high',
                'detail'    : f"Value '{probe_val}' reflected in response",
            }
        return {'found': False, 'signal': 'reflection', 'confidence': None, 'detail': ''}

    # ── Sinyal 3: Response size berubah signifikan ────────────────────
    def _check_size(self, resp: dict) -> dict:
        baseline_size = self._baseline['size']
        resp_size     = resp['size']
        variance      = self._baseline.get('size_variance', 0)

        diff     = abs(resp_size - baseline_size)
        diff_pct = diff / max(baseline_size, 1)

        # Abaikan jika diff dalam range noise/variance baseline
        noise_tolerance = max(variance * 2, self.MIN_SIZE_DIFF)

        if diff < noise_tolerance:
            return {'found': False, 'signal': 'size', 'confidence': None, 'detail': ''}

        # Tentukan confidence berdasarkan besarnya perubahan
        if diff_pct >= 0.30 or diff > 500:
            confidence = 'high'
        elif diff_pct >= self.SIZE_THRESHOLD:
            confidence = 'medium'
        else:
            return {'found': False, 'signal': 'size', 'confidence': None, 'detail': ''}

        direction = 'larger' if resp_size > baseline_size else 'smaller'
        return {
            'found'     : True,
            'signal'    : 'size',
            'confidence': confidence,
            'detail'    : f"Size: {int(baseline_size)} → {resp_size} bytes ({direction}, {diff_pct:.1%} diff)",
        }

    # ── Sinyal 4: Error-based — pesan error berubah ───────────────────
    def _check_error(self, param_name: str, resp: dict) -> dict:
        """
        Deteksi perubahan pesan error yang muncul karena parameter diproses.
        Ini menandakan parameter dikenal oleh aplikasi.
        """
        baseline_body = self._baseline['body'].lower()
        resp_body     = resp.get('body', '').lower()

        # Keyword error yang muncul baru di response (tidak ada di baseline)
        error_keywords = [
            'invalid', 'required', 'missing', 'expected',
            'must be', 'cannot be', 'not allowed', 'not found',
            'undefined', 'null', 'error', 'exception',
            'bad request', 'validation', 'unauthorized',
        ]

        new_errors = []
        for kw in error_keywords:
            in_baseline = kw in baseline_body
            in_response = kw in resp_body
            if in_response and not in_baseline:
                new_errors.append(kw)

        if new_errors:
            return {
                'found'     : True,
                'signal'    : 'error',
                'confidence': 'medium',
                'detail'    : f"New error keywords in response: {', '.join(new_errors[:3])}",
            }

        return {'found': False, 'signal': 'error', 'confidence': None, 'detail': ''}

    # ── Sinyal 5: Response time — parameter memicu proses berat ───────
    def _check_time(self, resp: dict) -> dict:
        baseline_time = self._baseline['time']
        resp_time     = resp['time']

        # Hanya laporkan jika 2x lebih lambat DAN minimal 1 detik lebih lambat
        if resp_time > baseline_time * self.TIME_THRESHOLD and resp_time - baseline_time > 1.0:
            return {
                'found'     : True,
                'signal'    : 'time',
                'confidence': 'low',
                'detail'    : f"Response time: {baseline_time:.3f}s → {resp_time:.3f}s",
            }

        return {'found': False, 'signal': 'time', 'confidence': None, 'detail': ''}
