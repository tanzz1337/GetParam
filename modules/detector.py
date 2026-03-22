"""
modules/detector.py
Discovery Engine — Inti dari GetParam
Fuzzing parameter dengan multi-thread dan chunk strategy
"""

import threading
from typing import List, Dict


class Detector:

    def __init__(self, analyzer, wordlist: list,
                 threads: int = 10, chunk_size: int = 50,
                 verbose: bool = False):
        self.analyzer   = analyzer
        self.wordlist   = wordlist
        self.threads    = threads
        self.chunk_size = chunk_size
        self.verbose    = verbose

        self._found   = []
        self._tested  = 0
        self._lock    = threading.Lock()

    def run(self) -> List[Dict]:
        """
        Jalankan discovery dalam dua fase:

        Fase 1 — Chunk scanning:
          Kirim N parameter sekaligus dalam satu request.
          Jika chunk menghasilkan perbedaan, lanjut ke fase 2.

        Fase 2 — Individual confirmation:
          Test satu per satu untuk konfirmasi dan identifikasi
          parameter mana yang sebenarnya valid.
        """
        # Fase 1: chunk scan untuk menemukan chunk yang "aktif"
        suspicious_chunks = self._phase1_chunk_scan()

        if not suspicious_chunks:
            # Tidak ada chunk aktif — scan individual semua (fallback)
            all_params = self.wordlist
        else:
            # Kumpulkan semua param dari chunk yang aktif
            all_params = []
            for chunk in suspicious_chunks:
                all_params.extend(chunk)
            # Deduplicate
            all_params = list(dict.fromkeys(all_params))

        # Fase 2: individual confirmation
        self._phase2_individual(all_params)

        return self._found

    # ── Fase 1: Chunk scan ────────────────────────────────────────────
    def _phase1_chunk_scan(self) -> list:
        """
        Bagi wordlist ke chunks, kirim semua param dalam chunk sekaligus.
        Lebih cepat tapi hanya untuk mengidentifikasi chunk yang aktif.
        """
        chunks     = self._split_chunks(self.wordlist, self.chunk_size)
        suspicious = []
        sem        = threading.Semaphore(self.threads)
        results    = {}
        lock       = threading.Lock()

        def scan_chunk(idx, chunk):
            sem.acquire()
            try:
                # Buat params dict: {param: probe_value}
                params = {p: f'getparam_probe_{p}' for p in chunk}
                resp   = self.analyzer.req.send(params)
                if resp is None:
                    return

                # Cek apakah ada sinyal dari chunk ini
                # Gunakan analisis size dan status saja di fase 1
                result = self.analyzer.compare('_chunk_', resp)

                # Untuk reflection, cek apakah ada probe value di response
                body = resp.get('body', '')
                has_reflection = any(
                    f'getparam_probe_{p}' in body for p in chunk
                )

                is_suspicious = result['found'] or has_reflection

                with lock:
                    results[idx] = (chunk, is_suspicious)
                    self._tested += len(chunk)
            finally:
                sem.release()

        threads = []
        for i, chunk in enumerate(chunks):
            t = threading.Thread(target=scan_chunk, args=(i, chunk))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Kumpulkan chunks yang suspicious
        for idx in sorted(results.keys()):
            chunk, is_sus = results[idx]
            if is_sus:
                suspicious.append(chunk)

        return suspicious

    # ── Fase 2: Individual confirmation ──────────────────────────────
    def _phase2_individual(self, params_to_test: list):
        """
        Test setiap parameter secara individual.
        Ini yang memberikan hasil akurat dan signal detection.
        """
        sem  = threading.Semaphore(self.threads)
        lock = threading.Lock()

        def test_param(param):
            sem.acquire()
            try:
                # Kirim satu parameter dengan probe value
                probe = {param: f'getparam_probe_{param}'}
                resp  = self.analyzer.req.send(probe)

                if resp is None:
                    return

                # Cek rate limiting
                if resp['status'] == 429:
                    if self.analyzer.req.bypass:
                        self.analyzer.req.bypass.on_rate_limited()
                    # Retry sekali setelah backoff
                    resp = self.analyzer.req.send(probe)
                    if resp is None:
                        return

                result = self.analyzer.compare(param, resp)

                if result['found']:
                    if self.analyzer.req.bypass:
                        self.analyzer.req.bypass.on_success()

                    found_entry = {
                        'name'      : param,
                        'signal'    : result['signal'],
                        'confidence': result['confidence'],
                        'detail'    : result['detail'],
                        'status'    : resp['status'],
                    }

                    with lock:
                        # Cek duplikat
                        existing = [f['name'] for f in self._found]
                        if param not in existing:
                            self._found.append(found_entry)
                            self._print_found(found_entry)

                if self.verbose:
                    with lock:
                        print(f"      [{resp['status']}] {param:<25} "
                              f"size={resp['size']}  "
                              f"signal={'YES:'+result['signal'] if result['found'] else 'no'}")

            finally:
                sem.release()

        threads = []
        for param in params_to_test:
            t = threading.Thread(target=test_param, args=(param,))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def _split_chunks(self, lst: list, size: int) -> list:
        """Bagi list ke sub-list dengan ukuran tertentu"""
        return [lst[i:i + size] for i in range(0, len(lst), size)]

    def _print_found(self, entry: dict):
        G  = '\033[92m'
        B  = '\033[1m'
        R  = '\033[0m'
        C  = '\033[96m'
        Y  = '\033[93m'
        RD = '\033[91m'
        DM = '\033[2m'

        signal_colored = {
            'size'      : f"{C}size_change{R}",
            'status'    : f"{RD}status_change{R}",
            'reflection': f"{Y}reflection{R}",
            'error'     : f"{Y}error_based{R}",
            'time'      : f"{DM}time_based{R}",
        }.get(entry['signal'], entry['signal'])

        print(f"  {G}{B}[+]{R} {B}{entry['name']:<20}{R}  "
              f"[{signal_colored}]  "
              f"{DM}{entry['detail']}{R}")
