#!/usr/bin/env python3
"""
 ██████╗ ███████╗████████╗██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗
██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║
██║  ███╗█████╗     ██║   ██████╔╝███████║██████╔╝███████║██╔████╔██║
██║   ██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║
╚██████╔╝███████╗   ██║   ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝

  Hidden Parameter Discovery Tool
  Version  : 1.0.0
  Author   : tanzz1337
  GitHub   : https://github.com/tanzz1337/getparam
  License  : MIT

  For authorized security testing and bug bounty only.
"""

import sys
import os
import argparse
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.requester   import Requester
from modules.waf         import WAFDetector
from modules.ratelimit   import RateLimitBypass
from modules.detector    import Detector
from modules.analyzer    import Analyzer
from modules.reporter    import Reporter

# ── Color codes ──────────────────────────────────────────────────────────────
R  = '\033[0m'       # reset
G  = '\033[92m'      # green
Y  = '\033[93m'      # yellow
C  = '\033[96m'      # cyan
RD = '\033[91m'      # red
B  = '\033[1m'       # bold
DM = '\033[2m'       # dim

BANNER = f"""
{G}{B}
 ██████╗ ███████╗████████╗██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗
██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║
██║  ███╗█████╗     ██║   ██████╔╝███████║██████╔╝███████║██╔████╔██║
██║   ██║██╔══╝     ██║   ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║
╚██████╔╝███████╗   ██║   ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║
 ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
{R}
  {C}Hidden Parameter Discovery Tool{R}  {DM}v1.0.0 by tanzz1337{R}
"""


def print_info(msg):   print(f"  {C}[*]{R} {msg}")
def print_found(msg):  print(f"  {G}{B}[+]{R} {msg}")
def print_warn(msg):   print(f"  {Y}[!]{R} {msg}")
def print_error(msg):  print(f"  {RD}[-]{R} {msg}")
def print_dim(msg):    print(f"  {DM}    {msg}{R}")


def parse_headers(header_list):
    """Parse -H 'Key: Value' ke dict"""
    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ':' in h:
            key, val = h.split(':', 1)
            headers[key.strip()] = val.strip()
    return headers


def load_wordlist(path):
    """Load wordlist dari file, strip whitespace dan skip komentar"""
    if not os.path.exists(path):
        print_error(f"Wordlist tidak ditemukan: {path}")
        sys.exit(1)
    with open(path, 'r', errors='ignore') as f:
        words = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith('#')
        ]
    return list(dict.fromkeys(words))   # deduplicate, preserve order


def get_default_wordlist():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, 'wordlists', 'common.txt')


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog='getparam',
        description='GetParam — Hidden Parameter Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python getparam.py -u https://example.com/profile
  python getparam.py -u https://example.com/api -m POST
  python getparam.py -u https://example.com/api -m JSON
  python getparam.py -u https://example.com/search -w wordlists/api.txt
  python getparam.py -u https://example.com/api -H "Authorization: Bearer TOKEN"
  python getparam.py -u https://example.com -t 20 --delay 0.5
        """
    )

    # Required
    parser.add_argument('-u', '--url',
                        required=True,
                        help='Target URL')

    # Method
    parser.add_argument('-m', '--method',
                        default='GET',
                        choices=['GET', 'POST', 'JSON', 'HEADER'],
                        help='HTTP method (default: GET)')

    # Wordlist
    parser.add_argument('-w', '--wordlist',
                        default=None,
                        help='Path ke wordlist custom (default: wordlists/common.txt)')

    # Threads
    parser.add_argument('-t', '--threads',
                        type=int,
                        default=10,
                        help='Jumlah thread paralel (default: 10)')

    # Chunk size
    parser.add_argument('--chunk',
                        type=int,
                        default=50,
                        help='Parameter per request chunk (default: 50)')

    # Custom headers
    parser.add_argument('-H', '--header',
                        action='append',
                        dest='headers',
                        help='Custom header: -H "Key: Value" (bisa diulang)')

    # Cookies
    parser.add_argument('-c', '--cookie',
                        default=None,
                        help='Cookie string: "name=val; name2=val2"')

    # Proxy
    parser.add_argument('--proxy',
                        default=None,
                        help='Proxy URL: http://127.0.0.1:8080')

    # Delay
    parser.add_argument('--delay',
                        type=float,
                        default=0,
                        help='Delay antar request (detik, default: 0)')

    # Timeout
    parser.add_argument('--timeout',
                        type=int,
                        default=10,
                        help='Request timeout detik (default: 10)')

    # Rate limit bypass
    parser.add_argument('--no-bypass',
                        action='store_true',
                        help='Matikan rate limit bypass (default: ON)')

    # WAF check
    parser.add_argument('--no-waf',
                        action='store_true',
                        help='Skip WAF detection')

    # Output
    parser.add_argument('-o', '--output',
                        default=None,
                        help='Simpan hasil ke file (misal: hasil.txt)')

    # Verbose
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Tampilkan detail setiap request')

    args = parser.parse_args()

    # ── Normalize URL ─────────────────────────────────────────────────
    url = args.url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # ── Load wordlist ─────────────────────────────────────────────────
    wordlist_path = args.wordlist or get_default_wordlist()
    print_info(f"Loading wordlist: {wordlist_path}")
    wordlist = load_wordlist(wordlist_path)
    print_info(f"Wordlist loaded  : {G}{len(wordlist):,}{R} parameter")

    # ── Parse headers dan cookie ──────────────────────────────────────
    custom_headers = parse_headers(args.headers)
    if args.cookie:
        custom_headers['Cookie'] = args.cookie

    # ── Inisialisasi komponen ─────────────────────────────────────────
    bypass  = RateLimitBypass(enabled=not args.no_bypass)
    req     = Requester(
        url          = url,
        method       = args.method.upper(),
        headers      = custom_headers,
        proxy        = args.proxy,
        timeout      = args.timeout,
        delay        = args.delay,
        bypass       = bypass,
        verbose      = args.verbose,
    )

    # ── Info scan ─────────────────────────────────────────────────────
    print()
    print_info(f"Target   : {C}{url}{R}")
    print_info(f"Method   : {C}{args.method.upper()}{R}")
    print_info(f"Threads  : {C}{args.threads}{R}")
    print_info(f"Chunk    : {C}{args.chunk}{R} param/request")
    print_info(f"Bypass   : {G}ON{R}" if not args.no_bypass else f"Bypass   : {Y}OFF{R}")

    # ── WAF Detection ─────────────────────────────────────────────────
    waf_name = None
    if not args.no_waf:
        print()
        print_info("Detecting WAF...")
        waf      = WAFDetector(req)
        waf_name = waf.detect()
        if waf_name:
            print_warn(f"WAF detected     : {RD}{waf_name}{R}")
            print_warn("Adapting strategy for WAF bypass...")
            bypass.set_waf_mode(waf_name)
        else:
            print_info(f"WAF              : {G}None detected{R}")

    # ── Baseline request ──────────────────────────────────────────────
    print()
    print_info("Sending baseline request...")
    analyzer = Analyzer(req, verbose=args.verbose)
    baseline = analyzer.get_baseline()

    if baseline is None:
        print_error("Target tidak bisa dijangkau. Periksa URL dan koneksi.")
        sys.exit(1)

    print_info(f"Baseline status  : {C}{baseline['status']}{R}")
    print_info(f"Baseline size    : {C}{baseline['size']:,}{R} bytes")
    print_info(f"Baseline time    : {C}{baseline['time']:.3f}s{R}")

    # ── Start discovery ───────────────────────────────────────────────
    print()
    print_info(f"Starting parameter discovery ({len(wordlist):,} params)...")
    print_dim("─" * 55)

    start_time = time.time()

    detector = Detector(
        analyzer   = analyzer,
        wordlist   = wordlist,
        threads    = args.threads,
        chunk_size = args.chunk,
        verbose    = args.verbose,
    )

    found_params = detector.run()

    elapsed = time.time() - start_time

    # ── Hasil ─────────────────────────────────────────────────────────
    print()
    print_dim("─" * 55)
    print()

    if found_params:
        print(f"  {G}{B}Found {len(found_params)} parameter(s):{R}\n")
        for p in found_params:
            signal_label = {
                'size'       : f"{C}size_change{R}",
                'status'     : f"{RD}status_change{R}",
                'reflection' : f"{Y}reflection{R}",
                'error'      : f"{Y}error_based{R}",
                'time'       : f"{DM}time_based{R}",
            }.get(p['signal'], p['signal'])

            print(f"  {G}{B}[+]{R} {B}{p['name']:<20}{R}  "
                  f"→  {url.split('?')[0]}?{p['name']}=  "
                  f"  [{signal_label}]")
    else:
        print_warn("Tidak ada parameter yang ditemukan.")
        print_dim("Coba wordlist lain atau method yang berbeda.")

    # ── Summary ───────────────────────────────────────────────────────
    print()
    print_dim("─" * 55)
    print_info(
        f"Done — {G}{len(found_params)} found{R} | "
        f"{len(wordlist):,} tested | "
        f"{elapsed:.1f}s"
    )
    if waf_name:
        print_info(f"WAF bypass used  : {waf_name}")

    # ── Save output ───────────────────────────────────────────────────
    if args.output and found_params:
        reporter = Reporter(
            url    = url,
            method = args.method,
            params = found_params,
            output = args.output,
        )
        reporter.save()
        print_info(f"Saved to         : {args.output}")

    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}[!]{R} Interrupted by user.\n")
        sys.exit(0)
