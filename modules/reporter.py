"""
modules/reporter.py
Output Reporter — Simpan hasil ke file teks
"""

from datetime import datetime


class Reporter:

    def __init__(self, url, method, params, output):
        self.url    = url
        self.method = method
        self.params = params
        self.output = output

    def save(self):
        lines = [
            "=" * 55,
            "  GetParam — Hidden Parameter Discovery",
            "=" * 55,
            f"  Target  : {self.url}",
            f"  Method  : {self.method}",
            f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Found   : {len(self.params)} parameter(s)",
            "=" * 55,
            "",
        ]

        for p in self.params:
            lines.append(f"[+] {p['name']}")
            lines.append(f"    URL    : {self.url}?{p['name']}=")
            lines.append(f"    Signal : {p['signal']}")
            lines.append(f"    Conf.  : {p['confidence']}")
            lines.append(f"    Detail : {p['detail']}")
            lines.append("")

        with open(self.output, 'w') as f:
            f.write('\n'.join(lines))
