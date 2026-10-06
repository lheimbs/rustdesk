#!/usr/bin/env python3
"""Summarise a `strace -f -e trace=connect,sendto,sendmsg` log and fail on unexpected network egress.

  tools/egress-analyze.py LOG [--allow ADDR[:PORT] ...]

Loopback is always allowed. Every other destination, and every resolved host name, is reported;
the exit status is 1 if any of them is not covered by --allow (an IP, optionally with :port).
"""
import argparse, re, sys

INET = re.compile(r'\{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
INET6 = re.compile(r'\{sa_family=AF_INET6, sin6_port=htons\((\d+)\), sin6_flowinfo=[^,]*, inet_pton\(AF_INET6, "([^"]+)"')
NAME = re.compile(r'\\"name\\":\\"([^\\"]+)')
DNS_SEND = re.compile(r'sendto\(\d+, "(?:[^"]|\\")*", \d+, [^,]*, \{sa_family=AF_INET6?, sin6?_port=htons\(53\)')


def is_loopback(ip):
    return ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--allow", action="append", default=[])
    a = ap.parse_args()
    allow = set(a.allow)
    dests, names, dns53 = {}, {}, 0
    for line in open(a.log, errors="replace"):
        for rx in (INET, INET6):
            for m in rx.finditer(line):
                port, ip = m.group(1), m.group(2)
                if not is_loopback(ip) and port != "0":
                    dests[(ip, port)] = dests.get((ip, port), 0) + 1
        for n in NAME.findall(line):
            names[n] = names.get(n, 0) + 1
        if DNS_SEND.search(line):
            dns53 += 1
    bad = [(d, c) for d, c in dests.items() if d[0] not in allow and f"{d[0]}:{d[1]}" not in allow]
    print(f"destinations (non-loopback): {len(dests)}   resolved names: {len(names)}   udp/53 queries: {dns53}")
    for (ip, port), c in sorted(dests.items()):
        mark = "ALLOWED" if ((ip, port), c) not in bad else "LEAK"
        print(f"  {mark:7} {ip}:{port}  x{c}")
    for n, c in sorted(names.items()):
        mark = "ALLOWED" if n in allow else "LEAK"
        print(f"  {mark:7} name {n}  x{c}")
        if n not in allow:
            bad.append(((n, "dns"), c))
    if dns53:
        bad.append((("udp/53", "dns"), dns53))
    print("RESULT:", "FAIL (unexpected egress)" if bad else "PASS (no unexpected egress)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
