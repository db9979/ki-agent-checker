"""Promptfoo, das auf eine E-Mail-Eingabe wartet."""

import sys
import time

print("  Email Verification Required", flush=True)
print("  Red team scans require email verification to continue.", flush=True)
print("? Work email: ", end="", flush=True)
sys.stdin.read()
time.sleep(60)
