"""garak, das eine Option ablehnt und trotzdem mit 0 endet (wie garak bei ungültigen Probes)."""

import sys

if sys.argv[1:] == ["--version"]:
    print("garak LLM vulnerability scanner v0.17.1")
    sys.exit(0)
print("garak LLM vulnerability scanner v0.17.1", flush=True)
print("❌ Unknown probes: promptinject.Nope", flush=True)
