import json
import sys
from pathlib import Path

from app.scanner import full_scan


if len(sys.argv) != 2:
    print("Usage: python test_scanner.py yourdomain.com")
    sys.exit(1)


domain = sys.argv[1].strip().lower()

print(f"Starting scan for: {domain}")

result = full_scan(domain)

print("\nScan summary:")
print(json.dumps(result["summary"], indent=2))

output_dir = Path("../data/outputs")
output_dir.mkdir(parents=True, exist_ok=True)

output_file = output_dir / f"{domain}-scan.json"

with open(output_file, "w") as f:
    json.dump(result, f, indent=2)

print(f"\nFull output saved to: {output_file}")