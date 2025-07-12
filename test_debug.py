#!/usr/bin/env python3

import sys
sys.path.insert(0, "src")

from syft_perm._impl import _doublestar_match

# Test the specific failing case
test_cases = [
    ("docs/**", "docs/readme.md"),
    ("**/docs/**", "docs/readme.md"),
    ("**/docs/**", "src/docs/guide.md"), 
    ("**", "docs/readme.md"),
]

for pat, pth in test_cases:
    result = _doublestar_match(pat, pth)
    print(f"Pattern: '{pat}' Path: '{pth}' Result: {result}")