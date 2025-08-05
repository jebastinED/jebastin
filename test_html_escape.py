#!/usr/bin/env python3

import html

test_string = "aaaa`-prompt(1)-`1<script>&\"'"
result = html.escape(test_string)
result_with_quotes = html.escape(test_string, quote=True)

print(f"Original: {test_string}")
print(f"html.escape(): {result}")
print(f"html.escape(quote=True): {result_with_quotes}")

print("\nCharacters that html.escape() handles:")
print(f"< becomes: {html.escape('<')}")
print(f"> becomes: {html.escape('>')}")
print(f"& becomes: {html.escape('&')}")
print(f"\" becomes: {html.escape('\"', quote=True)}")
print(f"' becomes: {html.escape(chr(39), quote=True)}")
print(f"` becomes: {html.escape('`')}")  # This won't change