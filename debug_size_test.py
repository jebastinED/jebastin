#!/usr/bin/env python3
"""Debug script to check size limiting"""

import html
import re

def _validate_field_value(value, field_name):
    if value is None:
        return None
    
    str_value = str(value)
    print(f"Original length: {len(str_value)}")
    
    if len(str_value) > 1000:
        str_value = str_value[:1000]
        print(f"After size limiting: {len(str_value)}")
    
    escaped_value = html.escape(str_value)
    print(f"After HTML escape: {len(escaped_value)}")
    
    if field_name in ['dagName', 'environmentName']:
        if re.match(r'^[a-zA-Z0-9_\-\.]+$', escaped_value):
            result = escaped_value
        else:
            result = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', escaped_value)
            print(f"After whitelist sanitization: {len(result)}")
    else:
        result = escaped_value
    
    return result

if __name__ == "__main__":
    # Test with oversized XSS input
    large_xss_input = '<script>alert(1)</script>' + 'A' * 2000
    print(f"Testing with input of length: {len(large_xss_input)}")
    
    result = _validate_field_value(large_xss_input, 'dagName')
    
    print(f"Final result length: {len(result)}")
    print(f"Final result (first 100 chars): {result[:100]}")
    
    # Check if dangerous content is present
    print(f"Contains '<script>': {'<script>' in result}")
    print(f"Result <= 1000 chars: {len(result) <= 1000}")