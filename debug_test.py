#!/usr/bin/env python3
"""Debug script to check sanitization output"""

import html
import re
import json

def _deep_html_escape_json_data(data):
    if isinstance(data, str):
        return html.escape(data)
    if isinstance(data, list):
        return [_deep_html_escape_json_data(item) for item in data]
    if isinstance(data, dict):
        return {key: _deep_html_escape_json_data(value) for key, value in data.items()}
    return data

def _validate_field_value(value, field_name):
    if value is None:
        return None
    
    str_value = str(value)
    
    if len(str_value) > 1000:
        str_value = str_value[:1000]
    
    escaped_value = html.escape(str_value)
    
    if field_name in ['dagName', 'environmentName']:
        if re.match(r'^[a-zA-Z0-9_\-\.]+$', escaped_value):
            return escaped_value
        else:
            return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', escaped_value)
    
    return escaped_value

def _validate_and_sanitize_user_input(user_input):
    if user_input is None:
        return None
    
    sanitized_input = _deep_html_escape_json_data(user_input)
    
    if isinstance(sanitized_input, dict):
        validated_dict = {}
        for key, value in sanitized_input.items():
            if isinstance(key, str) and re.match(r'^[a-zA-Z0-9_\-\.]+$', key):
                validated_dict[key] = _validate_field_value(value, key)
            else:
                safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
                validated_dict[safe_key] = _validate_field_value(value, safe_key)
        return validated_dict
    
    elif isinstance(sanitized_input, list):
        return [_validate_field_value(item, 'list_item') for item in sanitized_input]
    
    elif isinstance(sanitized_input, str):
        return _validate_field_value(sanitized_input, 'string_input')
    
    else:
        return html.escape(str(sanitized_input))

if __name__ == "__main__":
    test_payload = {
        'dagName': '<script>fetch("/steal", {method: "POST", body: document.cookie})</script>',
        'environmentName': '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">'
    }
    
    print("Original payload:")
    print(json.dumps(test_payload, indent=2))
    
    print("\nAfter _validate_and_sanitize_user_input:")
    step1 = _validate_and_sanitize_user_input(test_payload)
    print(json.dumps(step1, indent=2))
    
    print("\nAfter _deep_html_escape_json_data:")
    step2 = _deep_html_escape_json_data(step1)
    print(json.dumps(step2, indent=2))
    
    print("\nFinal JSON string:")
    final_str = json.dumps(step2)
    print(final_str)
    
    print("\nChecking for dangerous patterns:")
    dangerous_patterns = ['<script', 'onerror=', 'onload=']
    for pattern in dangerous_patterns:
        found = pattern in final_str
        print(f"  {pattern}: {'❌ FOUND' if found else '✅ NOT FOUND'}")
    
    print("\nChecking for escaped patterns:")
    escaped_patterns = ['&lt;script&gt;', '&lt;img', '&quot;', '&amp;lt;', '&amp;gt;']
    for pattern in escaped_patterns:
        found = pattern in final_str
        print(f"  {pattern}: {'✅ FOUND' if found else '❌ NOT FOUND'}")