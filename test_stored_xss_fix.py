#!/usr/bin/env python3
"""
Test Script for Stored XSS Fix
Validates that the Checkmarx Stored XSS vulnerability is properly addressed
"""

import json
import html
import re
from typing import Any, Dict

def sanitize_external_api_response(data: Any, max_length: int = 1000) -> Any:
    """
    Comprehensive sanitization for external API responses to prevent Stored XSS.
    """
    if data is None:
        return None
    
    if isinstance(data, str):
        # HTML escape and limit length
        sanitized = html.escape(data.strip())
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        return sanitized
    
    if isinstance(data, (int, float, bool)):
        # Convert to string and escape for safety
        return html.escape(str(data))
    
    if isinstance(data, dict):
        sanitized_dict = {}
        for key, value in data.items():
            # Sanitize keys as well
            safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
            sanitized_dict[safe_key] = sanitize_external_api_response(value, max_length)
        return sanitized_dict
    
    if isinstance(data, list):
        return [sanitize_external_api_response(item, max_length) for item in data]
    
    # For any other types, convert to string and escape
    return html.escape(str(data))

def validate_airflow_response_structure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize Airflow API response structure.
    """
    if not isinstance(data, dict):
        return {'error': 'Invalid response format'}
    
    # Define expected fields from Airflow API
    expected_fields = {
        'dag_run_id': str,
        'dag_id': str,
        'logical_date': str,
        'execution_date': str,
        'start_date': str,
        'end_date': str,
        'state': str,
        'external_trigger': bool,
        'conf': dict
    }
    
    sanitized_response = {}
    
    for field, expected_type in expected_fields.items():
        if field in data:
            value = data[field]
            
            # Type validation
            if isinstance(value, expected_type):
                # Sanitize the value
                sanitized_value = sanitize_external_api_response(value)
                sanitized_response[field] = sanitized_value
            else:
                # Convert to expected type if possible
                try:
                    converted_value = expected_type(value)
                    sanitized_response[field] = sanitize_external_api_response(converted_value)
                except (ValueError, TypeError):
                    # Skip invalid fields
                    continue
    
    return sanitized_response

def test_xss_payloads():
    """Test various XSS payloads to ensure they are properly sanitized"""
    
    print("Testing Stored XSS Fix")
    print("=" * 50)
    
    # Test cases with malicious payloads
    test_cases = [
        {
            "name": "Basic Script Tag",
            "input": {
                "dag_run_id": "test_run_123<script>alert('xss')</script>",
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "running"
            }
        },
        {
            "name": "Event Handler",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag<img src=x onerror=alert('xss')>",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "running"
            }
        },
        {
            "name": "JavaScript Protocol",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag",
                "execution_date": "javascript:alert('xss')",
                "state": "running"
            }
        },
        {
            "name": "Nested Script Tags",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "<script><script>alert('xss')</script></script>"
            }
        },
        {
            "name": "Unicode XSS",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "&#x3C;script&#x3E;alert('xss')&#x3C;/script&#x3E;"
            }
        },
        {
            "name": "Complex Payload",
            "input": {
                "dag_run_id": "test_run_123<script>alert('xss')</script>",
                "dag_id": "test_dag<img src=x onerror=alert('xss')>",
                "execution_date": "javascript:alert('xss')",
                "state": "<script><script>alert('xss')</script></script>",
                "conf": {
                    "malicious_key<script>alert('xss')</script>": "<script>alert('xss')</script>",
                    "normal_key": "normal_value"
                }
            }
        }
    ]
    
    all_tests_passed = True
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case['name']}")
        print("-" * 30)
        
        # Original malicious data
        original_data = test_case['input']
        print("Original data:")
        print(json.dumps(original_data, indent=2))
        
        # Apply sanitization
        sanitized_data = sanitize_external_api_response(original_data)
        print("\nSanitized data:")
        print(json.dumps(sanitized_data, indent=2))
        
        # Validate structure
        validated_data = validate_airflow_response_structure(original_data)
        print("\nValidated data:")
        print(json.dumps(validated_data, indent=2))
        
        # Check if any script tags remain
        data_str = json.dumps(sanitized_data)
        if "<script>" in data_str.lower() or "javascript:" in data_str.lower():
            print("❌ FAIL: Script tags or JavaScript protocol found in sanitized data")
            all_tests_passed = False
        else:
            print("✅ PASS: No script tags found in sanitized data")
        
        # Check if HTML entities are properly escaped
        if "&lt;" in data_str and "&gt;" in data_str:
            print("✅ PASS: HTML entities properly escaped")
        else:
            print("⚠️  WARNING: HTML entities may not be properly escaped")
    
    return all_tests_passed

def test_edge_cases():
    """Test edge cases and boundary conditions"""
    
    print("\n\nTesting Edge Cases")
    print("=" * 50)
    
    edge_cases = [
        {
            "name": "Null Values",
            "input": {
                "dag_run_id": None,
                "dag_id": "",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": None
            }
        },
        {
            "name": "Very Long Strings",
            "input": {
                "dag_run_id": "A" * 2000,  # Very long string
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "running"
            }
        },
        {
            "name": "Special Characters",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "running",
                "conf": {
                    "key with spaces": "value with & < > \" ' characters",
                    "key-with-dashes": "value-with-dashes",
                    "key_with_underscores": "value_with_underscores"
                }
            }
        },
        {
            "name": "Nested Structures",
            "input": {
                "dag_run_id": "test_run_123",
                "dag_id": "test_dag",
                "execution_date": "2025-01-01T00:00:00Z",
                "state": "running",
                "conf": {
                    "nested": {
                        "level1": {
                            "level2": "<script>alert('xss')</script>"
                        }
                    }
                }
            }
        }
    ]
    
    all_edge_tests_passed = True
    
    for i, test_case in enumerate(edge_cases, 1):
        print(f"\nEdge Case {i}: {test_case['name']}")
        print("-" * 30)
        
        original_data = test_case['input']
        sanitized_data = sanitize_external_api_response(original_data)
        
        print("Original data:")
        print(json.dumps(original_data, indent=2))
        
        print("\nSanitized data:")
        print(json.dumps(sanitized_data, indent=2))
        
        # Check for script tags
        data_str = json.dumps(sanitized_data)
        if "<script>" in data_str.lower():
            print("❌ FAIL: Script tags found in sanitized data")
            all_edge_tests_passed = False
        else:
            print("✅ PASS: No script tags found")
        
        # Check length limits
        for key, value in sanitized_data.items():
            if isinstance(value, str) and len(value) > 1000:
                print(f"❌ FAIL: String too long for key '{key}': {len(value)} characters")
                all_edge_tests_passed = False
            else:
                print(f"✅ PASS: String length OK for key '{key}'")
    
    return all_edge_tests_passed

def test_performance():
    """Test performance impact of sanitization"""
    
    print("\n\nTesting Performance")
    print("=" * 50)
    
    import time
    
    # Create large test data
    large_data = {
        "dag_run_id": "test_run_123",
        "dag_id": "test_dag",
        "execution_date": "2025-01-01T00:00:00Z",
        "state": "running",
        "conf": {}
    }
    
    # Add 1000 nested items
    for i in range(1000):
        large_data["conf"][f"key_{i}"] = f"value_{i}_with_some_content"
    
    print(f"Testing with data containing {len(large_data['conf'])} items")
    
    # Measure sanitization time
    start_time = time.time()
    sanitized_data = sanitize_external_api_response(large_data)
    end_time = time.time()
    
    sanitization_time = end_time - start_time
    print(f"Sanitization time: {sanitization_time:.4f} seconds")
    
    if sanitization_time < 1.0:  # Should be under 1 second
        print("✅ PASS: Performance acceptable")
        return True
    else:
        print("❌ FAIL: Performance too slow")
        return False

def main():
    """Run all tests"""
    
    print("Stored XSS Fix Validation Tests")
    print("=" * 60)
    
    # Run XSS payload tests
    xss_tests_passed = test_xss_payloads()
    
    # Run edge case tests
    edge_tests_passed = test_edge_cases()
    
    # Run performance tests
    performance_passed = test_performance()
    
    # Summary
    print("\n\nTest Summary")
    print("=" * 60)
    print(f"XSS Payload Tests: {'✅ PASSED' if xss_tests_passed else '❌ FAILED'}")
    print(f"Edge Case Tests: {'✅ PASSED' if edge_tests_passed else '❌ FAILED'}")
    print(f"Performance Tests: {'✅ PASSED' if performance_passed else '❌ FAILED'}")
    
    overall_result = xss_tests_passed and edge_tests_passed and performance_passed
    
    if overall_result:
        print("\n🎉 ALL TESTS PASSED! The Stored XSS fix is working correctly.")
        print("✅ Checkmarx vulnerability should be resolved.")
        return True
    else:
        print("\n❌ SOME TESTS FAILED! Review the results above.")
        print("⚠️  The Stored XSS fix may need additional work.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)