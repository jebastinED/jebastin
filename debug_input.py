#!/usr/bin/env python3
"""
Debug script to test the trigger-dag endpoint with different input formats
"""

import requests
import json

# Test different input formats
test_cases = [
    {
        "name": "Valid single object",
        "data": {
            "dagName": "test_dag",
            "environmentName": "DEV"
        }
    },
    {
        "name": "Valid array of objects",
        "data": [
            {
                "dagName": "test_dag1",
                "environmentName": "DEV"
            },
            {
                "dagName": "test_dag2", 
                "environmentName": "QA"
            }
        ]
    },
    {
        "name": "Invalid - string instead of object",
        "data": "test_dag"
    },
    {
        "name": "Invalid - array with string",
        "data": ["test_dag", "DEV"]
    },
    {
        "name": "Invalid - array with mixed types",
        "data": [
            {
                "dagName": "test_dag1",
                "environmentName": "DEV"
            },
            "invalid_string"
        ]
    }
]

def test_endpoint(test_case):
    """Test the trigger-dag endpoint with different input formats"""
    print(f"\n=== Testing: {test_case['name']} ===")
    print(f"Input data: {json.dumps(test_case['data'], indent=2)}")
    
    try:
        # Replace with your actual endpoint URL and credentials
        url = "https://your-server:8982/edh-spiff/trigger-dag"
        auth = ("your_username", "your_password")
        
        response = requests.post(
            url,
            json=test_case['data'],
            auth=auth,
            verify=False  # Only for testing
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    print("Debug script for trigger-dag endpoint")
    print("Update the URL and credentials before running")
    
    # Uncomment to run tests
    # for test_case in test_cases:
    #     test_endpoint(test_case)