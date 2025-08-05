#!/usr/bin/env python3
"""
Security Testing Script for EDH Automation HTTP Listener
Tests various security controls and attack vectors
"""

import requests
import json
import time
import sys
import ssl
import socket
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore')

class SecurityTester:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False  # For testing only
        self.test_results = []
        
    def log_test(self, test_name, passed, details=""):
        """Log test results"""
        status = "PASS" if passed else "FAIL"
        result = {
            'test': test_name,
            'status': status,
            'details': details,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.test_results.append(result)
        print(f"[{status}] {test_name}: {details}")
        
    def test_ssl_configuration(self):
        """Test SSL/TLS configuration"""
        print("\n=== Testing SSL/TLS Configuration ===")
        
        try:
            # Test SSL certificate
            hostname = self.base_url.split('://')[1].split(':')[0]
            port = int(self.base_url.split(':')[-1]) if ':' in self.base_url else 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if cert:
                        self.log_test("SSL Certificate Present", True, "Certificate found")
                        
                        # Check certificate expiration
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        
                        if days_until_expiry > 30:
                            self.log_test("SSL Certificate Expiration", True, f"Valid for {days_until_expiry} days")
                        else:
                            self.log_test("SSL Certificate Expiration", False, f"Expires in {days_until_expiry} days")
                    else:
                        self.log_test("SSL Certificate Present", False, "No certificate found")
                        
        except Exception as e:
            self.log_test("SSL Configuration", False, f"SSL test failed: {str(e)}")
    
    def test_authentication(self):
        """Test authentication mechanisms"""
        print("\n=== Testing Authentication ===")
        
        # Test valid authentication
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                self.log_test("Valid Authentication", True, "Authentication successful")
            else:
                self.log_test("Valid Authentication", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Valid Authentication", False, f"Request failed: {str(e)}")
        
        # Test invalid authentication
        try:
            invalid_session = requests.Session()
            invalid_session.auth = ('invalid', 'invalid')
            response = invalid_session.get(f"{self.base_url}/health")
            if response.status_code == 401:
                self.log_test("Invalid Authentication Rejection", True, "Properly rejected invalid credentials")
            else:
                self.log_test("Invalid Authentication Rejection", False, f"Should return 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Authentication Rejection", False, f"Request failed: {str(e)}")
    
    def test_input_validation(self):
        """Test input validation and sanitization"""
        print("\n=== Testing Input Validation ===")
        
        # Test XSS payload
        xss_payload = {
            "dagName": "<script>alert('xss')</script>",
            "environmentName": "DEV"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/edh-spiff/trigger-dag",
                json=xss_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            # Check if response contains sanitized data
            if response.status_code in [400, 500]:  # Should reject invalid input
                self.log_test("XSS Input Rejection", True, "Invalid input properly rejected")
            else:
                response_text = response.text
                if "<script>" in response_text:
                    self.log_test("XSS Input Sanitization", False, "XSS payload not sanitized")
                else:
                    self.log_test("XSS Input Sanitization", True, "XSS payload properly sanitized")
        except Exception as e:
            self.log_test("XSS Input Validation", False, f"Request failed: {str(e)}")
        
        # Test SQL injection payload
        sql_payload = {
            "dagName": "'; DROP TABLE users; --",
            "environmentName": "DEV"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/edh-spiff/trigger-dag",
                json=sql_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code in [400, 500]:
                self.log_test("SQL Injection Rejection", True, "SQL injection attempt properly rejected")
            else:
                self.log_test("SQL Injection Rejection", False, "SQL injection attempt not rejected")
        except Exception as e:
            self.log_test("SQL Injection Validation", False, f"Request failed: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n=== Testing Rate Limiting ===")
        
        # Send multiple requests quickly
        responses = []
        for i in range(15):  # More than the rate limit
            try:
                response = self.session.post(
                    f"{self.base_url}/edh-spiff/trigger-dag",
                    json={"dagName": "test_dag", "environmentName": "DEV"},
                    headers={'Content-Type': 'application/json'}
                )
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay
            except Exception as e:
                responses.append(f"Error: {str(e)}")
        
        # Check if rate limiting is working
        rate_limited = any(status == 429 for status in responses if isinstance(status, int))
        if rate_limited:
            self.log_test("Rate Limiting", True, "Rate limiting is working")
        else:
            self.log_test("Rate Limiting", False, "Rate limiting not detected")
    
    def test_security_headers(self):
        """Test security headers"""
        print("\n=== Testing Security Headers ===")
        
        try:
            response = self.session.get(f"{self.base_url}/health")
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,  # Just check if present
                'Content-Security-Policy': None     # Just check if present
            }
            
            for header, expected_value in security_headers.items():
                if header in headers:
                    if expected_value is None or headers[header] == expected_value:
                        self.log_test(f"Security Header: {header}", True, f"Header present: {headers[header]}")
                    else:
                        self.log_test(f"Security Header: {header}", False, f"Expected {expected_value}, got {headers[header]}")
                else:
                    self.log_test(f"Security Header: {header}", False, "Header missing")
                    
        except Exception as e:
            self.log_test("Security Headers", False, f"Request failed: {str(e)}")
    
    def test_error_handling(self):
        """Test error handling and information disclosure"""
        print("\n=== Testing Error Handling ===")
        
        # Test invalid endpoint
        try:
            response = self.session.get(f"{self.base_url}/invalid-endpoint")
            if response.status_code == 404:
                response_text = response.text.lower()
                if 'traceback' in response_text or 'exception' in response_text:
                    self.log_test("Error Information Disclosure", False, "Sensitive error information exposed")
                else:
                    self.log_test("Error Information Disclosure", True, "No sensitive information in error response")
            else:
                self.log_test("Error Handling", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("Error Handling", False, f"Request failed: {str(e)}")
    
    def test_request_size_limits(self):
        """Test request size limits"""
        print("\n=== Testing Request Size Limits ===")
        
        # Create large payload
        large_payload = {
            "dagName": "A" * 10000,  # Very long DAG name
            "environmentName": "DEV"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/edh-spiff/trigger-dag",
                json=large_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 413:  # Payload Too Large
                self.log_test("Request Size Limits", True, "Large request properly rejected")
            else:
                self.log_test("Request Size Limits", False, f"Large request not rejected, status: {response.status_code}")
        except Exception as e:
            self.log_test("Request Size Limits", False, f"Request failed: {str(e)}")
    
    def test_health_endpoint(self):
        """Test health endpoint security"""
        print("\n=== Testing Health Endpoint ===")
        
        try:
            # Test without authentication
            response = requests.get(f"{self.base_url}/health", verify=False)
            if response.status_code == 200:
                self.log_test("Health Endpoint Public Access", True, "Health endpoint accessible without auth")
            else:
                self.log_test("Health Endpoint Public Access", False, f"Health endpoint requires auth: {response.status_code}")
                
            # Check response content
            try:
                data = response.json()
                sensitive_keys = ['password', 'secret', 'key', 'token']
                has_sensitive_data = any(key in str(data).lower() for key in sensitive_keys)
                
                if has_sensitive_data:
                    self.log_test("Health Endpoint Information Disclosure", False, "Sensitive information in health response")
                else:
                    self.log_test("Health Endpoint Information Disclosure", True, "No sensitive information exposed")
            except json.JSONDecodeError:
                self.log_test("Health Endpoint Response Format", False, "Health endpoint not returning JSON")
                
        except Exception as e:
            self.log_test("Health Endpoint", False, f"Request failed: {str(e)}")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("Starting Security Tests for EDH Automation HTTP Listener")
        print("=" * 60)
        
        self.test_ssl_configuration()
        self.test_authentication()
        self.test_input_validation()
        self.test_rate_limiting()
        self.test_security_headers()
        self.test_error_handling()
        self.test_request_size_limits()
        self.test_health_endpoint()
        
        # Generate summary
        print("\n" + "=" * 60)
        print("SECURITY TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results if result['status'] == 'PASS')
        failed = sum(1 for result in self.test_results if result['status'] == 'FAIL')
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if failed > 0:
            print("\nFAILED TESTS:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test']}: {result['details']}")
        
        # Save results to file
        with open('security_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\nDetailed results saved to: security_test_results.json")
        
        return failed == 0

def main():
    if len(sys.argv) != 4:
        print("Usage: python security_test.py <base_url> <username> <password>")
        print("Example: python security_test.py https://localhost:8982 myuser mypass")
        sys.exit(1)
    
    base_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    tester = SecurityTester(base_url, username, password)
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ All security tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some security tests failed. Review the results above.")
        sys.exit(1)

if __name__ == "__main__":
    main()