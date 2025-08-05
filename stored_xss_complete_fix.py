#!/usr/bin/env python3
"""
Complete Stored XSS Fix for EDH Automation HTTP Listener
Addresses Checkmarx Stored XSS vulnerability with comprehensive security measures

Problem:
- External API data from Airflow REST API (line 365) contains untrusted data
- This data flows through to the response (line 484) without proper sanitization
- Could enable Stored XSS attacks if malicious data is stored in Airflow

Solution:
- Implement context-sensitive encoding for all dynamic data
- Add comprehensive input validation with whitelist approach
- Implement Content Security Policy (CSP)
- Set proper HTTP headers and cookie flags
- Use platform-provided encoding functionality
"""

import html
import json
import re
import base64
from typing import Any, Dict, List, Union, Optional
from urllib.parse import quote, quote_plus

# Import Flask components
from flask import Flask, request, jsonify, make_response
from marshmallow import Schema, fields, ValidationError

class XSSProtection:
    """
    Comprehensive XSS protection class implementing all recommended security measures
    """
    
    @staticmethod
    def html_encode(data: Any, max_length: int = 1000) -> Any:
        """
        HTML encode data for safe embedding in HTML content.
        Uses platform-provided encoding functionality (html.escape).
        
        Args:
            data: Data to encode
            max_length: Maximum length for string values
            
        Returns:
            HTML-encoded data safe for HTML context
        """
        if data is None:
            return None
        
        if isinstance(data, str):
            # HTML encode and limit length
            encoded = html.escape(data.strip())
            if len(encoded) > max_length:
                encoded = encoded[:max_length]
            return encoded
        
        if isinstance(data, (int, float, bool)):
            # Convert to string and HTML encode
            return html.escape(str(data))
        
        if isinstance(data, dict):
            encoded_dict = {}
            for key, value in data.items():
                # Encode keys as well
                safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
                encoded_dict[safe_key] = XSSProtection.html_encode(value, max_length)
            return encoded_dict
        
        if isinstance(data, list):
            return [XSSProtection.html_encode(item, max_length) for item in data]
        
        # For any other types, convert to string and encode
        return html.escape(str(data))
    
    @staticmethod
    def html_attribute_encode(data: str) -> str:
        """
        HTML Attribute encode data for safe embedding in HTML attribute values.
        
        Args:
            data: String data to encode
            
        Returns:
            HTML attribute-encoded string
        """
        if not isinstance(data, str):
            data = str(data)
        
        # HTML attribute encoding
        encoded = html.escape(data, quote=True)
        return encoded
    
    @staticmethod
    def javascript_encode(data: str) -> str:
        """
        JavaScript encode data for safe embedding in JavaScript context.
        
        Args:
            data: String data to encode
            
        Returns:
            JavaScript-encoded string
        """
        if not isinstance(data, str):
            data = str(data)
        
        # JavaScript encoding - escape special characters
        encoded = data.replace('\\', '\\\\')
        encoded = encoded.replace('"', '\\"')
        encoded = encoded.replace("'", "\\'")
        encoded = encoded.replace('\n', '\\n')
        encoded = encoded.replace('\r', '\\r')
        encoded = encoded.replace('\t', '\\t')
        
        return encoded
    
    @staticmethod
    def url_encode(data: str) -> str:
        """
        URL encode data for safe embedding in URLs.
        
        Args:
            data: String data to encode
            
        Returns:
            URL-encoded string
        """
        if not isinstance(data, str):
            data = str(data)
        
        return quote_plus(data)
    
    @staticmethod
    def base64_encode(data: str) -> str:
        """
        Base64 encode data for safe embedding in various contexts.
        
        Args:
            data: String data to encode
            
        Returns:
            Base64-encoded string
        """
        if not isinstance(data, str):
            data = str(data)
        
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')

class InputValidator:
    """
    Comprehensive input validation with whitelist approach
    """
    
    # Whitelist patterns for different data types
    DAG_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')
    ENVIRONMENT_PATTERN = re.compile(r'^(DEV|QA|PRD|STG)$')
    DAG_RUN_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')
    
    @staticmethod
    def validate_dag_name(dag_name: str) -> str:
        """
        Validate DAG name using whitelist approach.
        
        Args:
            dag_name: DAG name to validate
            
        Returns:
            Validated DAG name
            
        Raises:
            ValueError: If DAG name is invalid
        """
        if not dag_name or not isinstance(dag_name, str):
            raise ValueError("DAG name must be a non-empty string")
        
        if len(dag_name) > 100:
            raise ValueError("DAG name too long (max 100 characters)")
        
        if not InputValidator.DAG_NAME_PATTERN.match(dag_name):
            raise ValueError("Invalid DAG name format - must start with letter and contain only alphanumeric, underscore, or hyphen")
        
        return dag_name.strip()
    
    @staticmethod
    def validate_environment(env_name: str) -> str:
        """
        Validate environment name using whitelist approach.
        
        Args:
            env_name: Environment name to validate
            
        Returns:
            Validated environment name
            
        Raises:
            ValueError: If environment name is invalid
        """
        if not env_name or not isinstance(env_name, str):
            raise ValueError("Environment name must be a non-empty string")
        
        env_upper = env_name.upper().strip()
        if not InputValidator.ENVIRONMENT_PATTERN.match(env_upper):
            raise ValueError(f"Invalid environment. Allowed: DEV, QA, PRD, STG")
        
        return env_upper
    
    @staticmethod
    def validate_dag_run_id(dag_run_id: str) -> str:
        """
        Validate DAG run ID using whitelist approach.
        
        Args:
            dag_run_id: DAG run ID to validate
            
        Returns:
            Validated DAG run ID
        """
        if not dag_run_id or not isinstance(dag_run_id, str):
            return ""
        
        if InputValidator.DAG_RUN_ID_PATTERN.match(dag_run_id):
            return dag_run_id
        else:
            # Sanitize by keeping only safe characters
            return re.sub(r'[^a-zA-Z0-9_-]', '_', dag_run_id)
    
    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """
        Validate hostname using whitelist approach.
        
        Args:
            hostname: Hostname to validate
            
        Returns:
            Validated hostname
            
        Raises:
            ValueError: If hostname is invalid
        """
        if not hostname or not isinstance(hostname, str):
            raise ValueError("Hostname must be a non-empty string")
        
        if not InputValidator.HOSTNAME_PATTERN.match(hostname):
            raise ValueError("Invalid hostname format")
        
        return hostname.strip()

class AirflowResponseValidator:
    """
    Validate and sanitize Airflow API responses
    """
    
    # Expected fields from Airflow API with their types
    EXPECTED_FIELDS = {
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
    
    @staticmethod
    def validate_and_sanitize_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and sanitize Airflow API response structure.
        
        Args:
            data: Raw response from Airflow API
            
        Returns:
            Validated and sanitized response data
        """
        if not isinstance(data, dict):
            return {'error': 'Invalid response format'}
        
        sanitized_response = {}
        
        for field, expected_type in AirflowResponseValidator.EXPECTED_FIELDS.items():
            if field in data:
                value = data[field]
                
                # Type validation
                if isinstance(value, expected_type):
                    # Sanitize the value based on context
                    if field == 'dag_run_id':
                        sanitized_value = InputValidator.validate_dag_run_id(value)
                    elif field in ['dag_id', 'state']:
                        sanitized_value = XSSProtection.html_encode(value)
                    elif field in ['execution_date', 'start_date', 'end_date', 'logical_date']:
                        # Date fields - validate format and encode
                        if isinstance(value, str) and len(value) <= 50:
                            sanitized_value = XSSProtection.html_encode(value)
                        else:
                            sanitized_value = ""
                    elif field == 'conf':
                        # Configuration object - deep sanitization
                        sanitized_value = XSSProtection.html_encode(value)
                    else:
                        sanitized_value = XSSProtection.html_encode(value)
                    
                    sanitized_response[field] = sanitized_value
                else:
                    # Convert to expected type if possible
                    try:
                        converted_value = expected_type(value)
                        sanitized_response[field] = XSSProtection.html_encode(converted_value)
                    except (ValueError, TypeError):
                        # Skip invalid fields
                        continue
        
        return sanitized_response

class SecureResponseBuilder:
    """
    Build secure responses with proper encoding and headers
    """
    
    @staticmethod
    def build_success_response(dag_name: str, dag_run_id: str, execution_date: str = "", state: str = "") -> Dict[str, Any]:
        """
        Build a secure success response with proper encoding.
        
        Args:
            dag_name: DAG name (already validated)
            dag_run_id: DAG run ID (already validated)
            execution_date: Execution date from Airflow
            state: State from Airflow
            
        Returns:
            Secure response dictionary
        """
        # HTML encode all dynamic data
        safe_dag_name = XSSProtection.html_encode(dag_name)
        safe_dag_run_id = InputValidator.validate_dag_run_id(dag_run_id)
        safe_execution_date = XSSProtection.html_encode(execution_date)
        safe_state = XSSProtection.html_encode(state)
        
        response = {
            'status': 'Success',
            'dag_name': safe_dag_name,
            'dag_run_id': safe_dag_run_id,
            'message': 'DAG triggered successfully',
            'execution_date': safe_execution_date,
            'state': safe_state
        }
        
        return response
    
    @staticmethod
    def build_error_response(dag_name: str, error_message: str, status_code: int = 500) -> Dict[str, Any]:
        """
        Build a secure error response with proper encoding.
        
        Args:
            dag_name: DAG name (already validated)
            error_message: Error message to include
            status_code: HTTP status code
            
        Returns:
            Secure error response dictionary
        """
        # HTML encode all dynamic data
        safe_dag_name = XSSProtection.html_encode(dag_name)
        safe_error_message = XSSProtection.html_encode(error_message[:500])  # Limit length
        
        response = {
            'status': 'Failure',
            'dag_name': safe_dag_name,
            'message': f"Failed to trigger DAG: HTTP {status_code} - {safe_error_message}"
        }
        
        return response

class SecurityHeaders:
    """
    Set comprehensive security headers including CSP
    """
    
    @staticmethod
    def add_security_headers(response):
        """
        Add comprehensive security headers to prevent XSS and other attacks.
        """
        # Content Security Policy with explicit whitelist
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "frame-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        
        response.headers['Content-Security-Policy'] = csp_policy
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response

# Updated trigger_dag function with comprehensive XSS protection
def trigger_dag_secure(dag_name: str, env_val: str) -> Dict[str, Any]:
    """
    Secure version of trigger_dag function with comprehensive XSS protection.
    
    This function implements all recommended security measures:
    - Context-sensitive encoding for all dynamic data
    - Whitelist-based input validation
    - Proper error handling without information disclosure
    """
    try:
        # Validate inputs using whitelist approach
        safe_dag_name = InputValidator.validate_dag_name(dag_name)
        safe_env_val = InputValidator.validate_environment(env_val)
        
    except ValueError as e:
        # Log security event
        security_logger.log_security_event(
            "INPUT_VALIDATION_FAILED",
            f"DAG trigger input validation failed: {str(e)}"
        )
        return SecureResponseBuilder.build_error_response(
            dag_name, 
            f"Invalid input: {str(e)}"
        )
    
    # Setup Airflow context (existing code)
    log, env, region, airflow_instance, _ = setup_airflow_context(safe_dag_name, safe_env_val)
    session_info = get_session_info(log, region, airflow_instance)

    if not session_info:
        log.error("Authentication failed, no session info retrieved.")
        close_log(log.name)
        return SecureResponseBuilder.build_error_response(
            dag_name, 
            "Failed to authenticate session."
        )

    web_server_host_name, session_cookie = session_info
    
    # Validate hostname
    try:
        safe_hostname = InputValidator.validate_hostname(web_server_host_name)
    except ValueError as e:
        log.error(f"Invalid hostname: {web_server_host_name}")
        return SecureResponseBuilder.build_error_response(
            dag_name, 
            "Invalid server configuration."
        )
    
    cookies = {"session": session_cookie}
    json_body = {"conf": {}}

    url = f"https://{safe_hostname}/api/v1/dags/{safe_dag_name}/dagRuns"

    try:
        # External API call to Airflow with proper error handling
        external_api_response = requests.post(
            url, 
            cookies=cookies, 
            json=json_body, 
            timeout=30,
            verify=True  # Verify SSL certificates
        )
        
        if external_api_response.status_code == 200:
            # Get raw response from external API
            raw_dag_run_data = external_api_response.json()
            
            # Validate and sanitize the response structure
            validated_data = AirflowResponseValidator.validate_and_sanitize_response(raw_dag_run_data)
            
            # Extract and validate dag_run_id
            dag_run_id = validated_data.get('dag_run_id', '')
            safe_dag_run_id = InputValidator.validate_dag_run_id(dag_run_id)
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {safe_dag_run_id}")
            
            # Build secure success response
            return SecureResponseBuilder.build_success_response(
                dag_name=safe_dag_name,
                dag_run_id=safe_dag_run_id,
                execution_date=validated_data.get('execution_date', ''),
                state=validated_data.get('state', '')
            )
            
        else:
            # Handle error responses
            error_text = external_api_response.text
            if error_text:
                # Sanitize error text
                safe_error = XSSProtection.html_encode(error_text[:500])  # Limit length
            else:
                safe_error = 'Unknown error'
            
            log.error(f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {safe_error}")
            
            return SecureResponseBuilder.build_error_response(
                dag_name=safe_dag_name,
                error_message=safe_error,
                status_code=external_api_response.status_code
            )
            
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        
        return SecureResponseBuilder.build_error_response(
            dag_name=safe_dag_name,
            error_message=f"Request failed: {str(e)}"
        )
    finally:
        close_log(log.name)

# Updated dag_trigger endpoint with comprehensive XSS protection
def dag_trigger_secure():
    """
    Secure version of dag_trigger endpoint with comprehensive XSS protection.
    
    Implements all recommended security measures:
    - Context-sensitive encoding
    - Whitelist-based validation
    - Content Security Policy
    - Proper HTTP headers
    """
    if request.method == 'POST':
        try:
            # Get and validate JSON input
            raw_user_input = request.get_json(force=True)
            if not raw_user_input:
                return jsonify({'status': 'Error', 'message': 'No JSON data provided'}), 400
                
        except Exception as e:
            security_logger.log_security_event(
                "INVALID_JSON",
                f"Invalid JSON input: {str(e)}"
            )
            return jsonify({'status': 'Error', 'message': 'Invalid JSON input'}), 400

        # Validate and sanitize user input
        try:
            validated_user_input = DAGTriggerSchema().load(raw_user_input)
            # HTML encode the validated input
            sanitized_user_input = XSSProtection.html_encode(validated_user_input)
        except ValidationError as e:
            security_logger.log_security_event(
                "VALIDATION_ERROR",
                f"Request validation failed: {str(e.messages)}"
            )
            return jsonify({'status': 'Error', 'message': 'Invalid request data', 'details': e.messages}), 400

        responses = []

        # Ensure we have a list to process
        if isinstance(sanitized_user_input, dict):
            sanitized_user_input = [sanitized_user_input]

        for dagTriggerRequest in sanitized_user_input:
            # Extract validated values
            dag_name = dagTriggerRequest.get('dagName', '')
            env_val = dagTriggerRequest.get('environmentName', '')

            if not dag_name or not env_val:
                responses.append({
                    "status": "Error",
                    "message": "Missing dagName or environmentName.",
                    "details": {"request_data": XSSProtection.html_encode(dagTriggerRequest)}
                })
                continue

            try:
                # Use secure trigger_dag function
                result = trigger_dag_secure(dag_name, env_val)
                responses.append(result)

            except Exception as e:
                security_logger.log_security_event(
                    "DAG_TRIGGER_ERROR",
                    f"Unexpected error in DAG trigger: {str(e)}"
                )
                responses.append({
                    "status": "Error",
                    "message": "An unexpected error occurred",
                    "details": {
                        "dag_name": XSSProtection.html_encode(dag_name),
                        "env_val": XSSProtection.html_encode(env_val),
                        "error": XSSProtection.html_encode(str(e))
                    }
                })

        # Final encoding pass for all responses
        final_encoded_responses = XSSProtection.html_encode(responses)
        
        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        # Create response with security headers
        response = jsonify(final_encoded_responses)
        response = SecurityHeaders.add_security_headers(response)
        
        return response, status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'DAG trigger endpoint - use POST to trigger DAGs'}
        response = jsonify(safe_response)
        response = SecurityHeaders.add_security_headers(response)
        return response, 200

# Example usage and testing
if __name__ == "__main__":
    # Test the XSS protection functions
    test_data = {
        'dag_run_id': 'test_run_123<script>alert("xss")</script>',
        'dag_id': 'test_dag',
        'execution_date': '2025-01-01T00:00:00Z',
        'state': 'running',
        'conf': {'key': '<script>alert("xss")</script>'}
    }
    
    print("Original data:")
    print(json.dumps(test_data, indent=2))
    
    print("\nHTML encoded data:")
    encoded = XSSProtection.html_encode(test_data)
    print(json.dumps(encoded, indent=2))
    
    print("\nValidated data:")
    validated = AirflowResponseValidator.validate_and_sanitize_response(test_data)
    print(json.dumps(validated, indent=2))
    
    print("\nSecurity test:")
    test_str = '<script>alert("xss")</script>'
    print(f"Original: {test_str}")
    print(f"HTML encoded: {XSSProtection.html_encode(test_str)}")
    print(f"JavaScript encoded: {XSSProtection.javascript_encode(test_str)}")
    print(f"URL encoded: {XSSProtection.url_encode(test_str)}")