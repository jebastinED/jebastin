#!/usr/bin/env python3
"""
Validation Module for EDH Automation HTTP Listener
Contains all input validation and sanitization functions
"""

import html
import re
from typing import Any, Dict, List, Union

class XSSProtection:
    """XSS protection utilities"""
    
    @staticmethod
    def html_encode(data: Any, max_length: int = 1000) -> Any:
        """HTML encode data for safe embedding in HTML content"""
        if data is None:
            return None
        
        if isinstance(data, str):
            encoded = html.escape(data.strip())
            if len(encoded) > max_length:
                encoded = encoded[:max_length]
            return encoded
        
        if isinstance(data, (int, float, bool)):
            return html.escape(str(data))
        
        if isinstance(data, dict):
            encoded_dict = {}
            for key, value in data.items():
                safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
                encoded_dict[safe_key] = XSSProtection.html_encode(value, max_length)
            return encoded_dict
        
        if isinstance(data, list):
            return [XSSProtection.html_encode(item, max_length) for item in data]
        
        return html.escape(str(data))

class InputValidator:
    """Input validation with whitelist approach"""
    
    # Whitelist patterns
    DAG_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')
    ENVIRONMENT_PATTERN = re.compile(r'^(DEV|QA|PRD|STG)$')
    DAG_RUN_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')
    
    @staticmethod
    def validate_dag_name(dag_name: str) -> str:
        """Validate DAG name using whitelist approach"""
        if not dag_name or not isinstance(dag_name, str):
            raise ValueError("DAG name must be a non-empty string")
        
        if len(dag_name) > 100:
            raise ValueError("DAG name too long (max 100 characters)")
        
        if not InputValidator.DAG_NAME_PATTERN.match(dag_name):
            raise ValueError("Invalid DAG name format - must start with letter and contain only alphanumeric, underscore, or hyphen")
        
        return dag_name.strip()
    
    @staticmethod
    def validate_environment(env_name: str) -> str:
        """Validate environment name using whitelist approach"""
        if not env_name or not isinstance(env_name, str):
            raise ValueError("Environment name must be a non-empty string")
        
        env_upper = env_name.upper().strip()
        if not InputValidator.ENVIRONMENT_PATTERN.match(env_upper):
            raise ValueError(f"Invalid environment. Allowed: DEV, QA, PRD, STG")
        
        return env_upper
    
    @staticmethod
    def validate_dag_run_id(dag_run_id: str) -> str:
        """Validate DAG run ID using whitelist approach"""
        if not dag_run_id or not isinstance(dag_run_id, str):
            return ""
        
        if InputValidator.DAG_RUN_ID_PATTERN.match(dag_run_id):
            return dag_run_id
        else:
            return re.sub(r'[^a-zA-Z0-9_-]', '_', dag_run_id)
    
    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """Validate hostname using whitelist approach"""
        if not hostname or not isinstance(hostname, str):
            raise ValueError("Hostname must be a non-empty string")
        
        if not InputValidator.HOSTNAME_PATTERN.match(hostname):
            raise ValueError("Invalid hostname format")
        
        return hostname.strip()

class ResponseValidator:
    """Response validation and sanitization"""
    
    @staticmethod
    def sanitize_external_api_data(data: Any) -> Any:
        """Sanitize external API response data to prevent stored XSS"""
        if data is None:
            return ''
        if isinstance(data, str):
            return html.escape(data)
        if isinstance(data, (int, float, bool)):
            return html.escape(str(data))
        if isinstance(data, dict):
            return {key: ResponseValidator.sanitize_external_api_data(value) for key, value in data.items()}
        if isinstance(data, list):
            return [ResponseValidator.sanitize_external_api_data(item) for item in data]
        return html.escape(str(data))
    
    @staticmethod
    def validate_airflow_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize Airflow API response structure"""
        if not isinstance(data, dict):
            return {'error': 'Invalid response format'}
        
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
                
                if isinstance(value, expected_type):
                    if field == 'dag_run_id':
                        sanitized_value = InputValidator.validate_dag_run_id(value)
                    else:
                        sanitized_value = XSSProtection.html_encode(value)
                    
                    sanitized_response[field] = sanitized_value
                else:
                    try:
                        converted_value = expected_type(value)
                        sanitized_response[field] = XSSProtection.html_encode(converted_value)
                    except (ValueError, TypeError):
                        continue
        
        return sanitized_response

class SecurityHeaders:
    """Security headers configuration"""
    
    @staticmethod
    def add_security_headers(response):
        """Add comprehensive security headers to prevent XSS and other attacks"""
        # Content Security Policy
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "frame-src 'none'; "
            "base-uri 'self';"
        )
        
        response.headers['Content-Security-Policy'] = csp_policy
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response

# Legacy functions for backward compatibility
def _deep_html_escape_json_data(data):
    """Legacy function - use XSSProtection.html_encode instead"""
    return XSSProtection.html_encode(data)

def _sanitize_external_api_data(data):
    """Legacy function - use ResponseValidator.sanitize_external_api_data instead"""
    return ResponseValidator.sanitize_external_api_data(data)

def _validate_and_sanitize_user_input(user_input):
    """Legacy function - use InputValidator methods instead"""
    if user_input is None:
        return None
    
    sanitized_input = XSSProtection.html_encode(user_input)
    
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

def _validate_field_value(value, field_name):
    """Legacy function - use InputValidator methods instead"""
    if value is None:
        return None
    
    str_value = str(value)
    
    if len(str_value) > 800:
        str_value = str_value[:800]
    
    escaped_value = html.escape(str_value)
    
    if field_name in ['dagName', 'environmentName']:
        if re.match(r'^[a-zA-Z0-9_\-\.]+$', escaped_value):
            result = escaped_value
        else:
            result = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', escaped_value)
    else:
        result = escaped_value
    
    if len(result) > 1000:
        result = result[:1000]
    
    return result