#!/usr/bin/env python3
"""
Targeted Fix for Stored XSS Vulnerability
Checkmarx Issue: External API data not properly sanitized before response

Problem:
- External API response from Airflow REST API (line 365) contains untrusted data
- This data flows through to the response (line 484) without proper sanitization
- Could enable Stored XSS attacks if malicious data is stored in Airflow

Solution:
- Implement comprehensive sanitization for all external API responses
- Add validation for expected data structure
- Ensure all response data is properly encoded
"""

import html
import json
import re
from typing import Any, Dict, List, Union

def sanitize_external_api_response(data: Any, max_length: int = 1000) -> Any:
    """
    Comprehensive sanitization for external API responses to prevent Stored XSS.
    
    This function specifically addresses the Checkmarx Stored XSS vulnerability
    by ensuring all data from external APIs is properly sanitized before
    being included in responses.
    
    Args:
        data: Raw data from external API
        max_length: Maximum length for string values
        
    Returns:
        Sanitized data safe for JSON response
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
    
    This function ensures that the Airflow API response contains only
    expected fields and that all data is properly sanitized.
    
    Args:
        data: Raw response from Airflow API
        
    Returns:
        Validated and sanitized response data
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

def secure_trigger_dag_response(external_api_response, dag_name: str) -> Dict[str, Any]:
    """
    Secure wrapper for trigger_dag function response.
    
    This function specifically addresses the Checkmarx Stored XSS vulnerability
    by ensuring all external API data is properly sanitized.
    
    Args:
        external_api_response: Raw response from external API
        dag_name: Original DAG name for response
        
    Returns:
        Secure response dictionary
    """
    try:
        if external_api_response.status_code == 200:
            # Get raw response from external API
            raw_dag_run_data = external_api_response.json()
            
            # Validate and sanitize the response structure
            validated_data = validate_airflow_response_structure(raw_dag_run_data)
            
            # Extract dag_run_id with additional validation
            dag_run_id = validated_data.get('dag_run_id', '')
            if not dag_run_id or not isinstance(dag_run_id, str):
                dag_run_id = ''
            
            # Additional sanitization for dag_run_id
            dag_run_id_sanitized = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', dag_run_id)
            
            # Create secure response
            success_response = {
                'status': 'Success',
                'dag_name': html.escape(dag_name),
                'dag_run_id': dag_run_id_sanitized,
                'message': 'DAG triggered successfully',
                'execution_date': validated_data.get('execution_date', ''),
                'state': validated_data.get('state', '')
            }
            
            # Final sanitization pass
            return sanitize_external_api_response(success_response)
            
        else:
            # Handle error responses
            error_text = external_api_response.text
            if error_text:
                # Sanitize error text
                sanitized_error = html.escape(error_text[:500])  # Limit length
            else:
                sanitized_error = 'Unknown error'
            
            error_response = {
                'status': 'Failure',
                'dag_name': html.escape(dag_name),
                'message': f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_error}"
            }
            
            return sanitize_external_api_response(error_response)
            
    except Exception as e:
        # Handle any exceptions in response processing
        error_response = {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),
            'message': f"Error processing response: {html.escape(str(e))}"
        }
        
        return sanitize_external_api_response(error_response)

# Updated trigger_dag function with comprehensive Stored XSS protection
def trigger_dag_secure(dag_name: str, env_val: str) -> Dict[str, Any]:
    """
    Secure version of trigger_dag function with comprehensive Stored XSS protection.
    
    This function addresses the Checkmarx Stored XSS vulnerability by:
    1. Validating all input data
    2. Sanitizing external API responses
    3. Ensuring all output data is properly encoded
    """
    try:
        # Validate inputs
        safe_dag_name = validate_dag_name(dag_name)
        safe_env_val = validate_environment(env_val)
        
    except ValueError as e:
        security_logger.log_security_event(
            "INPUT_VALIDATION_FAILED",
            f"DAG trigger input validation failed: {str(e)}"
        )
        return {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),
            'message': f"Invalid input: {html.escape(str(e))}"
        }
    
    log, env, region, airflow_instance, _ = setup_airflow_context(safe_dag_name, safe_env_val)
    session_info = get_session_info(log, region, airflow_instance)

    if not session_info:
        log.error("Authentication failed, no session info retrieved.")
        close_log(log.name)
        return {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),
            'message': 'Failed to authenticate session.'
        }

    web_server_host_name, session_cookie = session_info
    cookies = {"session": session_cookie}
    json_body = {"conf": {}}

    url = f"https://{web_server_host_name}/api/v1/dags/{safe_dag_name}/dagRuns"

    try:
        # External API call to Airflow with proper error handling
        external_api_response = requests.post(
            url, 
            cookies=cookies, 
            json=json_body, 
            timeout=30,
            verify=True  # Verify SSL certificates
        )
        
        # Use secure response handler to prevent Stored XSS
        return secure_trigger_dag_response(external_api_response, dag_name)
            
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        
        exception_response = {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),
            'message': f"Request failed: {html.escape(str(e))}"
        }
        return sanitize_external_api_response(exception_response)
    finally:
        close_log(log.name)

# Updated dag_trigger endpoint with enhanced Stored XSS protection
def dag_trigger_secure():
    """Secure version of dag_trigger endpoint with comprehensive Stored XSS protection."""
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
            sanitized_user_input = sanitize_input(validated_user_input)
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
                    "details": {"request_data": sanitize_input(dagTriggerRequest)}
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
                        "dag_name": html.escape(dag_name),
                        "env_val": html.escape(env_val),
                        "error": html.escape(str(e))
                    }
                })

        # Final sanitization pass for all responses
        final_sanitized_responses = sanitize_external_api_response(responses)
        
        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        # Return sanitized response
        return jsonify(final_sanitized_responses), status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'DAG trigger endpoint - use POST to trigger DAGs'}
        return jsonify(safe_response), 200

# Example usage and testing
if __name__ == "__main__":
    # Test the sanitization functions
    test_data = {
        'dag_run_id': 'test_run_123<script>alert("xss")</script>',
        'dag_id': 'test_dag',
        'execution_date': '2025-01-01T00:00:00Z',
        'state': 'running',
        'conf': {'key': '<script>alert("xss")</script>'}
    }
    
    print("Original data:")
    print(json.dumps(test_data, indent=2))
    
    print("\nSanitized data:")
    sanitized = sanitize_external_api_response(test_data)
    print(json.dumps(sanitized, indent=2))
    
    print("\nValidated data:")
    validated = validate_airflow_response_structure(test_data)
    print(json.dumps(validated, indent=2))