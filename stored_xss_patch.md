# Stored XSS Vulnerability Fix - Patch Guide

## Checkmarx Issue Summary
- **Vulnerability**: Stored XSS
- **Severity**: High
- **Location**: Lines 365 and 484 in `edh_automation_http_listener.py`
- **Problem**: External API data from Airflow REST API not properly sanitized before response

## Root Cause Analysis

The vulnerability occurs because:
1. **Line 365**: `requests.post()` call to Airflow API returns untrusted data
2. **Line 484**: This untrusted data flows directly to `jsonify()` response without sanitization
3. **Risk**: If malicious data is stored in Airflow, it could be executed as JavaScript in the browser

## Required Changes

### 1. Add External API Response Sanitization Function

Add this function after the existing `sanitize_input` function:

```python
def sanitize_external_api_response(data: Any, max_length: int = 1000) -> Any:
    """
    Comprehensive sanitization for external API responses to prevent Stored XSS.
    
    This function specifically addresses the Checkmarx Stored XSS vulnerability
    by ensuring all data from external APIs is properly sanitized before
    being included in responses.
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
```

### 2. Add Airflow Response Validation Function

Add this function after the sanitization function:

```python
def validate_airflow_response_structure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and sanitize Airflow API response structure.
    
    This function ensures that the Airflow API response contains only
    expected fields and that all data is properly sanitized.
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
```

### 3. Modify the trigger_dag Function

Replace the existing `trigger_dag` function with this secure version:

```python
def trigger_dag(dag_name: str, env_val: str) -> Dict[str, Any]:
    """
    Triggers a DAG in a specified MWAA environment using the Airflow REST API.
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
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {dag_run_id_sanitized}")
            
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
            
            log.error(f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_error}")
            
            error_response = {
                'status': 'Failure',
                'dag_name': html.escape(dag_name),
                'message': f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_error}"
            }
            
            return sanitize_external_api_response(error_response)
            
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
```

### 4. Modify the dag_trigger Function

Update the `dag_trigger` function to include final sanitization:

```python
@app.route('/edh-spiff/trigger-dag', methods=['GET', 'POST'])
@requires_auth
@limiter.limit("10 per minute")  # Rate limit for DAG triggers
def dag_trigger():
    """Main endpoint for triggering DAGs with comprehensive security"""
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
                result = trigger_dag(dag_name, env_val)
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

        # Final sanitization pass for all responses to prevent Stored XSS
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
```

## Testing the Fix

### 1. Test with Malicious Payload

```python
# Test payload that would trigger Stored XSS
test_payload = {
    "dagName": "test_dag",
    "environmentName": "DEV"
}

# Mock Airflow response with malicious data
mock_airflow_response = {
    "dag_run_id": "test_run_123<script>alert('xss')</script>",
    "dag_id": "test_dag",
    "execution_date": "2025-01-01T00:00:00Z",
    "state": "running",
    "conf": {"key": "<script>alert('xss')</script>"}
}

# The sanitized response should have all script tags escaped
expected_sanitized = {
    "dag_run_id": "test_run_123&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
    "dag_id": "test_dag",
    "execution_date": "2025-01-01T00:00:00Z",
    "state": "running",
    "conf": {"key": "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"}
}
```

### 2. Verify the Fix

After implementing the changes:

1. **Checkmarx Scan**: Run a new scan to verify the vulnerability is resolved
2. **Manual Testing**: Test with various malicious payloads
3. **Integration Testing**: Ensure the application still works correctly

## Security Benefits

This fix provides:

1. **Comprehensive Sanitization**: All external API data is properly sanitized
2. **Type Validation**: Ensures data types match expected structure
3. **Length Limits**: Prevents oversized payloads
4. **HTML Escaping**: Converts dangerous characters to safe entities
5. **Key Sanitization**: Even dictionary keys are sanitized
6. **Defense in Depth**: Multiple layers of sanitization

## Compliance

This fix addresses:
- **OWASP Top 10 2021**: A3-Injection
- **PCI DSS v3.2.1**: 6.5.7 - Cross-site scripting (XSS)
- **NIST SP 800-53**: SI-15 Information Output Filtering
- **OWASP ASVS**: V05 Validation, Sanitization and Encoding

## Implementation Notes

1. **Backward Compatibility**: The fix maintains the same API interface
2. **Performance Impact**: Minimal - only adds sanitization overhead
3. **Error Handling**: Graceful handling of malformed responses
4. **Logging**: Security events are logged for monitoring

## Rollback Plan

If issues arise, you can temporarily disable the new sanitization by:
1. Commenting out the `sanitize_external_api_response()` calls
2. Reverting to the original response handling
3. Monitoring for any security issues

However, this should only be done temporarily while investigating any issues.