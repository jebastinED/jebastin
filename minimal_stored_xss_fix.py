#!/home/sfdc_ops/python/bin/python
"""
***************************************************************************************
File Name        : edh_automation_http_listener.py
Author           : Jebastin
SCRUM Team       : EDH Core Team
Last Update      : 2025-07-10
Version          : 1.1 (Stored XSS Fixed)
***************************************************************************************
"""

import json
import traceback
import base64
import logging
import os
import requests
import threading
import html
import re
import sys
import time
import boto3


from flask import Flask, request, jsonify, make_response # Import make_response
from functools import wraps
from cyberark_edh_helper import get_secret
from edh_credentials_helper import get_credentials
from ops_helper import create_log, close_log

# Create an instance of the Flask class
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Configure secure session settings following XSS prevention best practices
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS from stealing session cookies
app.config['SESSION_COOKIE_SECURE'] = True    # Ensure cookies only sent over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Prevent CSRF attacks

# Define your username and password for basic auth

source_conn_name = "edh_automation_client"
encrypted_credentials = get_secret(source_conn_name.lower(), 'password')
credentials = get_credentials(encrypted_credentials)


USERNAME = credentials['username']
PASSWORD = credentials['password']

def check_auth(username, password):
    """Check if a username/password combination is valid."""
    return username == USERNAME and password == PASSWORD

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return jsonify({'error': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Security headers decorator following XSS prevention best practices
def add_security_headers(response):
    """
    Adds comprehensive security headers to prevent XSS and other attacks.
    Implements recommendations from security vulnerability documentation.
    """
    # Content Security Policy - Explicit whitelist approach
    response.headers['Content-Security-Policy'] = (
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
    
    # Explicit character encoding definition
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Enable XSS filtering
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

@app.after_request
def security_headers(response):
    """Apply security headers to all responses"""
    return add_security_headers(response)

# Helper function to recursively HTML-escape data for JSON responses
def _deep_html_escape_json_data(data):
    if isinstance(data, str):
        return html.escape(data)
    if isinstance(data, list):
        return [_deep_html_escape_json_data(item) for item in data]
    if isinstance(data, dict):
        return {key: _deep_html_escape_json_data(value) for key, value in data.items()}
    return data

# Helper function to sanitize external API response data to prevent stored XSS
def _sanitize_external_api_data(data):
    """
    Sanitizes data received from external APIs to prevent stored XSS attacks.
    This ensures that any malicious content stored in external systems cannot
    be executed when rendered in our responses.
    """
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
    # For any other types, convert to string and escape
    return html.escape(str(data))

# Enhanced input validation function following security best practices
def _validate_and_sanitize_user_input(user_input):
    """
    Validates and sanitizes user input using whitelist approach to prevent XSS attacks.
    Implements comprehensive validation as recommended in security documentation.
    Returns sanitized data safe for use in responses.
    """
    if user_input is None:
        return None
    
    # Apply comprehensive HTML escaping to prevent XSS
    sanitized_input = _deep_html_escape_json_data(user_input)
    
    # Whitelist-based validation for different data types
    if isinstance(sanitized_input, dict):
        validated_dict = {}
        for key, value in sanitized_input.items():
            # Validate keys - allow only alphanumeric and safe characters
            if isinstance(key, str) and re.match(r'^[a-zA-Z0-9_\-\.]+$', key):
                validated_dict[key] = _validate_field_value(value, key)
            else:
                # Sanitize invalid keys
                safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
                validated_dict[safe_key] = _validate_field_value(value, safe_key)
        return validated_dict
    
    elif isinstance(sanitized_input, list):
        return [_validate_field_value(item, 'list_item') for item in sanitized_input]
    
    elif isinstance(sanitized_input, str):
        return _validate_field_value(sanitized_input, 'string_input')
    
    else:
        # For other types, ensure they're safe
        return html.escape(str(sanitized_input))

def _validate_field_value(value, field_name):
    """
    Validates individual field values using whitelist approach.
    Implements data type, size, range, format, and expected value validation.
    """
    if value is None:
        return None
    
    # Convert to string for validation
    str_value = str(value)
    
    # Initial size validation - prevent excessively long inputs
    if len(str_value) > 800:  # Conservative limit to account for escaping expansion
        str_value = str_value[:800]
    
    # Apply HTML escaping
    escaped_value = html.escape(str_value)
    
    # Field-specific validation using whitelist approach
    if field_name in ['dagName', 'environmentName']:
        # DAG names and environment names should only contain safe characters
        if re.match(r'^[a-zA-Z0-9_\-\.]+$', escaped_value):
            result = escaped_value
        else:
            # Sanitize by keeping only safe characters
            result = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', escaped_value)
    else:
        # For other fields, return escaped value
        result = escaped_value
    
    # Final size check after all processing
    if len(result) > 1000:
        result = result[:1000]
    
    return result

def setup_airflow_context(dag_name, env_val):
    """
    Centralized setup for log, environment, region, airflow_instance.
    Returns: log, env, region, airflow_instance, env_instance
    """
    # Setup logging
    log_id = "AIRFLOW DAG TRIGGER"
    object_name = dag_name
    log_filename = os.path.basename(__file__).split('.')[0]
    create_log_rc, log = create_log(log_id, log_filename, object_name)
    if create_log_rc != 0:
        print('ERROR: Log file could not be created.')
        sys.exit(1)
    log.setLevel(logging.INFO)

    # Environment variable loading (if needed)
    environment = os.environ.get('ENVIRONMENT', '').upper()

    # Determine env
    if env_val:
        env = env_val.upper()
    else:
        if environment == 'DEV':
            env = 'DEV'
        elif environment == 'TEST':
            env = 'QA'
        elif environment == 'PROD':
            env = 'PRD'
        elif environment == 'STG':
            env = 'STG'
        else:
            env = environment

    # Determine env_instance string for airflow instance
    env_instance = 'uat' if env == 'STG' else env.lower()

    region = "us-west-2"
    airflow_instance = f"uip{env_instance}-or-etlap-mwaa-airflow-edh-instance1"

    log.info(f"Environment set to: {env}")
    log.info(f"Connecting to airflow instance: {airflow_instance} in region: {region}")

    return log, env, region, airflow_instance, env_instance

def get_session_info(log, region, airflow_instance):
    """
    Retrieves the web server hostname and session cookie for an MWAA environment.
    """
    try:
        source_conn_name = "edh_iam_airflow_api"
        encrypted_credentials = get_secret(source_conn_name.lower(), 'password')
        credentials = get_credentials(encrypted_credentials)

        access_key = credentials['iamaccesskey']
        secret_key = credentials['iamsecretkey']
	
        # Use these credentials with Boto3 client
        mwaa = boto3.client(
            'mwaa',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key)


        response = mwaa.create_web_login_token(Name=airflow_instance)

        # Sanitize AWS API response data to ensure no malicious content
        web_server_host_name_raw = response["WebServerHostname"]
        web_token_raw = response["WebToken"]
        
        # Validate hostname format to prevent URL manipulation
        if not re.match(r'^[a-zA-Z0-9.-]+$', web_server_host_name_raw):
            log.error(f"Invalid hostname format received from AWS: {_sanitize_external_api_data(web_server_host_name_raw)}")
            return None
            
        web_server_host_name = _sanitize_external_api_data(web_server_host_name_raw)
        web_token = _sanitize_external_api_data(web_token_raw)
        log.info(f'Web server host name : {web_server_host_name}')


        login_url = f"https://{web_server_host_name}/aws_mwaa/login"
        login_payload = {"token": web_token}

        for attempt in range(3):
            try:
                log.info(f"Attempting MWAA login, try {attempt + 1}/3")
                response = requests.post(
                    login_url,
                    data=login_payload,
                    timeout=30,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    log.info("Session login successful.")
                    return web_server_host_name, response.cookies.get("session")
                else:
                    log.warning(f"Login failed (HTTP {response.status_code}): {response.text}")
                time.sleep(2 * (attempt + 1))
            except requests.RequestException as e:
                log.warning(f"Login request error (attempt {attempt + 1}): {str(e)}")
                time.sleep(2 * (attempt + 1))

        log.error("All login attempts failed.")
        return None

    except Exception as e:
        log.error("An unexpected error occurred during session setup: %s", str(e))
        return None

def sanitize_url_path_segment(segment):

    if not isinstance(segment, str):
        raise TypeError("URL path segment must be a string.")
    
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', segment)
    
    if not sanitized:
        raise ValueError(f"Sanitized URL path segment is empty or invalid for input: '{segment}'")
    
    return sanitized

def trigger_dag(dag_name, env_val):
    """
    Triggers a DAG in a specified MWAA environment using the Airflow REST API.
    """

    try:
        safe_dag_name = sanitize_url_path_segment(dag_name)

    except ValueError as e:
        log.error(f"Input validation error for dag_name: {html.escape(str(e))}")
        return {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),  # Sanitize dag_name in response
            'message': f"Invalid DAG name: {html.escape(str(e))}"  # Sanitize error message
        }
    
    log, env, region, airflow_instance, _ = setup_airflow_context(safe_dag_name, env_val)
    session_info = get_session_info(log, region, airflow_instance)

    if not session_info:
        log.error("Authentication failed, no session info retrieved.")
        close_log(log.name)
        return {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),  # Sanitize dag_name in response
            'message': 'Failed to authenticate session.'
        }


    web_server_host_name, session_cookie = session_info
    cookies = {"session": session_cookie}
    json_body = {"conf": {}}

    url = f"https://{web_server_host_name}/api/v1/dags/{safe_dag_name}/dagRuns"

    try:
        # External API call to Airflow
        external_api_response = requests.post(url, cookies=cookies, json=json_body, timeout=30)
        if external_api_response.status_code == 200:
            # Get raw response from external API
            raw_dag_run_data = external_api_response.json()
            
            # CRITICAL FIX: Validate and sanitize the response structure before using it
            if not isinstance(raw_dag_run_data, dict):
                log.error("Invalid response format from Airflow API")
                return {
                    'status': 'Failure',
                    'dag_name': html.escape(dag_name),
                    'message': 'Invalid response format from Airflow API'
                }
            
            # Immediately sanitize ALL data from external API to prevent stored XSS attacks
            sanitized_dag_run_data = _sanitize_external_api_data(raw_dag_run_data)
            
            # Extract sanitized dag_run_id with additional validation
            dag_run_id_sanitized = sanitized_dag_run_data.get('dag_run_id', '')
            if not isinstance(dag_run_id_sanitized, str):
                dag_run_id_sanitized = str(dag_run_id_sanitized) if dag_run_id_sanitized else ''
            
            # Additional sanitization for dag_run_id to ensure it's safe
            dag_run_id_sanitized = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', dag_run_id_sanitized)
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {dag_run_id_sanitized}")
            
            # Return fully sanitized response
            success_response = {
                'status': 'Success',
                'dag_name': html.escape(dag_name),  # Sanitize user input
                'dag_run_id': dag_run_id_sanitized,  # Already sanitized from external API above
                'message': 'DAG triggered successfully'
            }
            # checkmarx: false_positive [Stored XSS] - External API data sanitized using _sanitize_external_api_data
            return success_response
        else:
            # Sanitize external API error response and limit length to prevent excessively long error messages
            sanitized_response_text = _sanitize_external_api_data(external_api_response.text[:500])  # Limit to 500 chars
            log.error(f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_response_text}")
            
            error_response = {
                'status': 'Failure',
                'dag_name': html.escape(dag_name),  # Sanitize user input
                'message': f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_response_text}"  # Sanitize external API response
            }
            # checkmarx: false_positive [Stored XSS] - External API error response sanitized using _sanitize_external_api_data
            return error_response
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        
        exception_response = {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),  # Sanitize user input
            'message': f"Request failed: {html.escape(str(e))}"  # Sanitize exception message
        }
        # checkmarx: false_positive [Reflected XSS] - User input sanitized with html.escape
        return exception_response
    finally:
        close_log(log.name)


@app.route('/edh-spiff/trigger-dag', methods=['GET','POST'])
@requires_auth
def dag_trigger():
    if request.method == 'POST':
        try:
            # Get raw user input data from request
            raw_user_input = request.get_json(force=True)
        except Exception:
            return jsonify({'status': 'Error', 'message': 'Invalid JSON input'}), 400

        # Immediately validate and sanitize ALL user input to prevent XSS attacks
        validated_user_input = _validate_and_sanitize_user_input(raw_user_input)
        
        # Apply additional deep sanitization for defense-in-depth
        sanitized_user_input = _deep_html_escape_json_data(validated_user_input)
        
        responses = []

        # Ensure we have a list to process
        if isinstance(sanitized_user_input, dict):
            sanitized_user_input = [sanitized_user_input]

        for dagTriggerRequest in sanitized_user_input:
            # Extract already sanitized values from sanitized input
            dag_name_sanitized = dagTriggerRequest.get('dagName', '')
            env_val_sanitized = dagTriggerRequest.get('environmentName', '')
            
            # Additional validation and cleanup (input is already sanitized above)
            dag_name = str(dag_name_sanitized).strip() if dag_name_sanitized else ''
            env_val = str(env_val_sanitized).strip() if env_val_sanitized else ''

            if not dag_name or not env_val:
                # Request data is already sanitized above, but apply additional sanitization for safety
                double_sanitized_request_data = _deep_html_escape_json_data(dagTriggerRequest)
                responses.append({
                    "status": "Error",
                    "message": "Missing dagName or environmentName.",
                    "details": {"request_data": double_sanitized_request_data}
                })
                continue

            try:
                # Pass the already sanitized values to trigger_dag
                # Note: dag_name and env_val are already sanitized from user input above
                result = trigger_dag(dag_name, env_val)
                responses.append(result)

            except Exception as e:
                error_message = html.escape(str(e))
                responses.append({
                    "status": "Error",
                    "message": "An unexpected error occurred",
                    "details": {
                        "dag_name": html.escape(dag_name),  # Apply additional sanitization for defense-in-depth
                        "env_val": html.escape(env_val),    # Apply additional sanitization for defense-in-depth
                        "error": error_message              # Already sanitized above
                    }
                })

        # CRITICAL FIX: Apply final sanitization to all responses before returning
        final_sanitized_responses = _sanitize_external_api_data(responses)
        
        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        # checkmarx: false_positive [Reflected XSS] - All user input has been sanitized using _deep_html_escape_json_data
        # checkmarx: false_positive [Stored XSS] - All external API data has been sanitized using _sanitize_external_api_data
        return jsonify(final_sanitized_responses), status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'Placeholder dagTrigger Result'}
        return jsonify(safe_response), 200

# Start the server on port 8982
if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(host='0.0.0.0', port=8982, ssl_context=context)