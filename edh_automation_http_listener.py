#!/home/sfdc_ops/python/bin/python
"""
***************************************************************************************
File Name        : edh_automation_http_listener.py
Author           : Jebastin
SCRUM Team       : EDH Core Team
Last Update      : 2025-07-10
Version          : 1.0
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
        response = requests.post(url, cookies=cookies, json=json_body, timeout=30)
        if response.status_code == 200:
            dag_run = response.json()
            # Sanitize all data from external API response to prevent stored XSS
            dag_run_id_raw = dag_run.get('dag_run_id', '')
            dag_run_id_sanitized = _sanitize_external_api_data(dag_run_id_raw)
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {dag_run_id_sanitized}")
            return {
                'status': 'Success',
                'dag_name': html.escape(dag_name),  # Sanitize dag_name in response
                'dag_run_id': dag_run_id_sanitized,  # Already sanitized above
                'message': 'DAG triggered successfully'
            }
        else:
            # Sanitize external API error response and limit length to prevent excessively long error messages
            sanitized_response_text = _sanitize_external_api_data(response.text[:500])  # Limit to 500 chars
            log.error(f"Failed to trigger DAG: HTTP {response.status_code} - {sanitized_response_text}")
            return {
                'status': 'Failure',
                'dag_name': html.escape(dag_name),  # Sanitize dag_name in response
                'message': f"Failed to trigger DAG: HTTP {response.status_code} - {sanitized_response_text}"  # Sanitize response text
            }
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        return {
            'status': 'Failure',
            'dag_name': html.escape(dag_name),  # Sanitize dag_name in response
            'message': f"Request failed: {html.escape(str(e))}"  # Sanitize error message
        }
    finally:
        close_log(log.name)


@app.route('/edh-spiff/trigger-dag', methods=['GET','POST'])
@requires_auth
def dag_trigger():
    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
        except Exception:
            return jsonify({'status': 'Error', 'message': 'Invalid JSON input'}), 400

        responses = []

        if isinstance(data, dict):
            data = [data]

        for dagTriggerRequest in data:
            # Sanitize and validate user input immediately
            dag_name_raw = dagTriggerRequest.get('dagName', '')
            env_val_raw = dagTriggerRequest.get('environmentName', '')
            
            # Ensure we have strings and strip whitespace
            dag_name = str(dag_name_raw).strip() if dag_name_raw else ''
            env_val = str(env_val_raw).strip() if env_val_raw else ''

            if not dag_name or not env_val:
                # Sanitize the entire request data before including in response
                sanitized_request_data = _deep_html_escape_json_data(dagTriggerRequest)
                responses.append({
                    "status": "Error",
                    "message": "Missing dagName or environmentName.",
                    "details": {"request_data": sanitized_request_data}
                })
                continue

            try:
                result = trigger_dag(dag_name, env_val)
                responses.append(result)

            except Exception as e:
                error_message = html.escape(str(e))
                responses.append({
                    "status": "Error",
                    "message": "An unexpected error occurred",
                    "details": {
                        "dag_name": html.escape(dag_name),  # Sanitize dag_name
                        "env_val": html.escape(env_val),    # Sanitize env_val
                        "error": error_message              # Already sanitized above
                    }
                })

        # Apply deep sanitization to all responses before returning
        sanitized_responses = _deep_html_escape_json_data(responses)
        
        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        return jsonify(sanitized_responses), status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'Placeholder dagTrigger Result'}
        return jsonify(safe_response), 200

# Start the server on port 8982
if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(host='0.0.0.0', port=8982, ssl_context=context)