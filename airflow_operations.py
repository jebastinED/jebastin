#!/usr/bin/env python3
"""
Airflow Operations Module for EDH Automation HTTP Listener
Contains Airflow setup, session management, and DAG triggering functions
"""

import logging
import os
import requests
import time
import boto3
import re
import sys
from typing import Optional, Tuple, Any, Dict

from cyberark_edh_helper import get_secret
from edh_credentials_helper import get_credentials
from ops_helper import create_log, close_log
from validation_module import InputValidator, ResponseValidator, XSSProtection

def setup_airflow_context(dag_name: str, env_val: str) -> Tuple[Any, str, str, str, str]:
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

def get_session_info(log: Any, region: str, airflow_instance: str) -> Optional[Tuple[str, str]]:
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
            aws_secret_access_key=secret_key
        )

        response = mwaa.create_web_login_token(Name=airflow_instance)

        # Sanitize AWS API response data to ensure no malicious content
        web_server_host_name_raw = response["WebServerHostname"]
        web_token_raw = response["WebToken"]
        
        # Validate hostname format to prevent URL manipulation
        if not re.match(r'^[a-zA-Z0-9.-]+$', web_server_host_name_raw):
            log.error(f"Invalid hostname format received from AWS: {ResponseValidator.sanitize_external_api_data(web_server_host_name_raw)}")
            return None
            
        web_server_host_name = ResponseValidator.sanitize_external_api_data(web_server_host_name_raw)
        web_token = ResponseValidator.sanitize_external_api_data(web_token_raw)
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

def sanitize_url_path_segment(segment: str) -> str:
    """Sanitize URL path segment for safe use in URLs"""
    if not isinstance(segment, str):
        raise TypeError("URL path segment must be a string.")
    
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', segment)
    
    if not sanitized:
        raise ValueError(f"Sanitized URL path segment is empty or invalid for input: '{segment}'")
    
    return sanitized

def trigger_dag(dag_name: str, env_val: str) -> Dict[str, Any]:
    """
    Triggers a DAG in a specified MWAA environment using the Airflow REST API.
    """
    try:
        # Validate DAG name
        safe_dag_name = sanitize_url_path_segment(dag_name)

    except ValueError as e:
        return {
            'status': 'Failure',
            'dag_name': XSSProtection.html_encode(dag_name),
            'message': f"Invalid DAG name: {XSSProtection.html_encode(str(e))}"
        }
    
    log, env, region, airflow_instance, _ = setup_airflow_context(safe_dag_name, env_val)
    session_info = get_session_info(log, region, airflow_instance)

    if not session_info:
        log.error("Authentication failed, no session info retrieved.")
        close_log(log.name)
        return {
            'status': 'Failure',
            'dag_name': XSSProtection.html_encode(dag_name),
            'message': 'Failed to authenticate session.'
        }

    web_server_host_name, session_cookie = session_info
    
    # Validate hostname
    try:
        safe_hostname = InputValidator.validate_hostname(web_server_host_name)
    except ValueError as e:
        log.error(f"Invalid hostname: {web_server_host_name}")
        return {
            'status': 'Failure',
            'dag_name': XSSProtection.html_encode(dag_name),
            'message': 'Invalid server configuration.'
        }
    
    cookies = {"session": session_cookie}
    json_body = {"conf": {}}

    url = f"https://{safe_hostname}/api/v1/dags/{safe_dag_name}/dagRuns"

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
                    'dag_name': XSSProtection.html_encode(dag_name),
                    'message': 'Invalid response format from Airflow API'
                }
            
            # Validate and sanitize the response structure
            validated_data = ResponseValidator.validate_airflow_response(raw_dag_run_data)
            
            # Extract and validate dag_run_id
            dag_run_id_sanitized = validated_data.get('dag_run_id', '')
            if not isinstance(dag_run_id_sanitized, str):
                dag_run_id_sanitized = str(dag_run_id_sanitized) if dag_run_id_sanitized else ''
            
            # Additional sanitization for dag_run_id to ensure it's safe
            dag_run_id_sanitized = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', dag_run_id_sanitized)
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {dag_run_id_sanitized}")
            
            # Return fully sanitized response
            success_response = {
                'status': 'Success',
                'dag_name': XSSProtection.html_encode(dag_name),
                'dag_run_id': dag_run_id_sanitized,
                'message': 'DAG triggered successfully',
                'execution_date': validated_data.get('execution_date', ''),
                'state': validated_data.get('state', '')
            }
            
            return success_response
            
        else:
            # Handle error responses
            error_text = external_api_response.text
            if error_text:
                sanitized_error = ResponseValidator.sanitize_external_api_data(error_text[:500])
            else:
                sanitized_error = 'Unknown error'
            
            log.error(f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_error}")
            
            error_response = {
                'status': 'Failure',
                'dag_name': XSSProtection.html_encode(dag_name),
                'message': f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_error}"
            }
            
            return error_response
            
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        
        exception_response = {
            'status': 'Failure',
            'dag_name': XSSProtection.html_encode(dag_name),
            'message': f"Request failed: {XSSProtection.html_encode(str(e))}"
        }
        return exception_response
    finally:
        close_log(log.name)

# Legacy function for backward compatibility
def get_session_info_legacy(log, region, airflow_instance):
    """Legacy function - use get_session_info instead"""
    return get_session_info(log, region, airflow_instance)