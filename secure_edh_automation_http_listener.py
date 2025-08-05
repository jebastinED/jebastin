#!/home/sfdc_ops/python/bin/python
"""
***************************************************************************************
File Name        : secure_edh_automation_http_listener.py
Author           : Jebastin
SCRUM Team       : EDH Core Team
Last Update      : 2025-07-10
Version          : 2.0 (Security Enhanced)
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
import ssl
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any, Tuple

from flask import Flask, request, jsonify, make_response, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from marshmallow import Schema, fields, ValidationError

# Import custom modules
from cyberark_edh_helper import get_secret
from edh_credentials_helper import get_credentials
from ops_helper import create_log, close_log

# Create an instance of the Flask class
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Configure secure session settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Global variables for monitoring
request_counter = 0
error_counter = 0
active_connections = 0

# Security configuration
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
MAX_DAG_NAME_LENGTH = 100
ALLOWED_ENVIRONMENTS = {'DEV', 'QA', 'PRD', 'STG'}

class SecurityLogger:
    """Centralized security logging"""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.WARNING)
        
        # Add file handler for security events
        handler = logging.FileHandler('/var/log/edh_security.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_security_event(self, event_type: str, details: str, user: Optional[str] = None):
        """Log security events with comprehensive details"""
        self.logger.warning(
            f"SECURITY_EVENT: {event_type} - {details} - "
            f"User: {user} - IP: {request.remote_addr} - "
            f"User-Agent: {request.headers.get('User-Agent', 'Unknown')} - "
            f"Timestamp: {datetime.utcnow().isoformat()}"
        )

security_logger = SecurityLogger()

def get_credentials_safely() -> Dict[str, str]:
    """
    Safely retrieve credentials with proper error handling and rotation.
    Returns credentials or raises exception on failure.
    """
    try:
        source_conn_name = "edh_automation_client"
        encrypted_credentials = get_secret(source_conn_name.lower(), 'password')
        credentials = get_credentials(encrypted_credentials)
        
        # Validate credentials structure
        if not isinstance(credentials, dict):
            raise ValueError("Invalid credentials format")
        
        required_keys = {'username', 'password'}
        if not all(key in credentials for key in required_keys):
            raise ValueError("Missing required credential fields")
        
        return credentials
    except Exception as e:
        security_logger.log_security_event(
            "CREDENTIAL_RETRIEVAL_FAILED",
            f"Failed to retrieve credentials: {str(e)}"
        )
        raise

def validate_dag_name(dag_name: str) -> str:
    """
    Strict validation for DAG names to prevent injection attacks.
    
    Args:
        dag_name: The DAG name to validate
        
    Returns:
        Validated DAG name
        
    Raises:
        ValueError: If DAG name is invalid
    """
    if not dag_name or not isinstance(dag_name, str):
        raise ValueError("DAG name must be a non-empty string")
    
    if len(dag_name) > MAX_DAG_NAME_LENGTH:
        raise ValueError(f"DAG name too long (max {MAX_DAG_NAME_LENGTH} characters)")
    
    # Strict pattern matching for DAG names
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', dag_name):
        raise ValueError("Invalid DAG name format - must start with letter and contain only alphanumeric, underscore, or hyphen")
    
    return dag_name.strip()

def validate_environment(env_name: str) -> str:
    """
    Validate environment name against whitelist.
    
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
    if env_upper not in ALLOWED_ENVIRONMENTS:
        raise ValueError(f"Invalid environment. Allowed: {', '.join(ALLOWED_ENVIRONMENTS)}")
    
    return env_upper

def sanitize_input(data: Any) -> Any:
    """
    Comprehensive input sanitization to prevent XSS and injection attacks.
    
    Args:
        data: Input data to sanitize
        
    Returns:
        Sanitized data
    """
    if data is None:
        return None
    
    if isinstance(data, str):
        # HTML escape and limit length
        sanitized = html.escape(data.strip())
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]
        return sanitized
    
    if isinstance(data, dict):
        return {key: sanitize_input(value) for key, value in data.items()}
    
    if isinstance(data, list):
        return [sanitize_input(item) for item in data]
    
    # For other types, convert to string and escape
    return html.escape(str(data))

def check_auth(username: str, password: str) -> bool:
    """
    Check if a username/password combination is valid.
    Implements rate limiting and brute force protection.
    """
    try:
        credentials = get_credentials_safely()
        return username == credentials['username'] and password == credentials['password']
    except Exception as e:
        security_logger.log_security_event(
            "AUTHENTICATION_ERROR",
            f"Authentication check failed: {str(e)}"
        )
        return False

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return jsonify({'error': 'Authentication required'}), 401, {
        'WWW-Authenticate': 'Basic realm="Login Required"'
    }

def requires_auth(f):
    """Decorator for authentication with rate limiting"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            security_logger.log_security_event(
                "AUTHENTICATION_FAILED",
                f"Failed authentication attempt from {request.remote_addr}"
            )
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def add_security_headers(response):
    """
    Adds comprehensive security headers to prevent XSS and other attacks.
    """
    # Content Security Policy
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
    
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

@app.after_request
def security_headers(response):
    """Apply security headers to all responses"""
    return add_security_headers(response)

@app.before_request
def before_request():
    """Pre-request processing for security and monitoring"""
    global request_counter, active_connections
    
    # Increment counters
    request_counter += 1
    active_connections += 1
    
    # Check request size
    if request.content_length and request.content_length > MAX_REQUEST_SIZE:
        security_logger.log_security_event(
            "REQUEST_SIZE_EXCEEDED",
            f"Request size {request.content_length} exceeds limit {MAX_REQUEST_SIZE}"
        )
        return jsonify({'error': 'Request too large'}), 413
    
    # Store request start time for monitoring
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Post-request processing for monitoring"""
    global active_connections
    
    # Decrement active connections
    active_connections -= 1
    
    # Log request duration for monitoring
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        if duration > 5.0:  # Log slow requests
            security_logger.log_security_event(
                "SLOW_REQUEST",
                f"Request took {duration:.2f} seconds"
            )
    
    return response

# Request validation schemas
class DAGTriggerSchema(Schema):
    """Schema for DAG trigger requests"""
    dagName = fields.Str(required=True, validate=lambda x: len(x) <= MAX_DAG_NAME_LENGTH)
    environmentName = fields.Str(required=True, validate=lambda x: x.upper() in ALLOWED_ENVIRONMENTS)

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
        raise RuntimeError('Log file could not be created.')
    
    log.setLevel(logging.INFO)

    # Environment variable loading
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

        # Validate and sanitize AWS API response data
        web_server_host_name_raw = response.get("WebServerHostname")
        web_token_raw = response.get("WebToken")
        
        if not web_server_host_name_raw or not web_token_raw:
            log.error("Invalid response from AWS MWAA API")
            return None
        
        # Validate hostname format
        if not re.match(r'^[a-zA-Z0-9.-]+$', web_server_host_name_raw):
            log.error(f"Invalid hostname format received from AWS: {web_server_host_name_raw}")
            return None
            
        web_server_host_name = sanitize_input(web_server_host_name_raw)
        web_token = sanitize_input(web_token_raw)
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
                    allow_redirects=True,
                    verify=True  # Verify SSL certificates
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
            'dag_name': sanitize_input(dag_name),
            'message': f"Invalid input: {sanitize_input(str(e))}"
        }
    
    log, env, region, airflow_instance, _ = setup_airflow_context(safe_dag_name, safe_env_val)
    session_info = get_session_info(log, region, airflow_instance)

    if not session_info:
        log.error("Authentication failed, no session info retrieved.")
        close_log(log.name)
        return {
            'status': 'Failure',
            'dag_name': sanitize_input(dag_name),
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
            # Get and sanitize response from external API
            raw_dag_run_data = external_api_response.json()
            sanitized_dag_run_data = sanitize_input(raw_dag_run_data)
            
            # Extract sanitized dag_run_id
            dag_run_id_sanitized = sanitized_dag_run_data.get('dag_run_id', '') if isinstance(sanitized_dag_run_data, dict) else ''
            
            log.info(f"DAG triggered successfully: {safe_dag_name} with run id {dag_run_id_sanitized}")
            
            success_response = {
                'status': 'Success',
                'dag_name': sanitize_input(dag_name),
                'dag_run_id': dag_run_id_sanitized,
                'message': 'DAG triggered successfully'
            }
            return success_response
        else:
            # Sanitize external API error response
            sanitized_response_text = sanitize_input(external_api_response.text[:500])
            log.error(f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_response_text}")
            
            error_response = {
                'status': 'Failure',
                'dag_name': sanitize_input(dag_name),
                'message': f"Failed to trigger DAG: HTTP {external_api_response.status_code} - {sanitized_response_text}"
            }
            return error_response
            
    except requests.RequestException as e:
        log.error(f"Request to trigger DAG failed: {str(e)}")
        
        exception_response = {
            'status': 'Failure',
            'dag_name': sanitize_input(dag_name),
            'message': f"Request failed: {sanitize_input(str(e))}"
        }
        return exception_response
    finally:
        close_log(log.name)

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
                        "dag_name": sanitize_input(dag_name),
                        "env_val": sanitize_input(env_val),
                        "error": sanitize_input(str(e))
                    }
                })

        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        return jsonify(responses), status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'DAG trigger endpoint - use POST to trigger DAGs'}
        return jsonify(safe_response), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0',
        'uptime': time.time() - app.start_time if hasattr(app, 'start_time') else 0
    })

@app.route('/metrics', methods=['GET'])
@requires_auth
def metrics():
    """Metrics endpoint for monitoring"""
    return jsonify({
        'requests_total': request_counter,
        'errors_total': error_counter,
        'active_connections': active_connections,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors securely"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors securely"""
    security_logger.log_security_event(
        "INTERNAL_ERROR",
        f"Internal server error: {str(error)}"
    )
    return jsonify({'error': 'Internal server error'}), 500

# Start the server with secure configuration
if __name__ == '__main__':
    # Store start time for uptime calculation
    app.start_time = time.time()
    
    # Create secure SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain('resources/cert.pem', 'resources/key.pem')
    
    # Set secure cipher suites
    context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
    
    # Run with secure configuration
    app.run(
        host='0.0.0.0', 
        port=8982, 
        ssl_context=context,
        threaded=True,
        debug=False  # Disable debug mode in production
    )