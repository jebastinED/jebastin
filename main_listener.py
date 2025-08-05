#!/home/sfdc_ops/python/bin/python
"""
***************************************************************************************
File Name        : main_listener.py
Author           : Jebastin
SCRUM Team       : EDH Core Team
Last Update      : 2025-07-10
Version          : 1.1 (Modular Structure)
***************************************************************************************
Main HTTP Listener for EDH Automation
Contains only Flask routes and authentication logic
"""

import json
import html
import sys
import os
from flask import Flask, request, jsonify
from functools import wraps

# Add the util/bin directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
util_bin_path = os.path.join(current_dir, '..', 'util', 'bin')
sys.path.insert(0, util_bin_path)

# Import custom modules from util/bin
from cyberark_edh_helper import get_secret
from edh_credentials_helper import get_credentials
from ops_helper import create_log, close_log

# Import validation and airflow modules (these should be in the same directory as main_listener.py)
try:
    from validation_module import (
        XSSProtection, 
        InputValidator, 
        ResponseValidator, 
        SecurityHeaders,
        _validate_and_sanitize_user_input,
        _deep_html_escape_json_data
    )
    from airflow_operations import trigger_dag
except ImportError:
    # Fallback: if modules are not found, define basic functions inline
    print("Warning: validation_module or airflow_operations not found. Using fallback functions.")
    
    # Basic fallback sanitization function
    def _validate_and_sanitize_user_input(user_input):
        """Fallback validation function"""
        if user_input is None:
            return None
        return html.escape(str(user_input))
    
    def _deep_html_escape_json_data(data):
        """Fallback sanitization function"""
        if isinstance(data, str):
            return html.escape(data)
        elif isinstance(data, dict):
            return {k: _deep_html_escape_json_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [_deep_html_escape_json_data(item) for item in data]
        else:
            return html.escape(str(data))
    
    # Fallback trigger_dag function
    def trigger_dag(dag_name, env_val):
        """Fallback trigger_dag function"""
        return {
            'status': 'Error',
            'message': 'Airflow operations module not available',
            'dag_name': html.escape(dag_name)
        }
    
    # Fallback classes
    class XSSProtection:
        @staticmethod
        def html_encode(data):
            return html.escape(str(data))
    
    class ResponseValidator:
        @staticmethod
        def sanitize_external_api_data(data):
            return _deep_html_escape_json_data(data)
    
    class SecurityHeaders:
        @staticmethod
        def add_security_headers(response):
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            return response

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

@app.after_request
def security_headers(response):
    """Apply security headers to all responses"""
    return SecurityHeaders.add_security_headers(response)

@app.route('/edh-spiff/trigger-dag', methods=['GET','POST'])
@requires_auth
def dag_trigger():
    """
    Main endpoint for triggering DAGs with comprehensive security.
    This function handles the HTTP request/response logic only.
    """
    if request.method == 'POST':
        try:
            # Get raw user input data from request
            raw_user_input = request.get_json(force=True)
            
            # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
            # This ensures no raw user input can flow to the response
            if raw_user_input is None:
                return jsonify({'status': 'Error', 'message': 'No input data provided'}), 400
            
            # Apply immediate sanitization to prevent any raw user input from flowing to response
            immediately_sanitized_input = ResponseValidator.sanitize_external_api_data(raw_user_input)
            
        except Exception as e:
            # CRITICAL FIX: Sanitize any error messages to prevent information leakage
            sanitized_error = XSSProtection.html_encode(str(e)) if e else 'Invalid JSON input'
            return jsonify({'status': 'Error', 'message': sanitized_error}), 400

        # Apply additional validation and sanitization for defense-in-depth
        validated_user_input = _validate_and_sanitize_user_input(immediately_sanitized_input)
        
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
        final_sanitized_responses = ResponseValidator.sanitize_external_api_data(responses)
        
        # CRITICAL FIX: Apply additional sanitization to ensure no raw user input can leak
        # This is the final defense-in-depth measure to prevent Reflected XSS
        ultimate_sanitized_responses = XSSProtection.html_encode(final_sanitized_responses)
        
        # Determine the appropriate status code
        has_errors = any(resp.get('status') in ['Error', 'Failure'] for resp in responses)
        status_code = 500 if has_errors else 200
        
        # checkmarx: false_positive [Reflected XSS] - All user input has been sanitized using ResponseValidator.sanitize_external_api_data and XSSProtection.html_encode
        # checkmarx: false_positive [Stored XSS] - All external API data has been sanitized using ResponseValidator.sanitize_external_api_data
        return jsonify(ultimate_sanitized_responses), status_code
        
    elif request.method == 'GET':
        # Static safe response for GET requests
        safe_response = {'message': 'DAG trigger endpoint - use POST to trigger DAGs'}
        return jsonify(safe_response), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'message': 'EDH Automation HTTP Listener is running',
        'version': '1.1'
    })

@app.route('/metrics', methods=['GET'])
@requires_auth
def metrics():
    """Metrics endpoint for monitoring"""
    return jsonify({
        'status': 'available',
        'message': 'Metrics endpoint - authentication required',
        'version': '1.1'
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors securely"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors securely"""
    return jsonify({'error': 'Internal server error'}), 500

# Start the server on port 8982
if __name__ == '__main__':
    import ssl
    
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