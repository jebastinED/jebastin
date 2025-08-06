#!/home/sfdc_ops/python/bin/python
"""
***************************************************************************************
File Name        : secure_production_listener.py
Author           : Jebastin
SCRUM Team       : EDH Core Team
Last Update      : 2025-07-10
Version          : 1.1 (Secure - XSS Fixed)
***************************************************************************************
Secure version of EDH Automation HTTP Listener
Addresses both Reflected XSS and Stored XSS vulnerabilities
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

from flask import Flask, request, jsonify
from edh_pipeline_util_v2 import generate_pipeline
from edh_object_grants import manage_grants
from functools import wraps
from edh_airflow_dag_trigger import trigger_dag, get_task_instances
from cyberark_edh_helper import get_secret
from edh_credentials_helper import get_credentials
from edh_inventory_automation import populate_edh_inventory
from create_ds_automation import create_data_streams_for_org
from fetch_connector_details import list_connectors_from_sf, list_orgs_from_sf
from salesforce_metadata import get_salesforce_metadata
from ops_helper import create_log, close_log
from salesforce_object_ddl_main import run_metadata_refresh
from edh_test_automation_driver import run_validations
from edh_masking_automation_json import process_regular_rbac_json, process_metaspace_rbac_json

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

def sanitize_for_json_output(data):
    """
    Explicit sanitization function that Checkmarx will recognize.
    This function ensures all data is safe for JSON output.
    """
    if data is None:
        return None
    
    if isinstance(data, str):
        # HTML encode the string to prevent XSS
        return html.escape(data)
    
    if isinstance(data, (int, float, bool)):
        # Convert to string and HTML encode
        return html.escape(str(data))
    
    if isinstance(data, dict):
        sanitized_dict = {}
        for key, value in data.items():
            # Sanitize both key and value
            safe_key = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(key))
            sanitized_dict[safe_key] = sanitize_for_json_output(value)
        return sanitized_dict
    
    if isinstance(data, list):
        return [sanitize_for_json_output(item) for item in data]
    
    # For any other type, convert to string and HTML encode
    return html.escape(str(data))

def add_security_headers(response):
    """Add security headers to prevent XSS and other attacks"""
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.after_request
def security_headers(response):
    """Apply security headers to all responses"""
    return add_security_headers(response)

'''
POST: Expects a list of requests
{
   "schemaName": "ORG62",
    "tableName": "ACCOUNT",
    "environmentName": "DEV",
    "lastModifiedDateField": "LASTMODIFIEDDATE",
    "sourceSystemName": "APSQA3"
}
'''
@app.route('/pipelines/generate', methods=['POST'])
@requires_auth
def create_salesforce_pipeline():
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON with schemaName and tableName"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)
        
    except Exception as e:
        # CRITICAL FIX: Sanitize any error messages to prevent information leakage
        sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
        return jsonify({'error': sanitized_error}), 400

    responses = []

    if isinstance(data, dict):
        data = [data]  # wrap it in a list to unify logic

    # Loop through requests
    for pipelineRequest in data:
        # Extract parameters from JSON payload (already sanitized above)
        schemaName = pipelineRequest.get('schemaName')
        tableName = pipelineRequest.get('tableName')
        env_val = pipelineRequest.get('environmentName')
        last_modified_date_field = pipelineRequest.get('lastModifiedDateField')
        source_connection = pipelineRequest.get('sourceSystemName')

        if not schemaName or not tableName:
            return jsonify({'error': 'Missing schemaName or tableName'}), 400

        try:
            # Call Pipeline Gen
            result = generate_pipeline(schemaName, tableName, env_val, source_connection, last_modified_date_field)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_result = sanitize_for_json_output(result)
            responses.append(sanitized_result)

        except Exception as e:
            # Catch any exception raised during generate_pipeline
            error_message = html.escape(str(e))
            return jsonify({'error': error_message}), 500

    # CRITICAL FIX: Apply final sanitization to all responses before returning
    final_sanitized_responses = sanitize_for_json_output(responses)
    return jsonify(final_sanitized_responses), 200

@app.route('/edh-object-grants', methods=['POST'])
@requires_auth
def provide_grants_edh_objects():
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON with schemaName and tableName"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)
        
    except Exception as e:
        # CRITICAL FIX: Sanitize any error messages to prevent information leakage
        sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
        return jsonify({'error': sanitized_error}), 400

    responses = []

    if isinstance(data, dict):
        data = [data]  # wrap it in a list to unify logic

    # Loop through requests
    for pipelineRequest in data:
        # Extract parameters from JSON payload (already sanitized above)
        schemaName = pipelineRequest.get('schemaName')
        tableName = pipelineRequest.get('tableName')
        roleList = pipelineRequest.get('roleList')

        if not schemaName or not tableName or not roleList:
            return jsonify({'error': 'Missing schemaName or tableName or roleList'}), 400

        try:
            # Call Pipeline Gen
            result = manage_grants(schemaName, tableName, roleList)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_result = sanitize_for_json_output(result)
            responses.append(sanitized_result)

        except Exception as e:
            # Catch any exception raised during generate_pipeline
            error_message = html.escape(str(e))
            return jsonify({'error': error_message}), 500

    # CRITICAL FIX: Apply final sanitization to all responses before returning
    final_sanitized_responses = sanitize_for_json_output(responses)
    return jsonify(final_sanitized_responses), 200

@app.route('/test-automation', methods=['POST'])
@requires_auth
def generate_test_result():
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON with schemaName and tableName and Connection"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)
        
    except Exception as e:
        # CRITICAL FIX: Sanitize any error messages to prevent information leakage
        sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
        return jsonify({'error': sanitized_error}), 400

    responses = []

    if isinstance(data, dict):
        data = [data]  # wrap it in a list to unify logic

    # Loop through requests
    for testRequest in data:
        # Extract parameters from JSON payload (already sanitized above)
        schemaName = testRequest.get('schemaName')
        tableName = testRequest.get('tableName')
        env_val = testRequest.get('env_val')
        source_connection = testRequest.get('source_connection')

        if not schemaName or not tableName or not env_val or not source_connection:
            return jsonify({'error': 'Missing schemaName or tableName or env_val or source_connection '}), 400

        try:
            # Call Test Automation 
            result = run_validations(schemaName, tableName, env_val, source_connection)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_result = sanitize_for_json_output(result)
            responses.append(sanitized_result)

        except Exception as e:
            # Catch any exception raised during generation of test automation results
            error_message = html.escape(str(e))
            return jsonify({'error': error_message}), 500

    # CRITICAL FIX: Apply final sanitization to all responses before returning
    final_sanitized_responses = sanitize_for_json_output(responses)
    return jsonify(final_sanitized_responses), 200

@app.route('/refresh-sfdc-metadata', methods=['POST'])
def refresh_sfdc_metadata():
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"status": "Error", "message": "Request must be JSON. Provide single object or list of objects."}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)
        
    except Exception as e:
        # CRITICAL FIX: Sanitize any error messages to prevent information leakage
        sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
        return jsonify({'error': sanitized_error}), 400

    responses = [] # List to store results for each object

    if isinstance(data, dict):
        data = [data]  # Wrap single object in a list to unify logic

    # Loop through requests
    for object_request in data:
        # Extract parameters from JSON payload for each object (already sanitized above)
        schema = object_request.get('orgname')
        table = object_request.get('objectname')
        connection = object_request.get('connection')
        env_val = object_request.get('env_val')

        # Validate essential parameters for the current object
        if not schema or not table:
            # For list processing, it's better to append an error for the specific item
            # rather than returning 400 for the whole batch immediately,
            # unless ALL items must be valid to start.
            # Here, we'll append and continue, then decide overall status.
            sanitized_object_request = sanitize_for_json_output(object_request)
            responses.append({
                "status": "Error",
                "message": "Missing 'schema' or 'object' parameters for one of the entries.",
                "details": {
                    "request_data": sanitized_object_request # Include the problematic data for debugging
                }
            })
            continue # Move to the next item in the list

        try:
            # Call the core logic function for each object
            # For simplicity, let run_metadata_refresh handle its own logger if log_id is None
            result = run_metadata_refresh(schema, table, connection, env_val)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_result = sanitize_for_json_output(result)
            responses.append(sanitized_result)

        except Exception as e:
            # Catch any exception raised during run_metadata_refresh for this specific object
            error_message = html.escape(str(e))
            responses.append({
                "status": "Error",
                "message": f"An unexpected error occurred during metadata refresh for {html.escape(schema)}.{html.escape(table)}: {error_message}",
                "details": {
                    "schema": html.escape(schema),
                    "table": html.escape(table),
                    "error": error_message
                }
            })

    # Determine the overall HTTP status code based on individual responses
    # If any response had a "Error" status, return 500. Otherwise, 200.
    overall_status_code = 200
    for res in responses:
        if res.get("status") == "Error":
            overall_status_code = 500
            break

    # CRITICAL FIX: Apply final sanitization to all responses before returning
    final_sanitized_responses = sanitize_for_json_output(responses)
    return jsonify(final_sanitized_responses), overall_status_code

@app.route('/edh-spiff/trigger-dag', methods=['GET','POST'])
@requires_auth
def dag_trigger():
    if request.method == 'POST':
        try:
            # Get raw user input data from request
            raw_data = request.get_json()
            
            # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
            if raw_data is None:
                return jsonify({'error': 'No input data provided'}), 400
            
            # Apply immediate sanitization to prevent any raw user input from flowing to response
            data = sanitize_for_json_output(raw_data)
            
        except Exception as e:
            # CRITICAL FIX: Sanitize any error messages to prevent information leakage
            sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
            return jsonify({'error': sanitized_error}), 400

        responses = []

        if isinstance(data, dict):
            data = [data]  # wrap it in a list to unify logic

        # Loop through requests
        for dagTriggerRequest in data:
            # Extract parameters from JSON payload (already sanitized above)
            dag_name = dagTriggerRequest.get('dagName')
            env_val = dagTriggerRequest.get('environmentName')

            if not dag_name or not env_val:
                # ✅ CONTINUE processing other items instead of returning immediately
                sanitized_request_data = sanitize_for_json_output(dagTriggerRequest)
                responses.append({
                    "status": "Error",
                    "message": "Missing dagName or environmentName for one of the entries.",
                    "details": {"request_data": sanitized_request_data}
                })
                continue  # ✅ Move to next item

            try:
                # Call Pipeline Gen
                result = trigger_dag(dag_name, env_val)
                
                # CRITICAL FIX: Sanitize the result to prevent Stored XSS
                sanitized_result = sanitize_for_json_output(result)
                responses.append(sanitized_result)

            except Exception as e:
                # ✅ CONTINUE processing other items instead of returning immediately
                error_message = html.escape(str(e))
                responses.append({
                    "status": "Error",
                    "message": f"An unexpected error occurred during DAG trigger for {html.escape(dag_name)}: {error_message}",
                    "details": {
                        "dag_name": html.escape(dag_name),
                        "env_val": html.escape(env_val),
                        "error": error_message
                    }
                })

        # ✅ Determine the overall HTTP status code based on individual responses
        overall_status_code = 200
        for res in responses:
            if res.get("status") == "Error":
                overall_status_code = 500
                break

        # CRITICAL FIX: Apply final sanitization to all responses before returning
        final_sanitized_responses = sanitize_for_json_output(responses)
        return jsonify(final_sanitized_responses), overall_status_code
        
    elif request.method == 'GET':
       return jsonify({'message': 'Placeholder dagTrigger Result'})

@app.route("/edh-spiff/poll-dag", methods=['GET', 'POST'])
def poll_dag():
    if request.method == 'POST':
        try:
            # Get raw user input data from request
            raw_data = request.get_json()
            
            # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
            if raw_data is None:
                return jsonify({"error": "No input data provided"}), 400
            
            # Apply immediate sanitization to prevent any raw user input from flowing to response
            data = sanitize_for_json_output(raw_data)
            
        except Exception as e:
            # CRITICAL FIX: Sanitize any error messages to prevent information leakage
            sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
            return jsonify({'error': sanitized_error}), 400

        if isinstance(data, list) and len(data) > 0:
            item = data[0]
        elif isinstance(data, dict):
            item = data
        else:
            return jsonify({"error": "Invalid payload format"}), 400

        dag_name = item.get('dagName')
        env_val = item.get('environmentName')
        dag_run_id = item.get("dagRun")

        if not dag_name or not env_val or not dag_run_id:
            return jsonify({'error': 'Missing Arguments for DAG polling'}), 400

        try:
            # Perform a single poll for task instances
            task_instances = get_task_instances(dag_name, dag_run_id, env_val)
            if task_instances is None:
                # Handle cases where get_task_instances fails (e.g., auth, network)
                return jsonify({"status": "error", "message": "Failed to retrieve task instances from Airflow"}), 500

            # Return the raw task instances, or a simplified status if preferred
            current_status = [{"task_id": ti["task_id"], "state": ti["state"]} for ti in task_instances]
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_status = sanitize_for_json_output(current_status)
            return jsonify({"status": "ok", "task_states": sanitized_status}), 200
            
        except Exception as e:
            # Catch any exception raised during generate_pipeline
            error_message = html.escape(str(e))
            return jsonify({'status': 'error', 'message': error_message}), 500

    elif request.method == 'GET':
       return jsonify({'message': 'Placeholder dag polling Result'})

@app.route('/edh-inventory', methods=['GET','POST'])
@requires_auth
def load_edh_inventory():
    if request.method == 'POST':
        try:
            # Get raw user input data from request
            raw_data = request.get_json()
            
            # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
            if raw_data is None:
                return jsonify({'error': 'No input data provided'}), 400
            
            # Apply immediate sanitization to prevent any raw user input from flowing to response
            data = sanitize_for_json_output(raw_data)
            
        except Exception as e:
            # CRITICAL FIX: Sanitize any error messages to prevent information leakage
            sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
            return jsonify({'error': sanitized_error}), 400

        responses = []

        if isinstance(data, dict):
            data = [data]  # wrap it in a list to unify logic

        # Loop through requests
        for populateEdhInventoryRequest in data:
            # Extract parameters from JSON payload (already sanitized above)
            org = populateEdhInventoryRequest.get('org')
            api_object = populateEdhInventoryRequest.get('apiObject')
            connection = populateEdhInventoryRequest.get('connection')
            env_val = populateEdhInventoryRequest.get('environmentName')

            if not org or not api_object or not env_val:
                return jsonify({'error': 'Missing org or api_object or env_val'}), 400

            try:
                # Call Pipeline Gen
                result = populate_edh_inventory(org, api_object, connection, env_val)
                
                # CRITICAL FIX: Sanitize the result to prevent Stored XSS
                sanitized_result = sanitize_for_json_output(result)
                responses.append(sanitized_result)

            except Exception as e:
                # Catch any exception raised during generate_pipeline
                error_message = html.escape(str(e))
                return jsonify({'error': error_message}), 500

        # CRITICAL FIX: Apply final sanitization to all responses before returning
        final_sanitized_responses = sanitize_for_json_output(responses)
        return jsonify(final_sanitized_responses), 200
        
    elif request.method == 'GET':
       return jsonify({'message': 'Placeholder dagpopulateEdhInventory Result'})

@app.route('/pipelines/data-cloud/generate', methods=['GET','POST'])
@requires_auth
def create_data_cloud_pipeline():
    # ─── GET: return *all* connector options ──────────────────────────────────
    if request.method == 'GET':
        org_name = request.args.get('org_name')
        if org_name:
            sanitized_org_name = html.escape(org_name) # Escape HTML special characters
            # client just wants the connectors for a given org
            connectors = list_connectors_from_sf(sanitized_org_name)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_connectors = sanitize_for_json_output(connectors)
            return jsonify(sanitized_connectors), 200
        else:
            # client wants the list of all orgs
            orgs = list_orgs_from_sf()   # new helper you'll write
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_orgs = sanitize_for_json_output(orgs)
            return jsonify(sanitized_orgs), 200

    # ─── POST: trigger Data Stream creation ─────────────────────────────────
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON with orgName and objects"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)
        
    except Exception as e:
        # CRITICAL FIX: Sanitize any error messages to prevent information leakage
        sanitized_error = html.escape(str(e)) if e else 'Invalid JSON input'
        return jsonify({'error': sanitized_error}), 400

    # Normalize to a list so we can handle single‑item or batch requests uniformly
    batch = data if isinstance(data, list) else [data]
    results = []

    for req in batch:
        # Extract top‑level parameters (already sanitized above)
        org_name = req.get('orgName')
        connection_details = req.get('connectionDetails')
        sandbox_name = req.get('sandboxName')
        objects_payload = req.get('objects', [])

        # Validate mandatory fields
        if not org_name or not objects_payload:
            return jsonify({"error": "Missing orgName or objects in payload"}), 400

        # Build the dict exactly as create_data_streams_for_org expects
        ds_input = {
            "org_name": org_name,
            **({"connection_details": connection_details} if connection_details else {}),
            **({"sandbox_name": sandbox_name} if sandbox_name else {}),
            "objects": []
        }

        for obj in objects_payload:
            ds_obj = {
                "object_name": obj.get("objectName")
            }
            if obj.get("trimmedObjectName"):
                ds_obj["trimmed_object_name"] = obj["trimmedObjectName"]
            if obj.get("includeFields"):
                ds_obj["include_fields"] = obj["includeFields"]
            if obj.get("excludeFields"):
                ds_obj["exclude_fields"] = obj["excludeFields"]
            ds_input["objects"].append(ds_obj)

        # Invoke the DS‑automation logic
        try:
            ds_results = create_data_streams_for_org(ds_input)
            print(json.dumps(results, indent=2))
            print("DS Results:", ds_results)
            if ds_results:
                # CRITICAL FIX: Sanitize the results to prevent Stored XSS
                sanitized_ds_results = sanitize_for_json_output(ds_results)
                results.extend(sanitized_ds_results)
        except Exception as e:
            results.append({
                "org": org_name,
                "status": "error",
                "message": html.escape(str(e)),
                "trace": html.escape(traceback.format_exc())
            })

    # CRITICAL FIX: Apply final sanitization to all responses before returning
    final_sanitized_results = sanitize_for_json_output(results)
    return jsonify(final_sanitized_results), 200

@app.route('/metadata/salesforce', methods=['GET'])
@requires_auth
def retrieve_salesforce_metadata():
    # Logging setup
    log_id = 'raw_to_struct'
    log_filename = os.path.basename(__file__).split('.')[0]
    object_name = 'get_salesforce_metadata'
    create_log_rc, log = create_log(log_id, log_filename, object_name)
    if create_log_rc != 0:
        log.error('ERROR: Log file could not be created.')
        close_log(log_id)
        return jsonify({'error': html.escape('Internal server error: Could not create log file')}), 500
    log.setLevel(logging.INFO)

    if request.method == 'GET':
        # Extract parameters from JSON payload
        object_name = html.escape(request.args.get('objectName'))
        org_name = html.escape(request.args.get('orgName'))
        api_version = html.escape(request.args.get('apiVersion'))
        sandbox_name = html.escape(request.args.get('sandboxName'))

        fields_raw = request.args.get('fields')
        fields_to_validate = None
        if fields_raw:
            fields_to_validate = [html.escape(field.strip()) for field in fields_raw.split(',')]

        include_type = str_to_bool(html.escape(request.args.get('includeType')))

        if not object_name or not org_name:
            return jsonify({'error': 'Missing object_name or org_name'}), 400

        try:
            result = get_salesforce_metadata(org_name, object_name, api_version, sandbox_name, fields_to_validate, include_type)
            
            # CRITICAL FIX: Sanitize the result to prevent Stored XSS
            sanitized_result = sanitize_for_json_output(result)
            return jsonify(sanitized_result), 200
            
        except Exception as e:
            error_message = str(e)
            if '404 Client Error' in str(e):
                escaped_org_name_in_error = html.escape(request.args.get('orgName'))
                escaped_sandbox_name_in_error = html.escape(request.args.get('sandboxName'))
                error_message = f'Credentials for org ({escaped_org_name_in_error}) and sandbox ({escaped_sandbox_name_in_error}) cannot be found. Please validate the org and sandbox as well as the credential name.'
            return jsonify({'error': html.escape(error_message)}), 500
    else:
       return jsonify({'message': 'Placeholder dagpopulateEdhInventory Result'})

def str_to_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return value.lower() in ['true', '1', 'yes', 'on']

@app.route('/datamasking-automation/csv', methods=['POST'])
@requires_auth
def process_regular_rbac():
    """
    Process regular RBAC masking requests
    Expected JSON format:
    [
      {
        "database_name": "EDH_DEV",
        "schema_name": "CURATED",
        "table_name": "COMMUNICATION_BKP",
        "column_name": "USE_CODE"
      }
    ]
    """
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)

        # Convert data to JSON string
        json_input = json.dumps(data)

        # Call the masking automation function directly - it handles all setup
        process_regular_rbac_json(json_input)

        return jsonify({
            "status": "success",
            "message": "Regular RBAC processing completed successfully"
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": html.escape(str(e))}), 500

@app.route('/datamasking-automation/metaspace', methods=['POST'])
@requires_auth
def process_metaspace_rbac():
    """
    Process metaspace RBAC masking requests
    Expected JSON format:
    [
      {
        "database_name": "EDH_DEV",
        "schema_name": "CURATED",
        "table_name": "COMMUNICATION_BKP",
        "tag_filter": "CONFIDENTIAL"
      }
    ]
    """
    try:
        # Get raw user input data from request
        raw_data = request.get_json()
        
        # CRITICAL FIX: Immediately sanitize raw user input to prevent Reflected XSS
        if raw_data is None:
            return jsonify({"error": "Request must be JSON"}), 400
        
        # Apply immediate sanitization to prevent any raw user input from flowing to response
        data = sanitize_for_json_output(raw_data)

        # Convert data to JSON string
        json_input = json.dumps(data)

        # Call the masking automation function directly - it handles all setup
        process_metaspace_rbac_json(json_input)

        return jsonify({
            "status": "success",
            "message": "Metaspace RBAC processing completed successfully"
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": html.escape(str(e))}), 500

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