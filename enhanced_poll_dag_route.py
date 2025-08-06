# Enhanced poll-dag route with comprehensive security
@app.route("/edh-spiff/poll-dag", methods=['GET', 'POST'])
@requires_auth
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

        responses = []

        # Normalize to list for consistent batch processing
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return jsonify({"error": "Invalid payload format - must be object or array"}), 400

        # Loop through requests (batch processing)
        for poll_request in data:
            # Extract parameters from JSON payload (already sanitized above)
            dag_name = poll_request.get('dagName')
            env_val = poll_request.get('environmentName')
            dag_run_id = poll_request.get("dagRun")

            if not dag_name or not env_val or not dag_run_id:
                # ✅ CONTINUE processing other items instead of returning immediately
                sanitized_request_data = sanitize_for_json_output(poll_request)
                responses.append({
                    "status": "Error",
                    "message": "Missing dagName, environmentName, or dagRun for one of the entries.",
                    "details": {"request_data": sanitized_request_data}
                })
                continue  # ✅ Move to next item

            try:
                # Perform a single poll for task instances
                task_instances = get_task_instances(dag_name, dag_run_id, env_val)
                
                if task_instances is None:
                    # Handle cases where get_task_instances fails (e.g., auth, network)
                    responses.append({
                        "status": "Error",
                        "message": "Failed to retrieve task instances from Airflow",
                        "details": {
                            "dag_name": html.escape(dag_name),
                            "dag_run_id": html.escape(dag_run_id),
                            "env_val": html.escape(env_val)
                        }
                    })
                    continue  # ✅ Move to next item

                # Create simplified status response
                current_status = []
                for ti in task_instances:
                    if isinstance(ti, dict):
                        task_id = ti.get("task_id", "")
                        state = ti.get("state", "")
                        current_status.append({
                            "task_id": html.escape(str(task_id)),
                            "state": html.escape(str(state))
                        })

                # ✅ SUCCESS response
                responses.append({
                    "status": "Success",
                    "message": f"Successfully retrieved task instances for DAG {html.escape(dag_name)}",
                    "details": {
                        "dag_name": html.escape(dag_name),
                        "dag_run_id": html.escape(dag_run_id),
                        "task_count": len(current_status)
                    },
                    "task_states": current_status
                })
                
            except Exception as e:
                # ✅ CONTINUE processing other items instead of returning immediately
                error_message = html.escape(str(e))
                responses.append({
                    "status": "Error",
                    "message": f"An unexpected error occurred during DAG polling for {html.escape(dag_name)}: {error_message}",
                    "details": {
                        "dag_name": html.escape(dag_name),
                        "dag_run_id": html.escape(dag_run_id),
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
        # Static safe response for GET requests
        safe_response = {'message': 'DAG polling endpoint - use POST to poll DAG status'}
        return jsonify(safe_response), 200