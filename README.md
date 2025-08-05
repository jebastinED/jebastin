# EDH Automation HTTP Listener

This Flask application provides an HTTP API for triggering AWS MWAA (Managed Workflows for Apache Airflow) DAGs with enhanced security features.

## Security Fixes Applied

### XSS Vulnerability Mitigation
The application has been updated to address Reflected XSS vulnerabilities identified by security scanning:

1. **Input Sanitization**: All user inputs are now properly sanitized using `html.escape()` before being included in responses
2. **Deep Sanitization**: The `_deep_html_escape_json_data()` function ensures recursive sanitization of all response data
3. **Immediate Sanitization**: User inputs are sanitized immediately upon receipt and validation
4. **Error Message Sanitization**: All error messages and exception details are properly escaped

### Key Security Improvements:
- **Line 183-184**: Added `html.escape()` to `dag_name` in error responses
- **Line 192**: Added `html.escape()` to `dag_name` in authentication failure responses  
- **Line 207-209**: Added sanitization to success response fields (`dag_name`, `dag_run_id`)
- **Line 213-214**: Added sanitization to failure response fields and error messages
- **Line 220-221**: Added sanitization to exception handling responses
- **Line 238-245**: Enhanced input validation and sanitization in the main endpoint
- **Line 254-261**: Added explicit sanitization for error responses with user input data
- **Line 268-274**: Added sanitization to exception handling within the request loop

## Features

- **Basic HTTP Authentication**: Secure endpoint access with username/password
- **AWS MWAA Integration**: Direct integration with AWS Managed Workflows for Apache Airflow
- **SSL/TLS Support**: HTTPS encryption for secure communication
- **Input Validation**: Comprehensive validation and sanitization of all inputs
- **Logging**: Detailed logging for audit and debugging purposes
- **Error Handling**: Robust error handling with sanitized error messages

## Prerequisites

1. Python 3.8+
2. AWS credentials with MWAA access
3. SSL certificates (cert.pem and key.pem)
4. Required Python packages (see requirements.txt)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure SSL certificates in the `resources/` directory:
   - Replace `resources/cert.pem` with your SSL certificate
   - Replace `resources/key.pem` with your SSL private key

3. Ensure the following helper modules are available:
   - `cyberark_edh_helper`
   - `edh_credentials_helper` 
   - `ops_helper`

## Usage

### Starting the Server
```bash
python edh_automation_http_listener.py
```

The server will start on port 8982 with HTTPS enabled.

### API Endpoints

#### POST /edh-spiff/trigger-dag
Triggers one or more DAGs in the specified MWAA environment.

**Authentication**: Basic HTTP Authentication required

**Request Body** (JSON):
```json
[
  {
    "dagName": "example_dag",
    "environmentName": "DEV"
  }
]
```

**Response**:
```json
[
  {
    "status": "Success",
    "dag_name": "example_dag",
    "dag_run_id": "manual__2025-01-01T00:00:00+00:00",
    "message": "DAG triggered successfully"
  }
]
```

#### GET /edh-spiff/trigger-dag
Returns a placeholder response for testing connectivity.

## Security Considerations

1. **Input Validation**: All inputs are validated and sanitized to prevent XSS attacks
2. **Authentication**: Basic HTTP authentication protects the endpoints
3. **HTTPS**: SSL/TLS encryption ensures secure data transmission
4. **Error Handling**: Error messages are sanitized to prevent information disclosure
5. **Logging**: Security events are logged for monitoring and auditing

## Environment Variables

- `ENVIRONMENT`: Determines the target environment (DEV, TEST, PROD, STG)

## Error Handling

The application provides comprehensive error handling with sanitized error messages:
- Invalid JSON input
- Missing required parameters
- Authentication failures
- AWS API errors
- Network connectivity issues

All error responses are properly sanitized to prevent XSS vulnerabilities while maintaining useful debugging information.