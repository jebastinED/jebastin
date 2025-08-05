# Modular EDH Automation HTTP Listener - Deployment Guide

## Overview

The application has been restructured into modular components for better organization and maintainability:

- **`main_listener.py`** - Flask routes and authentication logic
- **`validation_module.py`** - Input validation and sanitization
- **`airflow_operations.py`** - Airflow setup, session management, and DAG triggering

## File Structure

```
edh_automation/
├── main_listener.py          # Main Flask application
├── validation_module.py      # Validation and sanitization
├── airflow_operations.py     # Airflow operations
├── requirements.txt          # Dependencies
├── resources/               # SSL certificates
│   ├── cert.pem
│   └── key.pem
└── logs/                    # Application logs
```

## Module Responsibilities

### 1. `main_listener.py`
- **Purpose**: Flask application with routes and authentication
- **Contains**:
  - Flask app configuration
  - Authentication logic
  - HTTP route handlers
  - Security headers
  - Error handlers

### 2. `validation_module.py`
- **Purpose**: Input validation and XSS protection
- **Contains**:
  - `XSSProtection` class
  - `InputValidator` class
  - `ResponseValidator` class
  - `SecurityHeaders` class
  - Legacy compatibility functions

### 3. `airflow_operations.py`
- **Purpose**: Airflow-specific operations
- **Contains**:
  - `setup_airflow_context()`
  - `get_session_info()`
  - `trigger_dag()`
  - URL sanitization functions

## Deployment Steps

### Step 1: Create Directory Structure

```bash
# Create application directory
mkdir -p /opt/edh_automation
cd /opt/edh_automation

# Create subdirectories
mkdir -p resources logs
```

### Step 2: Deploy Modules

```bash
# Copy all modules to the application directory
cp main_listener.py /opt/edh_automation/
cp validation_module.py /opt/edh_automation/
cp airflow_operations.py /opt/edh_automation/

# Copy SSL certificates
cp cert.pem /opt/edh_automation/resources/
cp key.pem /opt/edh_automation/resources/

# Set proper permissions
chmod 600 /opt/edh_automation/resources/key.pem
chmod 644 /opt/edh_automation/resources/cert.pem
```

### Step 3: Install Dependencies

```bash
# Create requirements.txt
cat > /opt/edh_automation/requirements.txt << EOF
Flask==3.0.0
requests==2.31.0
boto3==1.34.0
marshmallow==3.20.1
EOF

# Install dependencies
pip install -r /opt/edh_automation/requirements.txt
```

### Step 4: Configure Systemd Service

```bash
# Create systemd service file
cat > /etc/systemd/system/edh-automation.service << EOF
[Unit]
Description=EDH Automation HTTP Listener (Modular)
After=network.target

[Service]
Type=simple
User=edh_automation
Group=edh_automation
WorkingDirectory=/opt/edh_automation
Environment=PATH=/opt/edh_automation/bin
ExecStart=/opt/edh_automation/bin/python main_listener.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/edh_automation/logs

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable edh-automation
```

### Step 5: Start the Service

```bash
# Start the service
systemctl start edh-automation

# Check status
systemctl status edh-automation

# View logs
journalctl -u edh-automation -f
```

## Testing the Modular Structure

### 1. Test Individual Modules

```bash
# Test validation module
python -c "
from validation_module import XSSProtection, InputValidator
print('Validation module imported successfully')
test_data = {'test': '<script>alert(\"xss\")</script>'}
sanitized = XSSProtection.html_encode(test_data)
print(f'Sanitized: {sanitized}')
"

# Test Airflow operations module
python -c "
from airflow_operations import sanitize_url_path_segment
print('Airflow operations module imported successfully')
result = sanitize_url_path_segment('test-dag-name')
print(f'Sanitized URL: {result}')
"
```

### 2. Test Main Application

```bash
# Test the main application
cd /opt/edh_automation
python main_listener.py &
PID=$!

# Test health endpoint
curl -k https://localhost:8982/health

# Stop the application
kill $PID
```

## Maintenance and Updates

### Updating Individual Modules

```bash
# Update validation module only
cp validation_module.py /opt/edh_automation/
systemctl restart edh-automation

# Update Airflow operations only
cp airflow_operations.py /opt/edh_automation/
systemctl restart edh-automation

# Update main listener only
cp main_listener.py /opt/edh_automation/
systemctl restart edh-automation
```

### Adding New Validation Rules

1. **Edit `validation_module.py`**:
```python
class InputValidator:
    # Add new pattern
    NEW_FIELD_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    
    @staticmethod
    def validate_new_field(value: str) -> str:
        """Validate new field using whitelist approach"""
        if not value or not isinstance(value, str):
            raise ValueError("Field must be a non-empty string")
        
        if not InputValidator.NEW_FIELD_PATTERN.match(value):
            raise ValueError("Invalid field format")
        
        return value.strip()
```

2. **Import in `main_listener.py`**:
```python
from validation_module import InputValidator

# Use in route
validated_field = InputValidator.validate_new_field(raw_field)
```

### Adding New Airflow Operations

1. **Edit `airflow_operations.py`**:
```python
def new_airflow_operation(param1: str, param2: str) -> Dict[str, Any]:
    """New Airflow operation"""
    # Implementation here
    pass
```

2. **Import in `main_listener.py`**:
```python
from airflow_operations import new_airflow_operation

# Use in route
result = new_airflow_operation(param1, param2)
```

## Security Benefits of Modular Structure

### 1. **Separation of Concerns**
- Validation logic isolated in `validation_module.py`
- Airflow operations isolated in `airflow_operations.py`
- HTTP handling isolated in `main_listener.py`

### 2. **Easier Testing**
- Test validation functions independently
- Test Airflow operations independently
- Test HTTP routes independently

### 3. **Easier Maintenance**
- Update validation rules without touching HTTP logic
- Update Airflow operations without touching validation
- Update HTTP logic without touching business logic

### 4. **Better Code Organization**
- Clear responsibility boundaries
- Easier to find and fix issues
- Easier to add new features

## Troubleshooting

### Module Import Errors

```bash
# Check Python path
python -c "import sys; print(sys.path)"

# Add application directory to Python path
export PYTHONPATH="/opt/edh_automation:$PYTHONPATH"
```

### SSL Certificate Issues

```bash
# Check certificate permissions
ls -la /opt/edh_automation/resources/

# Fix permissions if needed
chmod 600 /opt/edh_automation/resources/key.pem
chmod 644 /opt/edh_automation/resources/cert.pem
chown edh_automation:edh_automation /opt/edh_automation/resources/*
```

### Service Startup Issues

```bash
# Check service status
systemctl status edh-automation

# View detailed logs
journalctl -u edh-automation -n 50

# Check file permissions
ls -la /opt/edh_automation/
```

## Migration from Monolithic Structure

If migrating from the original monolithic file:

1. **Backup original file**:
```bash
cp edh_automation_http_listener.py edh_automation_http_listener.py.backup
```

2. **Deploy modular structure**:
```bash
# Deploy new modules
cp main_listener.py /opt/edh_automation/
cp validation_module.py /opt/edh_automation/
cp airflow_operations.py /opt/edh_automation/
```

3. **Test thoroughly**:
```bash
# Test all functionality
curl -k -u username:password -X POST https://localhost:8982/edh-spiff/trigger-dag \
  -H "Content-Type: application/json" \
  -d '{"dagName": "test_dag", "environmentName": "DEV"}'
```

4. **Switch service**:
```bash
# Update systemd service to use main_listener.py
systemctl restart edh-automation
```

## Benefits of This Modular Structure

1. **Maintainability**: Easier to maintain and update individual components
2. **Testability**: Each module can be tested independently
3. **Reusability**: Modules can be reused in other applications
4. **Security**: Clear separation of concerns improves security
5. **Scalability**: Easier to scale individual components
6. **Debugging**: Easier to identify and fix issues

This modular structure provides better organization while maintaining all the security features needed to pass the Checkmarx Stored XSS scan.