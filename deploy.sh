#!/bin/bash
# Deployment script for EDH Automation HTTP Listener (Modular Structure)

echo "=== EDH Automation HTTP Listener Deployment ==="
echo ""

# Get current directory
CURRENT_DIR=$(pwd)
echo "Current directory: $CURRENT_DIR"

# Check if we're in the right location
if [[ ! -d "util/bin" ]]; then
    echo "Error: util/bin directory not found. Please run this script from the src directory."
    echo "Expected structure: src/util/bin/"
    exit 1
fi

echo "✓ Found util/bin directory"

# Create backup of original file if it exists
if [[ -f "bin/edh_automation_http_listener.py" ]]; then
    echo "Creating backup of original file..."
    cp bin/edh_automation_http_listener.py bin/edh_automation_http_listener.py.backup.$(date +%Y%m%d_%H%M%S)
    echo "✓ Backup created"
fi

# Deploy the modular files
echo ""
echo "Deploying modular files..."

# Copy main listener
if [[ -f "main_listener.py" ]]; then
    cp main_listener.py bin/edh_automation_main_listener.py
    echo "✓ Deployed main_listener.py as edh_automation_main_listener.py"
else
    echo "⚠ Warning: main_listener.py not found in current directory"
fi

# Copy validation module
if [[ -f "validation_module.py" ]]; then
    cp validation_module.py bin/validation_module.py
    echo "✓ Deployed validation_module.py"
else
    echo "⚠ Warning: validation_module.py not found in current directory"
fi

# Copy airflow operations
if [[ -f "airflow_operations.py" ]]; then
    cp airflow_operations.py bin/airflow_operations.py
    echo "✓ Deployed airflow_operations.py"
else
    echo "⚠ Warning: airflow_operations.py not found in current directory"
fi

# Copy secure version
if [[ -f "secure_main_listener.py" ]]; then
    cp secure_main_listener.py bin/secure_main_listener.py
    echo "✓ Deployed secure_main_listener.py"
else
    echo "⚠ Warning: secure_main_listener.py not found in current directory"
fi

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Files deployed to bin/ directory:"
ls -la bin/*.py | grep -E "(edh_automation_main_listener|validation_module|airflow_operations|secure_main_listener)"

echo ""
echo "=== Next Steps ==="
echo "1. Test the application:"
echo "   cd bin"
echo "   python edh_automation_main_listener.py"
echo ""
echo "2. Or test the secure version:"
echo "   cd bin"
echo "   python secure_main_listener.py"
echo ""
echo "3. Update your systemd service to use the new file:"
echo "   # Edit /etc/systemd/system/edh-automation.service"
echo "   # Change ExecStart to point to the new file"
echo ""
echo "4. Restart the service:"
echo "   systemctl restart edh-automation"
echo ""
echo "=== File Structure ==="
echo "bin/"
echo "├── edh_automation_main_listener.py  (main application)"
echo "├── secure_main_listener.py          (secure version)"
echo "├── validation_module.py             (validation logic)"
echo "├── airflow_operations.py            (airflow operations)"
echo "└── ... (other existing files)"
echo ""
echo "util/bin/"
echo "├── cyberark_edh_helper.py           (existing helper)"
echo "├── edh_credentials_helper.py        (existing helper)"
echo "├── ops_helper.py                    (existing helper)"
echo "└── ... (other existing helpers)"