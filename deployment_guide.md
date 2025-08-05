# Secure EDH Automation HTTP Listener - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the secure version of the EDH Automation HTTP Listener with comprehensive security measures.

## Prerequisites

### System Requirements
- Python 3.8 or higher
- Linux environment (tested on Ubuntu 20.04+)
- Minimum 2GB RAM
- 10GB disk space
- Network access to AWS services

### Security Requirements
- SSL certificates (valid and properly configured)
- Firewall rules configured
- Access to CyberArk for credential management
- AWS IAM permissions for MWAA access

## Installation Steps

### 1. Environment Setup

```bash
# Create virtual environment
python3 -m venv /opt/edh_automation
source /opt/edh_automation/bin/activate

# Install dependencies
pip install -r requirements_secure.txt

# Verify installation
python -c "import flask, boto3, requests; print('Dependencies installed successfully')"
```

### 2. SSL Certificate Configuration

```bash
# Create certificates directory
mkdir -p /opt/edh_automation/resources

# Copy SSL certificates (replace with your actual certificates)
cp /path/to/your/cert.pem /opt/edh_automation/resources/
cp /path/to/your/key.pem /opt/edh_automation/resources/

# Set proper permissions
chmod 600 /opt/edh_automation/resources/key.pem
chmod 644 /opt/edh_automation/resources/cert.pem
chown edh_automation:edh_automation /opt/edh_automation/resources/*
```

### 3. Security Configuration

#### Create Security Log Directory
```bash
# Create security log directory
sudo mkdir -p /var/log/edh_security
sudo chown edh_automation:edh_automation /var/log/edh_security
sudo chmod 750 /var/log/edh_security
```

#### Configure Firewall Rules
```bash
# Allow HTTPS traffic on port 8982
sudo ufw allow 8982/tcp

# Allow health check endpoint (optional)
sudo ufw allow 8983/tcp

# Restrict access to specific IP ranges if needed
sudo ufw allow from 10.0.0.0/8 to any port 8982
```

### 4. Application Configuration

#### Environment Variables
Create `/opt/edh_automation/.env`:
```bash
# Environment configuration
ENVIRONMENT=PROD

# Security settings
MAX_REQUEST_SIZE=1048576
MAX_DAG_NAME_LENGTH=100

# Logging configuration
LOG_LEVEL=INFO
SECURITY_LOG_LEVEL=WARNING

# Rate limiting
RATE_LIMIT_DAILY=200
RATE_LIMIT_HOURLY=50
RATE_LIMIT_PER_MINUTE=10
```

#### Load Environment Variables
```bash
# Add to /opt/edh_automation/start.sh
#!/bin/bash
source /opt/edh_automation/.env
export $(cat /opt/edh_automation/.env | xargs)
```

### 5. Systemd Service Configuration

Create `/etc/systemd/system/edh-automation.service`:
```ini
[Unit]
Description=EDH Automation HTTP Listener
After=network.target

[Service]
Type=simple
User=edh_automation
Group=edh_automation
WorkingDirectory=/opt/edh_automation
Environment=PATH=/opt/edh_automation/bin
ExecStart=/opt/edh_automation/bin/python secure_edh_automation_http_listener.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/edh_security /opt/edh_automation/logs

[Install]
WantedBy=multi-user.target
```

### 6. User and Permissions Setup

```bash
# Create application user
sudo useradd -r -s /bin/false edh_automation

# Set ownership
sudo chown -R edh_automation:edh_automation /opt/edh_automation

# Set proper permissions
sudo chmod 750 /opt/edh_automation
sudo chmod 640 /opt/edh_automation/.env
```

## Security Hardening

### 1. Network Security

#### Configure Reverse Proxy (Recommended)
```nginx
# /etc/nginx/sites-available/edh-automation
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location /edh-spiff/ {
        proxy_pass https://127.0.0.1:8982;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /health {
        proxy_pass https://127.0.0.1:8982;
        access_log off;
    }
}
```

### 2. Monitoring and Logging

#### Configure Log Rotation
Create `/etc/logrotate.d/edh-automation`:
```
/var/log/edh_security/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 edh_automation edh_automation
    postrotate
        systemctl reload edh-automation
    endscript
}
```

#### Setup Monitoring Scripts
Create `/opt/edh_automation/monitoring/health_check.sh`:
```bash
#!/bin/bash

# Health check script
HEALTH_URL="https://localhost:8982/health"
METRICS_URL="https://localhost:8982/metrics"

# Check application health
response=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)
if [ $response -ne 200 ]; then
    echo "CRITICAL: Application health check failed"
    exit 1
fi

# Check metrics endpoint
response=$(curl -s -o /dev/null -w "%{http_code}" $METRICS_URL)
if [ $response -ne 401 ]; then  # Should require authentication
    echo "WARNING: Metrics endpoint not properly secured"
fi

echo "OK: Application is healthy"
```

### 3. Backup and Recovery

#### Backup Configuration
Create `/opt/edh_automation/backup/backup.sh`:
```bash
#!/bin/bash

BACKUP_DIR="/opt/edh_automation/backup/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configuration files
cp -r /opt/edh_automation/resources $BACKUP_DIR/
cp /opt/edh_automation/.env $BACKUP_DIR/
cp /etc/systemd/system/edh-automation.service $BACKUP_DIR/

# Backup logs (last 7 days)
find /var/log/edh_security -name "*.log" -mtime -7 -exec cp {} $BACKUP_DIR/ \;

# Compress backup
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

# Clean old backups (keep 30 days)
find /opt/edh_automation/backup -name "*.tar.gz" -mtime +30 -delete
```

## Deployment Checklist

### Pre-Deployment
- [ ] SSL certificates obtained and configured
- [ ] Firewall rules configured
- [ ] CyberArk credentials configured
- [ ] AWS IAM permissions verified
- [ ] Security log directory created
- [ ] Application user created
- [ ] Dependencies installed

### Deployment
- [ ] Application files deployed
- [ ] Configuration files updated
- [ ] Permissions set correctly
- [ ] Systemd service configured
- [ ] Service started and enabled
- [ ] Health checks passing

### Post-Deployment
- [ ] Security headers verified
- [ ] Rate limiting tested
- [ ] Authentication working
- [ ] Logging configured
- [ ] Monitoring alerts set up
- [ ] Backup procedures tested

## Troubleshooting

### Common Issues

#### SSL Certificate Issues
```bash
# Verify certificate
openssl x509 -in /opt/edh_automation/resources/cert.pem -text -noout

# Test SSL connection
openssl s_client -connect localhost:8982 -servername localhost
```

#### Permission Issues
```bash
# Check file permissions
ls -la /opt/edh_automation/resources/
ls -la /var/log/edh_security/

# Fix permissions if needed
sudo chown -R edh_automation:edh_automation /opt/edh_automation
sudo chmod 600 /opt/edh_automation/resources/key.pem
```

#### Service Issues
```bash
# Check service status
sudo systemctl status edh-automation

# View logs
sudo journalctl -u edh-automation -f

# Restart service
sudo systemctl restart edh-automation
```

### Security Incident Response

#### If Compromise is Suspected
1. **Immediate Actions**:
   - Stop the service: `sudo systemctl stop edh-automation`
   - Isolate the system from network
   - Preserve logs: `sudo cp -r /var/log/edh_security /tmp/backup/`

2. **Investigation**:
   - Review security logs: `grep -i "security_event" /var/log/edh_security/*.log`
   - Check system logs: `sudo journalctl -u edh-automation --since "1 hour ago"`
   - Analyze network connections: `netstat -tulpn | grep 8982`

3. **Recovery**:
   - Rotate all credentials
   - Update SSL certificates
   - Restore from clean backup
   - Restart service with enhanced monitoring

## Maintenance

### Regular Tasks
- **Daily**: Check health endpoint and review error logs
- **Weekly**: Review security logs and update dependencies
- **Monthly**: Rotate credentials and test backup procedures
- **Quarterly**: Conduct security assessment and update SSL certificates

### Updates
```bash
# Update dependencies
pip install -r requirements_secure.txt --upgrade

# Security audit
bandit -r /opt/edh_automation/
safety check

# Restart service after updates
sudo systemctl restart edh-automation
```

## Compliance and Auditing

### Log Retention
- Security logs: 1 year
- Application logs: 90 days
- Access logs: 30 days

### Audit Trail
- All authentication attempts logged
- All DAG trigger requests logged
- All security events logged
- All configuration changes logged

### Monitoring Alerts
- Failed authentication attempts
- Rate limit violations
- SSL certificate expiration
- Service availability
- High error rates