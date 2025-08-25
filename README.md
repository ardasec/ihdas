# ihdas - URL Shortener

## Overview
URL shortening service built with Go and PostgreSQL

## Features
- **URL Shortening**: Generate random 6-character codes or custom aliases
- **Expiration**: Set optional expiration dates for links
- **Analytics**: Track click counts through the stats API
- **Caching**: In-memory cache with 5-minute TTL for fast redirects
- **Health Monitoring**: Dashboard and API for system observability

## Setup

### Dependencies (Ubuntu/Debian)
```bash
# Install required packages
sudo apt update
sudo apt install -y postgresql postgresql-contrib golang-go
```

### Application Setup
```bash
# 1. Create PostgreSQL database
sudo -u postgres psql -c "CREATE DATABASE ihdas;"
sudo -u postgres psql -c "CREATE USER ihdas WITH PASSWORD 'your-secure-password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ihdas TO ihdas;"

# 2. Update service configuration (config/ihdas.service)
# Set DATABASE_URL with your credentials:
# Environment=DATABASE_URL=postgres://ihdas:your-secure-password@localhost/ihdas?sslmode=disable

# 3. Install service
sudo cp config/ihdas.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ihdas

# 4. Build and deploy
go build
sudo mkdir -p /opt/ihdas
sudo cp ihdas /opt/ihdas/
sudo cp -r static /opt/ihdas/
sudo chown -R ihdas:ihdas /opt/ihdas

# 5. Start service
sudo systemctl start ihdas
```

## API Documentation
### Create Short URL
`POST /api/v1/shorten`
```json
{
  "original_url": "https://example.com",
  "custom_code": "optional-alias",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### Redirect
`GET /:code`  
Handles URL redirection with these behaviors:
- **Valid code**: 301 redirect to original URL
- **Invalid code**: 404 Not Found
- **Expired code**: 410 Gone
- **Caching**: 5-minute in-memory cache for popular URLs
- **Statistics**: click tracking

### Get Statistics
`GET /api/v1/stats/:code`
```json
{
  "short_code": "abc123",
  "original_url": "https://example.com",
  "click_count": 42,
  "created_at": "2025-08-25T16:42:50Z"
}
```

## Monitoring
- **Dashboard**: `http://localhost:8080/health`
- **API Endpoint**: `http://localhost:8080/api/health`

## Production Deployment

### Nginx Reverse Proxy Setup
1. Install Nginx and Certbot:
```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

2. Configure Nginx:
```bash
sudo cp config/nginx.conf /etc/nginx/sites-available/ihdas
sudo ln -s /etc/nginx/sites-available/ihdas /etc/nginx/sites-enabled/
```

3. Update domain in config:
```bash
sudo nano /etc/nginx/sites-available/ihdas
```
Replace `your_domain.com` with your actual domain

4. Obtain SSL certificate:
```bash
sudo certbot --nginx -d your_domain.com -d www.your_domain.com
```

5. Enable automatic certificate renewal:
```bash
sudo certbot renew --dry-run
```

6. Test and reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Service Configuration
- All application configuration is handled through `config/ihdas.service`
- Default port: 8080 (editable in service file)
- Runs as dedicated `ihdas` system user for security

### Firewall Configuration
```bash
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 'OpenSSH'
sudo ufw enable
```

### Updating the Application
1. Build new version: `go build`
2. Stop service: `sudo systemctl stop ihdas`
3. Replace binary: `sudo cp ihdas /opt/ihdas/`
4. Start service: `sudo systemctl start ihdas`

## Requirements
- PostgreSQL 12+
- Go 1.20+
