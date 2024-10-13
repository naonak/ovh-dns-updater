# OVH DNS Updater

This script automatically updates the DNS A records for specified domains using the public IP address of your server. It works by periodically checking the public IP and updating the DNS records on OVH if the IP has changed.

## Features

- Automatically retrieves the current public IP from multiple services.
- Updates OVH DNS A records if the public IP changes.
- Supports caching of DNS records to reduce API calls.
- Notifies via email or AppRise (optional) when DNS records are updated.
- Dry-run mode for testing without applying changes.
- Configurable logging verbosity.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Command-line Arguments](#command-line-arguments)
- [Usage](#usage)
  - [Docker](#docker)
- [License](#license)

## Requirements

- Python 3.6+
- `ovh` Python package for OVH API integration.
- `requests` for HTTP requests.
- `smtplib` for sending email alerts (optional).
- `apprise` for external notifications (optional).

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/naonak/ovh-dns-updater.git
   cd ovh-dns-updater
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Environment Variables

The script supports the following environment variables for configuration:

- `OVH_APP_KEY`: Your OVH API application key.
- `OVH_APP_SECRET`: Your OVH API application secret.
- `OVH_API_CONSUMER_KEY`: Your OVH API consumer key.
- `DNS_DOMAINS`: Comma-separated list of domains to update.
- `PUBLIC_IP_SERVICES`: Comma-separated list of services to retrieve the public IP.
- `DNS_UPDATE_INTERVAL`: Time in seconds between IP checks (default: `60` seconds).
- `DNS_CACHE_EXPIRATION`: Time in seconds for caching DNS records (default: `300` seconds).
- `VERBOSITY`: Logging verbosity level (`ERROR`, `WARNING`, `INFO`, `DEBUG`).
- `DRY_RUN`: Set to `true` to test the script without making actual changes.
- `ALERT_SMTP_SERVER`: SMTP server for sending email alerts (optional).
- `ALERT_SMTP_USER`: SMTP username for sending email alerts (optional).
- `ALERT_SMTP_PASSWORD`: SMTP password for sending email alerts (optional).
- `ALERT_EMAIL_RECIPIENT`: Recipient email for alerts (optional).
- `ALERT_APPRISE_URL`: URL for AppRise notifications (optional).

### Command-line Arguments

The script also accepts several command-line arguments. Command-line arguments take precedence over environment variables.

```bash
usage: ovh-dns-updater.py [-h] [-s PUBLIC_IP_SERVICES] [-d DNS_DOMAINS]
                          [-k OVH_APP_KEY] [-p OVH_APP_SECRET]
                          [-c OVH_API_CONSUMER_KEY] [-i DNS_UPDATE_INTERVAL]
                          [--dry-run] [--dns-cache-expiration-time DNS_CACHE_EXPIRATION]
                          [--verbosity {ERROR,WARNING,INFO,DEBUG}]
                          [--alert-apprise-url ALERT_APPRISE_URL]
                          [--alert-smtp-server ALERT_SMTP_SERVER]
                          [--alert-smtp-user ALERT_SMTP_USER]
                          [--alert-smtp-password ALERT_SMTP_PASSWORD]
                          [--alert-email-recipient ALERT_EMAIL_RECIPIENT]

optional arguments:
  -h, --help            Show this help message and exit.
  -s PUBLIC_IP_SERVICES, --public-ip-services PUBLIC_IP_SERVICES
                        List of services to retrieve the public IP.
  -d DNS_DOMAINS, --dns-domains DNS_DOMAINS
                        List of domains to update.
  -k OVH_APP_KEY, --ovh-app-key OVH_APP_KEY
                        OVH application key.
  -p OVH_APP_SECRET, --ovh-app-secret OVH_APP_SECRET
                        OVH application secret.
  -c OVH_API_CONSUMER_KEY, --ovh-api-consumer-key OVH_API_CONSUMER_KEY
                        OVH consumer key.
  -i DNS_UPDATE_INTERVAL, --dns-update-interval DNS_UPDATE_INTERVAL
                        Check interval in seconds (default: 60).
  --dry-run             Test mode, no changes will be applied.
  --dns-cache-expiration-time DNS_CACHE_EXPIRATION
                        Time in seconds for cache expiration.
  --verbosity {ERROR,WARNING,INFO,DEBUG}
                        Set the logging verbosity level (default: INFO).
  --alert-apprise-url ALERT_APPRISE_URL
                        AppRise URL for notifications (optional).
  --alert-smtp-server ALERT_SMTP_SERVER
                        SMTP server for email alerts (optional).
  --alert-smtp-user ALERT_SMTP_USER
                        SMTP user for email alerts (optional).
  --alert-smtp-password ALERT_SMTP_PASSWORD
                        SMTP password for email alerts (optional).
  --alert-email-recipient ALERT_EMAIL_RECIPIENT
                        Recipient for email alerts (optional).
```

### Verbosity Levels

You can adjust the verbosity of the logs using the `--verbosity` argument or by setting the `VERBOSITY` environment variable. The available levels are:

- `ERROR`: Only logs critical errors.
- `WARNING`: Logs warnings and errors.
- `INFO`: Logs basic information, warnings, and errors.
- `DEBUG`: Logs detailed debug information, including requests and API responses.

## Usage

### Docker

You can use Docker to run the script easily. Here's a sample `docker-compose.yml` file:

```yaml
version: '3'
services:
  ovh-dns-updater:
    image: ghcr.io/naonak/ovh-dns-updater:latest
    environment:
      OVH_APP_KEY: 'your-app-key'
      OVH_APP_SECRET: 'your-app-secret'
      OVH_API_CONSUMER_KEY: 'your-consumer-key'
      DNS_DOMAINS: 'example.com,www.example.com'
      DNS_UPDATE_INTERVAL: 60
      DNS_CACHE_EXPIRATION: 300
      VERBOSITY: 'INFO'
      ALERT_SMTP_SERVER: 'smtp.example.com'
      ALERT_SMTP_USER: 'user@example.com'
      ALERT_SMTP_PASSWORD: 'password'
      ALERT_EMAIL_RECIPIENT: 'admin@example.com'
    command:
      - --public-ip-services
      - https://api.ipify.org
      - https://checkip.amazonaws.com
```

To start the container:

```bash
docker-compose up -d
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
