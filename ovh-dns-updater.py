import argparse
import os
import time
import requests
import json
import re
import logging
import ovh.exceptions
import sys
import smtplib
from email.mime.text import MIMEText

# Import AppRise for external notifications
import apprise

CONFIG_DIR = '/config'
CONSUMER_KEY_FILE = os.path.join(CONFIG_DIR, 'consumer_key.json')

# Function to validate an IP address
def is_valid_ip(ip):
    ip_regex = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"  # Regex to match IPv4 format
    )
    return ip_regex.match(ip) is not None

# Function to send email alerts (optional)
def send_alert_email(subject, body, smtp_server, smtp_user, smtp_password, recipient):
    if smtp_server and smtp_user and smtp_password and recipient:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = smtp_user
        msg['To'] = recipient

        try:
            with smtplib.SMTP(smtp_server) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            logging.info(f"Alert email sent to {recipient}")
        except Exception as e:
            logging.error(f"Error sending alert email: {e}")
    else:
        logging.info("SMTP details are incomplete. Unable to send alert email.")

# Function to send alert via AppRise (optional)
def send_apprise_alert(body, apprise_url):
    if apprise_url:
        apobj = apprise.Apprise()
        apobj.add(apprise_url)
        try:
            apobj.notify(
                body=body,
                title="DNS Update Alert",
            )
            logging.info("AppRise notification sent successfully.")
        except Exception as e:
            logging.error(f"Error sending AppRise notification: {e}")
    else:
        logging.info("No AppRise URL provided for notifications.")

# Function to get public IP using multiple services with a temporary blacklist
def get_public_ip(services):
    index = 0  # Index for rotating through services
    services_count = len(services)
    blacklist = {}  # Dictionary to temporarily block services

    while True:
        service = services[index]

        if service in blacklist and time.time() < blacklist[service]:
            logging.debug(f"Service {service} is temporarily blacklisted.")
        else:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if is_valid_ip(ip):
                        logging.debug(f"Valid IP retrieved: {ip}")
                        return ip
                    else:
                        logging.warning(f"Invalid IP retrieved: {ip}")
                else:
                    logging.error(f"Service {service} returned status code {response.status_code}")
            except requests.exceptions.Timeout:
                logging.warning(f"Service {service} timed out.")
            except requests.exceptions.ConnectionError:
                logging.error(f"Connection error with service {service}.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Unexpected error with service {service}: {e}")

            # Temporarily blacklist the service after multiple failures
            blacklist[service] = time.time() + 300  # Blacklist for 5 minutes

        index = (index + 1) % services_count
        logging.debug(f"Trying the next service: {services[index]}")

def generate_consumer_key(client, access_rules):
    try:
        result = client.request_consumerkey(access_rules)
        logging.info(f"Please validate the consumer key using the following URL:\n"
                     f"Validation URL: {result['validationUrl']}\n"
                     f"ConsumerKey: {result['consumerKey']}")
        return result['consumerKey'], result['validationUrl']
    except ovh.exceptions.APIError as e:
        logging.error(f"Error generating consumer key: {e}")
        return None, None

def api_retry(call_function, max_retries=3):
    for attempt in range(max_retries):
        try:
            logging.debug("Making API call to OVH...")
            return call_function()
        except (ovh.exceptions.APIError, ovh.exceptions.NetworkError) as e:
            logging.error(f"API error: {e}. Attempt {attempt + 1} of {max_retries}")
            time.sleep(5)
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            break
    raise Exception("Max retries exceeded")

def save_consumer_key_to_file(consumer_key, validation_url):
    try:
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR)

        with open(CONSUMER_KEY_FILE, 'w') as f:
            json.dump({'consumerKey': consumer_key, 'validationUrl': validation_url}, f)
        logging.debug(f"Saved consumer key to {CONSUMER_KEY_FILE}")
    except Exception as e:
        logging.error(f"Error saving consumer key: {e}")

def load_consumer_key_from_file():
    try:
        with open(CONSUMER_KEY_FILE, 'r') as file:
            data = json.load(file)
            consumer_key = data['consumerKey']
            validation_url = data['validationUrl']
            logging.debug(f"Using previously generated consumer key: {consumer_key}. Validation URL: {validation_url}")
            return consumer_key, validation_url
    except FileNotFoundError:
        logging.error(f"Consumer key file not found at {CONSUMER_KEY_FILE}")
        return None, None
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {CONSUMER_KEY_FILE}")
        return None, None

def fetch_all_records(client, domains):
    
    logging.info(f"Fetching all A records")

    all_records = {}
    
    for domain in domains:
        primary_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        logging.debug(f"Fetching A records for {primary_domain}")
        
        try:
            records = api_retry(lambda: client.get(f'/domain/zone/{primary_domain}/record', fieldType='A'))
            for record in records:
                record_details = api_retry(lambda: client.get(f'/domain/zone/{primary_domain}/record/{record}'))
                sub_domain = record_details['subDomain'] if record_details['subDomain'] else primary_domain
                full_domain = f"{sub_domain}.{primary_domain}" if sub_domain != primary_domain else primary_domain
                
                all_records[full_domain] = {
                    'id': record_details['id'],
                    'ip': record_details['target']
                }
                logging.debug(f"Record for {full_domain}: ID={record_details['id']}, IP={record_details['target']}")
        
        except ovh.exceptions.APIError as e:
            logging.error(f"API error while fetching records for domain {domain}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while fetching records for domain {domain}: {e}")

    return all_records, time.time()

def update_records_if_needed(client, all_records, new_ip, dry_run=False, apprise_url=None, smtp_server=None, smtp_user=None, smtp_password=None, email_recipient=None):
    modified = False

    for domain, record in all_records.items():
        current_ip = record['ip']
        record_id = record['id']
        logging.debug(f"Checking {domain} (current IP: {current_ip}, Record ID: {record_id})")
        
        if current_ip != new_ip:
            logging.warning(f"Update needed for {domain} to new IP {new_ip} (current: {current_ip})")
            if not dry_run:
                primary_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
                
                api_retry(lambda: client.put(f'/domain/zone/{primary_domain}/record/{record_id}', target=new_ip))
                modified = True

                alert_message = f"The IP for {domain} has been updated successfully. New IP: {new_ip} (previous: {current_ip})"
                logging.info(alert_message)
                send_alert_email(
                    subject="DNS Update Successful",
                    body=alert_message,
                    smtp_server=smtp_server,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    recipient=email_recipient
                )
                send_apprise_alert(body=alert_message, apprise_url=apprise_url)
        else:
            logging.debug(f"The IP for {domain} is already up-to-date: {current_ip}")

    if modified and not dry_run:
        for domain in set([d.split('.')[-2] + '.' + d.split('.')[-1] for d in all_records.keys()]):
            api_retry(lambda: client.post(f'/domain/zone/{domain}/refresh'))
            logging.info(f"DNS zone for {domain} refreshed.")

    return modified

def check_required_params(ovh_key, ovh_secret, services, domains):
    if not ovh_key:
        logging.error("OVH application key (OVH_APP_KEY) is missing.")
        return False
    if not ovh_secret:
        logging.error("OVH application secret (OVH_APP_SECRET) is missing.")
        return False
    if not services or len(services) == 0:
        logging.error("List of IP services (PUBLIC_IP_SERVICES) is missing or empty.")
        return False
    if not domains or len(domains) == 0:
        logging.error("List of domains (DOMAINS) is missing or empty.")
        return False
    return True

def parse_args():
    parser = argparse.ArgumentParser(description="Update DNS A records with the public IP.")
    parser.add_argument('-s', '--public-ip-services', nargs='+', help="List of services to retrieve the public IP")
    parser.add_argument('-d', '--dns-domains', nargs='+', help="List of domains to update")
    parser.add_argument('-k', '--ovh-app-key', help="OVH application key")
    parser.add_argument('-p', '--ovh-app-secret', help="OVH application secret")
    parser.add_argument('-c', '--ovh-api-consumer-key', help="OVH consumer key")
    parser.add_argument('-i', '--dns-update-interval', type=int, help="Check interval in seconds")
    parser.add_argument('--dry-run', action='store_true', help="Test mode, no changes will be applied")
    parser.add_argument('--dns-cache-expiration-time', type=int, help="Time (in seconds) for cache expiration")
    parser.add_argument('--verbosity', type=str, choices=['ERROR', 'WARNING', 'INFO', 'DEBUG'], default=os.getenv('VERBOSITY', 'INFO'), help="Set the verbosity level")

    parser.add_argument('--alert-apprise-url', help="AppRise URL for notifications (optional)")
    parser.add_argument('--alert-smtp-server', help="SMTP server for email alerts (optional)")
    parser.add_argument('--alert-smtp-user', help="SMTP user for email alerts (optional)")
    parser.add_argument('--alert-smtp-password', help="SMTP password for email alerts (optional)")
    parser.add_argument('--alert-email-recipient', help="Recipient for email alerts (optional)")
    
    return parser.parse_args()

def main():
    args = parse_args()

    # Prioritize environment variables if defined
    verbosity = args.verbosity or os.getenv('VERBOSITY', 'INFO').upper()
    ovh_key = args.ovh_app_key or os.getenv('OVH_APP_KEY')
    ovh_secret = args.ovh_app_secret or os.getenv('OVH_APP_SECRET')
    ovh_consumer_key = args.ovh_api_consumer_key or os.getenv('OVH_API_CONSUMER_KEY')

    services = args.public_ip_services or os.getenv('PUBLIC_IP_SERVICES', 'https://api.ipify.org,https://checkip.amazonaws.com').split(',')
    domains = args.dns_domains or os.getenv('DNS_DOMAINS').split(',')
    interval = args.dns_update_interval or int(os.getenv('DNS_UPDATE_INTERVAL', 60))
    cache_expiration_time = args.dns_cache_expiration_time if args.dns_cache_expiration_time is not None else int(os.getenv('DNS_CACHE_EXPIRATION', 300))

    smtp_server = args.alert_smtp_server or os.getenv('ALERT_SMTP_SERVER')
    smtp_user = args.alert_smtp_user or os.getenv('ALERT_SMTP_USER')
    smtp_password = args.alert_smtp_password or os.getenv('ALERT_SMTP_PASSWORD')
    email_recipient = args.alert_email_recipient or os.getenv('ALERT_EMAIL_RECIPIENT')
    apprise_url = args.alert_apprise_url or os.getenv('ALERT_APPRISE_URL')
    dry_run = args.dry_run or os.getenv('DRY_RUN', 'False').lower() in ['true', '1', 't']

    # Set the logging level
    logging.basicConfig(level=getattr(logging, verbosity, logging.INFO), format='%(asctime)s - %(levelname)s - %(message)s')

    # Check essential parameters
    if not check_required_params(ovh_key, ovh_secret, services, domains):
        logging.error("The script has been stopped due to missing parameters.")
        sys.exit(1)

    # Check if consumer_key is provided via parameter and if the consumer_key.json file exists
    if ovh_consumer_key:
        if os.path.exists(CONSUMER_KEY_FILE):
            logging.info(f"Consumer key provided via parameters, deleting the existing file {CONSUMER_KEY_FILE}")
            os.remove(CONSUMER_KEY_FILE)
    else:
        if os.path.exists(CONSUMER_KEY_FILE):
            ovh_consumer_key, validation_url = load_consumer_key_from_file()
            if not ovh_consumer_key:
                sys.exit(1)
            logging.info(f"Using previously generated consumer key: {ovh_consumer_key}. Validation URL: {validation_url}")
            sys.exit(0)
        else:
            logging.info("No consumer_key provided. Initializing: generating a new consumer_key.")
    
    if not ovh_consumer_key:
        if os.path.exists(CONSUMER_KEY_FILE):
            ovh_consumer_key, validation_url = load_consumer_key_from_file()
            if not ovh_consumer_key:
                sys.exit(1)
            logging.info(f"Using previously generated consumer key: {ovh_consumer_key}. Validation URL: {validation_url}")
            sys.exit(0)
        else:
            logging.info("No consumer_key provided. Initializing: generating a new consumer_key.")
            client = ovh.Client(endpoint='ovh-eu', application_key=ovh_key, application_secret=ovh_secret)
            access_rules = [
                {"method": "GET", "path": "/domain/*"},
                {"method": "GET", "path": "/domain/zone/*/record/*"},
                {"method": "POST", "path": "/domain/zone/*/record"},
                {"method": "PUT", "path": "/domain/zone/*/record/*"},
                {"method": "DELETE", "path": "/domain/zone/*/record/*"},
                {"method": "POST", "path": "/domain/zone/*/refresh"}
            ]
            consumer_key, validation_url = generate_consumer_key(client, access_rules)
            if consumer_key:
                save_consumer_key_to_file(consumer_key, validation_url)
                message = (
                    f"Please validate the consumer key using the following URL:\n"
                    f"Validation URL: {validation_url}\n"
                    f"ConsumerKey: {consumer_key}"
                )
                logging.info(message)
                send_alert_email(
                    subject="Consumer key generation required",
                    body=message,
                    smtp_server=smtp_server,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    recipient=email_recipient
                )
                send_apprise_alert(
                    body=message,
                    apprise_url=apprise_url
                )
            else:
                error_message = "Error generating the consumer key."
                logging.error(error_message)
                send_alert_email(
                    subject="Error generating consumer key",
                    body=error_message,
                    smtp_server=smtp_server,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    recipient=email_recipient
                )
                send_apprise_alert(
                    body=error_message,
                    apprise_url=apprise_url
                )
            sys.exit(1)

    # Log de la configuration des paramètres au lancement
    logging.info("=== Configuration ===")
    logging.info(f"OVH App Key: {ovh_key}")

    logging.info(f"Public IP Services: {services}")
    logging.info(f"DNS Domains to Update: {domains}")

    logging.info(f"DNS Update Interval (seconds): {interval}")
    logging.info(f"DNS Cache Expiration Time (seconds): {cache_expiration_time}")

    if smtp_server and smtp_user and smtp_password:
        logging.info(f"SMTP Server: {smtp_server}")
        logging.info(f"SMTP User: {smtp_user}")
        logging.info(f"Email Alerts Recipient: {email_recipient}")
    else:
        logging.info("No email alert configuration found.")

    if apprise_url:
        logging.info(f"AppRise Notification URL: {apprise_url}")
    else:
        logging.info("No AppRise alert configuration found.")

    logging.info(f"Dry Run Mode: {'Enabled' if dry_run else 'Disabled'}")
    logging.info("=== End of Configuration ===")

    # Connect to the OVH API with the consumer_key
    client = ovh.Client(
        endpoint='ovh-eu',
        application_key=ovh_key,
        application_secret=ovh_secret,
        consumer_key=ovh_consumer_key,
    )

    # Fetch all DNS records at the beginning
    all_records = fetch_all_records(client, domains)

    # Infinite loop to check and update the IP at each interval
    records_cache = None
    cache_timestamp = 0
    last_ip = None

    while True:
        try:
            ip = get_public_ip(services)
            cache_expired = not records_cache or time.time() - cache_timestamp > cache_expiration_time

            if ip:
                logging.debug(f"Public IP retrieved: {ip}")

                if last_ip != ip:
                    logging.warning(f"Public IP has changed from {last_ip} to {ip}")

                if last_ip == ip and not cache_expired:
                    logging.debug("The public IP hasn't changed. No update needed.")
                else:
                    last_ip = ip

                    if cache_expired:
                        logging.debug("Cache expired or not available, fetching DNS records.")
                        records_cache, cache_timestamp = fetch_all_records(client, domains)

                    if update_records_if_needed(client, records_cache, ip, dry_run, apprise_url, smtp_server, smtp_user, smtp_password, email_recipient):
                        records_cache, cache_timestamp = fetch_all_records(client, domains)
            else:
                error_message = "Unable to retrieve public IP."
                logging.error(error_message)
                send_alert_email(
                    subject="Error retrieving IP",
                    body=error_message,
                    smtp_server=smtp_server,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    recipient=email_recipient
                )
                send_apprise_alert(
                    body=error_message,
                    apprise_url=apprise_url
                )

        except Exception as e:
            error_message = f"Unexpected error: {e}"
            logging.error(error_message)
            send_alert_email(
                subject="Unexpected error in DNS script",
                body=error_message,
                smtp_server=smtp_server,
                smtp_user=smtp_user,
                smtp_password=smtp_password,
                recipient=email_recipient
            )
            send_apprise_alert(
                body=error_message,
                apprise_url=apprise_url
            )

        time.sleep(interval)

if __name__ == '__main__':
    main()
