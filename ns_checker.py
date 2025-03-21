import requests
import datetime
import os
import tldextract
import logging

# Constants and configurations
API_KEY = ""  # API key for CompleteDNS API
API_URL = ""  # API endpoint for DNS history
extra_folder = ""  # Folder for additional files

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load bad nameservers list from bad.txt
with open(os.path.join(os.getcwd(), extra_folder, "bad.txt"), "r") as f:
    BAD_NS_LIST = [line.strip() for line in f.readlines()]

# Function to extract the top-level domain (TLD) from a nameserver
def extract_tld(ns):
    domain_details = tldextract.extract(ns)
    return f"{domain_details.domain}.{domain_details.suffix}"

# Function to call the CompleteDNS API
def fetch_ns_history(domain):
    try:
        response = requests.get(f"{API_URL}/{domain}?", params={"key": API_KEY})
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}

# Function to process nameserver changes for a domain
def process_domain(domain, current_date):
    data = fetch_ns_history(domain)
    if "error" in data:
        return None, f"Domain: {domain} - Error: {data['error']}"

    filtered_events = data.get("events", [])
    if not filtered_events:
        return None, None

    bad_domain = False
    cloudflare_first_seen = None
    cloudflare_recent_seen = None

    for event in filtered_events:
        ns_set = {extract_tld(ns) for ns in event["nameservers"]}

        # Check if any nameserver in the change is in the BAD_NS_LIST
        if any(ns in BAD_NS_LIST for ns in ns_set):
            bad_domain = True

        # Check for cloudflare.com conditions
        if "cloudflare.com" in ns_set:
            # Safely handle missing or None dates
            event_date_str = event.get("date", {}).get("date")
            if event_date_str:
                event_date = datetime.datetime.strptime(event_date_str, "%Y-%m-%d")
                if not cloudflare_first_seen:
                    cloudflare_first_seen = event_date
                cloudflare_recent_seen = event_date

    # Check if cloudflare.com condition is met
    if cloudflare_recent_seen and cloudflare_first_seen:
        if (current_date - cloudflare_recent_seen).days <= 365 and cloudflare_first_seen == cloudflare_recent_seen:
            bad_domain = True

    return domain if bad_domain else None, None

# Main function to process domains and generate the BAD_DATE_TIME.txt file
def main():
    current_date = datetime.datetime.now()
    input_file = os.path.join(os.getcwd(), extra_folder, "domains.txt")
    bad_file = f'BAD_{current_date.strftime("%Y%m%d_%H%M%S")}.txt'

    domains = []
    with open(input_file, "r") as f:
        domains = [line.strip() for line in f.readlines()]

    bad_domains = []
    errors = []

    for i, domain in enumerate(domains, start=1):
        logging.info(f"Processing {i}/{len(domains)}: {domain}")  # Log the current domain being processed
        bad_domain, error = process_domain(domain, current_date)
        if bad_domain:
            bad_domains.append(bad_domain)
        if error:
            errors.append(error)

    # Write bad domains to BAD_DATE_TIME.txt
    if bad_domains:
        with open(bad_file, "w") as f:
            f.write("\n".join(bad_domains))

    # Print errors if any
    if errors:
        logging.error("Errors encountered:")
        for error in errors:
            logging.error(error)

if __name__ == "__main__":
    main()
