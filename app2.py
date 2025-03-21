import fnmatch
import requests
import pandas as pd
import datetime
import re
import os
import tldextract
import logging

# Load configurations from config.py
from config import FULL_REPORT, GOOD_REPORT, BAD_REPORT

# Constants and configurations
API_KEY = ""
API_URL = ""

extra_folder = ""

with open(os.path.join(os.getcwd(), extra_folder, "bad.txt"), "r") as f:
    BAD_NS_LIST = [line.strip() for line in f.readlines()]
EXPIRED_NS_LIST = ["*whois*", "*expired*", "*renew*"]
with open(os.path.join(os.getcwd(), extra_folder, "expired.txt"), "r") as f:
    EXPIRED_NS_LIST = [line.strip() for line in f.readlines()]
EXCLUDE_DAYS = 150

# Load same.txt and create a dictionary for NS groups
SAME_NS_GROUPS = {}
with open(os.path.join(os.getcwd(), extra_folder, "same.txt"), "r") as f:
    lines = [line.strip() for line in f if line.strip()]
    current_main_ns = None
    for line in lines:
        if not line:
            current_main_ns = None
            continue
        if not current_main_ns:
            current_main_ns = line

        SAME_NS_GROUPS[line] = current_main_ns


# Function to map NS to their main NS group
def map_to_main_ns(ns):
    if ns in SAME_NS_GROUPS.keys():
        return SAME_NS_GROUPS[ns]
    return ns


# Function to call the CompleteDNS API
def fetch_ns_history(domain):
    try:
        response = requests.get(f"{API_URL}/{domain}?", params={"key": API_KEY})
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def longest_active_domain(ns_):
    longest_domain = None
    max_duration = 0

    current_domain = None
    last_duration = 0
    for i in range(len(ns_)):
        domain = list(ns_[i][0])[0]

        start_date = ns_[i][1]
        if ns_[i][2]:
            end_date = ns_[i][2]
        elif i + 1 < len(ns_):
            next_domain_start_date = ns_[i + 1][1]
            end_date = next_domain_start_date
        else:
            end_date = datetime.datetime.now() - datetime.timedelta(days=90)

        if current_domain is None:
            current_domain = domain

        if current_domain and current_domain == domain:
            pass
        else:
            last_duration = 0

        current_duration = (end_date - start_date).days + last_duration

        if current_duration > max_duration:
            max_duration = current_duration
            longest_domain = domain

        current_domain = domain
        last_duration = current_duration

    return longest_domain, round(max_duration / 365.0, 1)


def contains_expired(text, patterns):
    for pattern in patterns:
        regex_pattern = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
        if regex_pattern.search(text):
            return True
    return False


def is_date_within_period(dates, period_end_date):
    return any(date <= period_end_date for date in dates)


def is_bad_or_expired(ns, bad_patterns):
    return any(re.search(pattern.replace("*", ".*"), ns) for pattern in bad_patterns)


def filter_nameservers(ns_periods, period_end_date, bad_ns_list, expired_ns_list):
    bad_patterns = bad_ns_list + expired_ns_list
    return {
        ns
        for ns, dates in ns_periods.items()
        if is_date_within_period(dates, period_end_date)
        and not is_bad_or_expired(ns, bad_patterns)
    }


def count_unique_non_empty_domain_sets(domain_history):
    unique_domain_sets = set()
    result = 0
    for domain_set, _, __ in domain_history:
        if domain_set:
            filtered_texts = {map_to_main_ns(text) for text in domain_set if not contains_expired(text, EXPIRED_NS_LIST)}
            unique_domain_sets.add(frozenset(filtered_texts)) if filtered_texts else None
    result = len(unique_domain_sets)
    
    return result


def contains_expired_in_sub_domain(ns):
    return any(fnmatch.fnmatch(ns, pattern) for pattern in EXPIRED_NS_LIST)


def extract_tld(ns):
    if contains_expired_in_sub_domain(ns):
        return ns
    domain_details = tldextract.extract(ns)
    return f"{domain_details.domain}.{domain_details.suffix}"


def check_substrings(my_list, my_set):
    set_value = next(iter(my_set)) if my_set else ""
    return not any(pattern.strip("*") in set_value for pattern in my_list)


def count_unique_expired_dates(ns_changes, expired_patterns):
    unique_expired_dates = set()
    for ns_set, _, date in ns_changes:
        if any(
            re.search(pattern.replace("*", ".*"), ns)
            for ns in ns_set
            for pattern in expired_patterns
        ):
            unique_expired_dates.add(date)
    return len(unique_expired_dates)


def check_ns_condition(date_start, date_end, ns_set):
    pop = False
    expired = False
    bad = False
    total_months1 = date_start.year * 12 + date_start.month
    total_months2 = date_end.year * 12 + date_end.month
    month_diff = abs(total_months2 - total_months1)
    if month_diff == 4:
        if date_end.day <= date_start.day:
            is_expired = check_substrings(EXPIRED_NS_LIST, ns_set)
            if not is_expired:
                expired = True
            for ns in ns_set:
                check_bad = any(
                    re.search(pattern.replace("*", ".*"), ns) for pattern in BAD_NS_LIST
                )
                if check_bad:
                    bad = True
                    break
            pop = True
    elif month_diff < 4:
        is_expired = check_substrings(EXPIRED_NS_LIST, ns_set)
        if not is_expired:
            expired = True
        for ns in ns_set:
            check_bad = any(
                re.search(pattern.replace("*", ".*"), ns) for pattern in BAD_NS_LIST
            )
            if check_bad:
                bad = True
                break
        pop = True
    return pop, expired, bad


def process_ns_history(data, current_date):
    if "error_type" in data.keys() or "error" in data.keys():
        return {"error": data["error_msg"]}
    # print('.'*15, data)
    domain = data["domain"]
    filtered_events = data.get("events", [])

    if not filtered_events:
        return {"Unique NS Changes": 0}

    # ns_changes = []
    ns_periods = {}
    ns_end_limit = datetime.datetime.now() - datetime.timedelta(days=150)
    extra_expired = 0
    extra_bad = 0
    ns_ = []
    need_end_date = False
    last_ns=''
    last_ns_date = None
    ns_changes_count = 0
    expired_ns_count = 0
    bad_ns_count = 0
    longest_duration=0.0
    last_is_longest = None
    last_is_good = None
    event_count=0
    longest_ns=''
    drop_list = []
    for event in filtered_events:
        event_count+=1
        ns_set = {map_to_main_ns(extract_tld(ns)) for ns in event["nameservers"]}
        # -----------------------------------------------
        if event.get("date").get("date"):
            date_start = datetime.datetime.strptime(
                event.get("date").get("date"), "%Y-%m-%d"
            )
            date_end = datetime.datetime.strptime(
                event.get("date").get("date"), "%Y-%m-%d"
            )
        else:
            date_start = datetime.datetime.strptime(
                event.get("date").get("date_start"), "%Y-%m-%d"
            )
            date_end = datetime.datetime.strptime(
                event.get("date").get("date_end"), "%Y-%m-%d"
            )

        if need_end_date and ns_:
            if not ns_[-1][2]:
                ns_[-1][2] = date_end
                pop, expired, bad = check_ns_condition(ns_[-1][1], ns_[-1][2], ns_[-1][0])
                if pop:
                    ns_.pop()
                    need_end_date = False
                if expired:
                    extra_expired += 1
                if bad:
                    extra_bad += 1
        if date_start < ns_end_limit:
            if event.get('type')=='dropped':
                continue
            elif ns_set:
                ns_.append([ns_set, date_start, None])
                need_end_date = True
                last_ns_date = date_end
        else:
            break
            # -----------------------------------------------
        for ns in ns_set:
            if ns in ns_periods:
                ns_periods[ns].append(date_end)
            else:
                ns_periods[ns] = [date_end]

    if need_end_date and ns_:
        ns_[-1][2] = datetime.datetime.now() - datetime.timedelta(days=90)
        pop, expired, bad = check_ns_condition(ns_[-1][1], ns_[-1][2], ns_[-1][0])
        if pop:
            ns_.pop()
        if expired:
            extra_expired += 1
        if bad:
            extra_bad += 1
    if ns_:
        first_ns_set, first_ns_date, _ = ns_[0]
        current_year = current_date.year
        first_ns_year = first_ns_date.year
        period_years = 3 if current_year - first_ns_year >= 8 else .83333333
        period_end_date = first_ns_date + datetime.timedelta(days=365 * period_years)

        good_ns = []
        for domain, start_date, end_date in ns_:
            if period_end_date>=start_date:
                if not is_bad_or_expired(ns, BAD_NS_LIST+EXPIRED_NS_LIST):
                    good_ns.append(next(iter(domain)))

        ns_temp = ns_[1:]
        ns_=[]
        for i in ns_temp:
            if next(iter(i[0])) not in good_ns:
                ns_.append(i)

        ns_changes_count = count_unique_non_empty_domain_sets(ns_)
        ns_ = ns_temp
        if ns_:
            bad_ns_count = sum(
                any(re.search(pattern.replace("*", ".*"), ns) for pattern in BAD_NS_LIST)
                for ns_set, _, __ in ns_
                for ns in ns_set
            )
            bad_ns_count += extra_bad
            expired_ns_count = count_unique_expired_dates(ns_, EXPIRED_NS_LIST)
            expired_ns_count += extra_expired
            longest_ns, longest_duration = longest_active_domain(ns_)

            last_ns_set, _, __ = ns_[-1]
            for last_ns_ in range(len(ns_) - 2, -1, -1):
                _ns_set, _, _ns_date = ns_[last_ns_]
                if _ns_set == last_ns_set:
                    last_ns_set, _, last_ns_date = ns_[last_ns_]
                else:
                    break
            last_ns = next(iter(last_ns_set))

            last_is_longest = "Yes" if last_ns == longest_ns else "No"

            last_is_good = "Yes" if last_ns in good_ns else "No"
        else:
            last_ns_date = None
    return {
        "Unique NS Changes": ns_changes_count,
        "Bad NS": bad_ns_count,
        "Expired NS": expired_ns_count,
        "Longest NS": f"{longest_ns} | {round(longest_duration, 1)}y",
        "Last NS": last_ns,
        "Last NS Date": last_ns_date.strftime("%Y-%m-%d") if last_ns_date else None,
        "Last=Longest?": last_is_longest if last_is_longest else None,
        "Last=Good?": last_is_good if last_is_good else None,
    }


# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to extract the top-level domain (TLD) from a nameserver
def extract_tld(ns):
    domain_details = tldextract.extract(ns)
    return f"{domain_details.domain}.{domain_details.suffix}"

# Function to process nameserver changes for a domain (new logic)
def process_domain_for_bad_list(domain, current_date):
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

# Function to process nameserver changes for the ns_checker logic
def process_ns_checker_logic(domain, ns_changes):
    bad_domains = []
    for ns_set, start_date, end_date in ns_changes:
        for ns in ns_set:
            # Check if the nameserver matches any pattern in BAD_NS_LIST
            if any(re.search(pattern.replace("*", ".*"), ns) for pattern in BAD_NS_LIST):
                bad_domains.append(domain)
                break
    return bad_domains

# Updated main function to remove the old bad.txt logic
def main(input_file, output_file, error_file):
    current_date = datetime.datetime.now()
    domains = []

    with open(input_file, "r") as f:
        domains = [line.strip() for line in f.readlines()]

    results = []
    success_results = []
    errors = []
    bad_domains_new_logic = []  # To store domains flagged by the new logic
    i = 1
    for domain in domains:
        logging.info(f"Processing {i}/{len(domains)}: {domain}")
        i += 1
        data = fetch_ns_history(domain)
        if "error" in data:
            errors.append(f"Domain: {domain} - Error: {data['error']}")
        else:
            result = process_ns_history(data, current_date)
            if "error" in result:
                errors.append(f"Domain: {domain} - Error: {result['error']}")
                new_item = {
                    "Domain": domain,
                }
                conclusion_item = {"Conclusion": ""}
                default_value = {
                                    "Unique NS Changes": None,
                                    "Bad NS": None,
                                    "Expired NS": None,
                                    "Longest NS": '',
                                    "Last NS": None,
                                    "Last NS Date": None,
                                    "Last=Longest?": None,
                                    "Last=Good?": None,
                                }
                result_2 = {**new_item, **default_value, **conclusion_item}
                results.append(result_2)
            else:
                new_item = {
                    "Domain": domain,
                }
                conclusion_item = {"Conclusion": ""}
                result_2 = {**new_item, **result, **conclusion_item}
                results.append(result_2)
                success_results.append(result_2)

        # Process new logic for bad domains
        bad_domain, error = process_domain_for_bad_list(domain, current_date)
        if bad_domain:
            bad_domains_new_logic.append(bad_domain)
        if error:
            errors.append(error)

    if errors and FULL_REPORT:
        with open(error_file, "w") as f:
            f.write("\n".join(errors))
    df = pd.DataFrame(results)
    success_df = pd.DataFrame(success_results)

    if success_results:
        good_domains = success_df[
            (success_df["Unique NS Changes"] == 0)
            | (success_df["Last=Good?"] == "Yes")
            | (
                (success_df["Last=Longest?"] == "YES") & success_df["Longest NS"]
                & (success_df["Longest NS"].apply(lambda x: float(x.split(" | ")[1][:-1]) >= 4))
            )
        ]
        if GOOD_REPORT:
            good_file = f'Good_{current_date.strftime("%Y%d%m_%H%M%S")}.txt'
            good_domains["Domain"].to_csv(good_file, index=False, header=False)

        bad_domains = success_df[
            (success_df["Bad NS"] >= 1)
            | (
                (success_df["Expired NS"] >= 2)
                & (success_df["Last=Longest?"] == "NO")
                & (success_df["Last=Good?"] == "NO")
            )
            | (
                (success_df["Expired NS"] == 1)
                & (success_df["Last=Longest?"] == "NO")
                & (success_df["Last=Good?"] == "NO")
                & (success_df["Unique NS Changes"] >= 4)
            )
        ]
        if BAD_REPORT:
            bad_file = f'Bad_{current_date.strftime("%Y%d%m_%H%M%S")}.txt'
            bad_domains["Domain"].to_csv(bad_file, index=False, header=False)

    # Write BAD_DATE_TIME.txt for the new logic
    if bad_domains_new_logic:
        bad_ns_checker_file = f'BAD_{current_date.strftime("%Y%m%d_%H%M%S")}.txt'
        with open(bad_ns_checker_file, "w") as f:
            f.write("\n".join(set(bad_domains_new_logic)))

    bad = list(bad_domains["Domain"])
    good = list(good_domains["Domain"])
    if FULL_REPORT:
        for i in range(len(df["Conclusion"])):
            if df["Domain"][i] in bad:
                df.loc[i, "Conclusion"] = "Bad"
            elif df["Domain"][i] in good:
                df.loc[i, "Conclusion"] = "Good"
        df.to_csv(output_file, index=False)


if __name__ == "__main__":
    input_file = os.path.join(os.getcwd(), extra_folder, "domains.txt")
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    today = datetime.datetime.today()

    output_file = f'report_{current_date}_{today.strftime("%Y%d%m_%H%M%S")}.csv'
    error_file = f'errors_{current_date}_{today.strftime("%Y%d%m_%H%M%S")}.txt'
    main(input_file, output_file, error_file)
