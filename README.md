# Nameserver History Checker

This Python script analyzes domain nameservers' history using the CompleteDNS API. It processes a list of domains, identifies patterns in nameserver changes, and generates reports based on specific criteria.

## Features

- **Domain Analysis**: Processes a list of domains from `domains.txt` and fetches their nameserver history.
- **Bad Nameserver Detection**: Identifies domains associated with bad nameservers listed in `bad.txt`.
- **Expired Nameserver Detection**: Flags domains with expired nameservers based on patterns in `expired.txt`.
- **Same Nameserver Grouping**: Groups related nameservers using `same.txt` for better analysis.
- **Reports**:
  - Generates a full report (`report_DATE_TIME.csv`) with detailed analysis.
  - Creates a list of good domains (`Good_DATE_TIME.txt`) based on specific criteria.
  - Creates a list of bad domains (`Bad_DATE_TIME.txt`) based on specific criteria.
  - Logs errors encountered during processing in `errors_DATE_TIME.txt`.

## Configuration

The script uses the following configuration options from `config.py`:
- `FULL_REPORT`: Set to `1` to enable full report generation.
- `GOOD_REPORT`: Set to `1` to enable good domains report generation.
- `BAD_REPORT`: Set to `1` to enable bad domains report generation.

## Input Files

- **`domains.txt`**: List of domains to analyze.
- **`bad.txt`**: List of bad nameservers to flag.
- **`expired.txt`**: Patterns to identify expired nameservers.
- **`same.txt`**: Groups of related nameservers.

## Output Files

- **`report_DATE_TIME.csv`**: Full report with detailed analysis.
- **`Good_DATE_TIME.txt`**: List of good domains.
- **`Bad_DATE_TIME.txt`**: List of bad domains.
- **`errors_DATE_TIME.txt`**: Log of errors encountered during processing.

## How It Works

1. **Load Configurations**: Reads configurations and input files (`bad.txt`, `expired.txt`, `same.txt`).
2. **Fetch Nameserver History**: Calls the CompleteDNS API to fetch nameserver history for each domain.
3. **Analyze Nameservers**:
   - Detects bad nameservers using patterns from `bad.txt`.
   - Flags expired nameservers using patterns from `expired.txt`.
   - Groups related nameservers using `same.txt`.
4. **Generate Reports**:
   - Identifies good and bad domains based on analysis.
   - Writes results to output files.

## Requirements

- Python 3.x
- Required Python libraries:
  - `requests`
  - `pandas`
  - `tldextract`

Install dependencies using:
```bash
pip install requests pandas tldextract
