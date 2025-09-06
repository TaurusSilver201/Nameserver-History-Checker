# DNS Nameserver History Analyzer

A Python tool for analyzing domain nameserver history to identify potentially malicious or compromised domains based on their DNS hosting patterns.

## Overview

This tool fetches nameserver history data from the CompleteDNS API and analyzes patterns to classify domains as "Good", "Bad", or neutral based on various criteria including:

- Nameserver change frequency
- Usage of known bad or expired nameservers
- Duration of nameserver usage
- Consistency of hosting patterns

## Features

- **Bulk Domain Analysis**: Process multiple domains from a text file
- **Pattern Recognition**: Identify suspicious nameserver patterns
- **Flexible Reporting**: Generate full reports, good domain lists, or bad domain lists
- **Historical Analysis**: Analyze nameserver changes over configurable time periods
- **Error Handling**: Comprehensive error logging for failed API requests

## Installation

### Prerequisites

- Python 3.7+
- CompleteDNS API access

### Dependencies

Install required packages:

```bash
pip install requests pandas tldextract
```

## Configuration

### 1. API Setup

Configure your API credentials by setting these variables in the script:

```python
API_KEY = "your_completedns_api_key"
API_URL = "your_completedns_api_url"
```

### 2. Configuration Files

Create a `config.py` file with report settings:

```python
FULL_REPORT = True   # Generate comprehensive CSV report
GOOD_REPORT = True   # Generate list of good domains
BAD_REPORT = True    # Generate list of bad domains
```

### 3. Required Data Files

Create these files in your project directory:

#### `domains.txt`
List of domains to analyze (one per line):
```
example.com
test-domain.org
suspicious-site.net
```

#### `bad.txt`
Patterns for known bad nameservers:
```
*parking*
*sedo*
*sedoparking*
*banned*
```

#### `expired.txt`
Patterns for expired/renewal nameservers:
```
*whois*
*expired*
*renew*
*domaincontrol*
```

#### `same.txt`
Group similar nameservers (optional):
```
ns1.example.com
ns2.example.com

ns1.hosting.com
ns2.hosting.com
```

## Usage

### Basic Usage

```bash
python dns_analyzer.py
```

### File Structure

```
project/
├── dns_analyzer.py
├── config.py
├── domains.txt
├── bad.txt
├── expired.txt
├── same.txt
└── outputs/
    ├── report_YYYY-MM-DD_YYYYDDMM_HHMMSS.csv
    ├── Good_YYYYDDMM_HHMMSS.txt
    ├── Bad_YYYYDDMM_HHMMSS.txt
    └── errors_YYYY-MM-DD_YYYYDDMM_HHMMSS.txt
```

## Analysis Criteria

### Good Domains
Domains are classified as "Good" if they meet any of these criteria:
- No nameserver changes (Unique NS Changes = 0)
- Current nameserver is in the "good" list
- Longest nameserver duration ≥ 4 years AND current NS = longest NS

### Bad Domains
Domains are classified as "Bad" if they meet any of these criteria:
- 1+ bad nameserver usage
- 2+ expired nameserver events AND current NS ≠ longest NS AND current NS ≠ good NS
- 1 expired NS event AND current NS ≠ longest NS AND current NS ≠ good NS AND 4+ unique NS changes

## Output Files

### Full Report (CSV)
Contains detailed analysis for each domain:
- `Domain`: Domain name
- `Unique NS Changes`: Number of unique nameserver changes
- `Bad NS`: Count of bad nameserver usage
- `Expired NS`: Count of expired nameserver events
- `Longest NS`: Longest-used nameserver and duration
- `Last NS`: Current nameserver
- `Last NS Date`: Date of last nameserver change
- `Last=Longest?`: Whether current NS matches longest-used NS
- `Last=Good?`: Whether current NS is in good list
- `Conclusion`: Final classification (Good/Bad/empty)

### Good/Bad Domain Lists
Simple text files containing domain names classified as good or bad.

### Error Log
Lists domains that couldn't be processed due to API errors.

## Algorithm Details

### Time Period Analysis
- For domains with 8+ years of history: Analyzes last 3 years
- For newer domains: Analyzes last 10 months
- Excludes recent 150 days to avoid incomplete data

### Nameserver Grouping
The tool maps similar nameservers (defined in `same.txt`) to main groups to avoid counting minor variations as separate changes.

### Duration Calculation
Calculates continuous usage periods for each nameserver, accounting for gaps and overlaps in the historical data.

## Limitations

- Requires CompleteDNS API access
- Analysis quality depends on historical data availability
- Pattern matching may need adjustment for different threat landscapes
- Processing time increases with domain count and history depth

## Error Handling

The tool handles various error conditions:
- API request failures
- Invalid domain formats
- Missing historical data
- Network timeouts

Errors are logged to timestamped error files for review.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your chosen license here]

## Support

For issues and questions:
- Create an issue in this repository
- Check the error logs for troubleshooting
- Verify API credentials and data file formats

## Changelog

### v1.0.0
- Initial release
- Basic nameserver history analysis
- Pattern-based domain classification
- Bulk processing capabilities
