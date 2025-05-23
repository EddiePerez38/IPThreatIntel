# AI-Powered IP Threat Intelligence

## Summary
This project is a proof-of-concept AI-powered IP threat intelligence system designed for educational purposes in a blue team cybersecurity exercise. The detector analyzes potentially malicious IP addresses, leveraging both traditional threat intelligence techniques and AI capabilities through Llama 3.2 model integration via Ollama.

The system extracts IP characteristics, geolocates addresses, checks reputation against known blacklists, identifies suspicious patterns, calculates threat scores, and generates security recommendations. Results are provided in a structured JSON format for easy integration with other security tools or reporting systems.

## Dependencies

### Core Libraries
- Python 3.10+
- Ollama with Llama 3.2 model installed
- requests==2.31.0 - HTTP library for API calls
- colorama==0.4.6 - Terminal text coloring
- tqdm==4.66.1 - Progress bars
- rich==13.6.0 - Rich text formatting in terminal

### Data Processing
- numpy==1.26.0 - Numerical processing
- pandas==2.1.1 - Data manipulation

### IP Analysis Specific
- ipaddress==1.0.23 - IP address manipulation
- geoip2==4.7.0 - IP geolocation
- python-whois==0.8.0 - WHOIS lookups
- dnspython==2.4.2 - DNS queries
- aiohttp==3.8.5 - Async HTTP requests

## Installation Instructions

### Setting Up the Environment
1. Clone or download this repository
2. Ensure you have Python 3.10+ installed
3. Set up a virtual environment:

```powershell
# Create and navigate to the project directory
New-Item -Path "C:\Projects\IPThreatIntel" -ItemType Directory
cd C:\Projects\IPThreatIntel

# Clone directories
New-Item -Path "output" -ItemType Directory
New-Item -Path "samples" -ItemType Directory
New-Item -Path "src" -ItemType Directory
New-Item -Path "data" -ItemType Directory

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate
```

4. Install required packages:

```powershell
# Install all dependencies
pip install requests==2.31.0 colorama==0.4.6 tqdm==4.66.1 rich==13.6.0
pip install numpy==1.26.0 pandas==2.1.1
pip install ipaddress==1.0.23 geoip2==4.7.0 python-whois==0.8.0 dnspython==2.4.2 aiohttp==3.8.5
pip install ollama
```

5. Ensure Ollama is installed with Llama 3.2:

```powershell
# Pull the Llama 3.2 model (if not already installed)
ollama pull llama3.2
```

6. Download GeoIP Database (Optional, but recommended):

```powershell
# Download GeoLite2 databases from MaxMind
# You'll need to create a free account at https://dev.maxmind.com/geoip/geoip2/geolite2/
# After registering, download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
# and place them in the data directory
```

## Usage

### Basic Usage
Run the detector against an IP address:

```powershell
python .\src\detector.py 8.8.8.8
```

Example with different model:
```powershell
python .\src\detector.py 45.95.168.17 --model llama3.2
```

### Using Demo Script
The included demo script provides a simpler way to run the detector against multiple IPs:

```powershell
python .\src\run_detector.py
```

### Generating Test Data
You can generate simulated malicious IP samples for testing:

```powershell
python .\samples\ip_generator.py
```

### Output
The detector saves its results as JSON files in the `output` directory. The output includes:
- IP information (address, type, status)
- Geolocation data (country, city, ASN)
- WHOIS information
- Reverse DNS details
- Reputation analysis
- Threat scoring
- MITRE ATT&CK TTPs mapping
- Potential threat actor attribution
- Security recommendations
- AI-powered analysis

## Project Structure

### Directory Structure
```
IPThreatIntel/
├── data/             # GeoIP databases and other reference data
├── output/           # Analysis results saved here
├── samples/          # Sample IP lists and generators
│   ├── ip_generator.py   # Script to generate test data
│   └── ip_samples.txt    # List of IPs for testing
├── src/              # Source code
│   ├── detector.py   # Main detector logic
│   ├── run_detector.py # Demo script
│   └── utils.py      # Utility functions
├── venv/             # Virtual environment
└── README.md         # This file
```

### File Descriptions

#### src/utils.py
Contains utility functions for IP analysis:
- `validate_ip()`: Validates IP address format
- `get_ip_info()`: Extracts basic IP information
- `get_geo_location()`: Retrieves geolocation data
- `get_whois_info()`: Performs WHOIS lookups
- `get_reverse_dns()`: Queries DNS records
- `check_reputation()`: Checks IP against reputation services
- `calculate_threat_score()`: Calculates security threat scores
- `map_to_tactics()`: Maps activity to MITRE ATT&CK framework
- `get_threat_actors()`: Identifies potential threat actors
- `get_recommendation()`: Generates security recommendations

#### src/detector.py
Core IP threat intelligence system:
- `IPThreatIntelligence` class: Main class for IP analysis
- `analyze_ip()`: Orchestrates the analysis process
- `_query_ollama()`: Interfaces with Ollama/Llama 3.2 for AI analysis
- `save_analysis()`: Saves results to JSON
- CLI integration for command-line usage

#### src/run_detector.py
Simple demonstration script that:
- Imports the `IPThreatIntelligence` class
- Reads sample IPs from the samples file
- Runs the detector on multiple IPs and displays results
- Serves as an example of how to use the detector in custom code

#### samples/ip_generator.py
A script that generates simulated malicious IP data:
- Creates realistic IP addresses with different threat profiles
- Generates metadata for scanning, C2, and botnet activities
- Creates both JSON and text files for testing

## Security Note
This tool is designed for educational and ethical security purposes only. The included IP samples are simulations or publicly known addresses. Always ensure you have proper authorization before analyzing any IP addresses or network traffic, and never use these techniques for malicious purposes.

## Threat Scoring System
The detector uses a weighted scoring system similar to CVSS, with scores ranging from 0.0 to 100.0:
- 0.0-25.0: LOW severity
- 25.1-50.0: MEDIUM severity
- 50.1-75.0: HIGH severity
- 75.1-100.0: CRITICAL severity

The score calculation considers factors such as:
- Reputation data from threat intelligence feeds
- Geographic location risk assessment
- DNS patterns and anomalies
- WHOIS registration timing and patterns
- AI analysis of potential threats

## Future Enhancements
Potential improvements for this proof-of-concept:
- Adding active enumeration capabilities
- Enhancing AI model prompt engineering for better analysis
- Integrating with more threat intelligence feeds
- Supporting IPv6 analysis
- Improving threat actor attribution
- Adding temporal analysis to track IP behavior over time
- Implementing a web UI for easier visualization
