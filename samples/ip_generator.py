# samples/ip_generator.py
# This script generates sample IP data files for testing the IP Threat Intelligence tool

import os
import random
import json
from datetime import datetime, timedelta

def generate_malicious_ip_sample():
    """Generate a simulated malicious IP with threat intelligence data"""
    # Create sample IP ranges for different categories
    scanner_ranges = [
        ('45.134.', (0, 255), (0, 255)),   # Example range
        ('185.143.', (200, 255), (0, 255)) # Another example range
    ]
    
    c2_ranges = [
        ('91.219.', (28, 31), (0, 255)),
        ('195.123.', (210, 245), (0, 255))
    ]
    
    botnet_ranges = [
        ('103.107.', (196, 199), (0, 255)),
        ('185.176.', (26, 28), (0, 255))
    ]
    
    # Pick a category and generate an IP
    categories = ['scanner', 'c2', 'botnet']
    category = random.choice(categories)
    
    if category == 'scanner':
        ip_range = random.choice(scanner_ranges)
    elif category == 'c2':
        ip_range = random.choice(c2_ranges)
    else:  # botnet
        ip_range = random.choice(botnet_ranges)
    
    # Generate IP
    prefix = ip_range[0]
    part3 = random.randint(ip_range[1][0], ip_range[1][1])
    part4 = random.randint(ip_range[2][0], ip_range[2][1])
    ip = f"{prefix}{part3}.{part4}"
    
    # Generate metadata
    creation_date = datetime.now() - timedelta(days=random.randint(30, 365))
    first_seen = creation_date + timedelta(days=random.randint(1, 30))
    last_seen = datetime.now() - timedelta(days=random.randint(0, 14))
    
    # Generate ports based on category
    ports = []
    if category == 'scanner':
        # Scanners often check common vulnerable services
        port_options = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
        ports = random.sample(port_options, k=random.randint(3, 6))
    elif category == 'c2':
        # C2 servers often use unusual ports
        port_options = [1024, 4444, 8000, 8008, 8080, 8888, 9000, 50050]
        ports = random.sample(port_options, k=random.randint(1, 3))
    else:  # botnet
        # Botnets may use common ports to blend in
        port_options = [53, 80, 443, 8080]
        ports = random.sample(port_options, k=random.randint(1, 2))
    
    # Generate tags
    tags = [category]
    if category == 'scanner':
        scanner_types = ['port_scanner', 'vulnerability_scanner', 'reconnaissance']
        tags.extend(random.sample(scanner_types, k=random.randint(1, 2)))
    elif category == 'c2':
        c2_types = ['malware_c2', 'ransomware_c2', 'trojan_c2']
        tags.extend(random.sample(c2_types, k=random.randint(1, 2)))
    else:  # botnet
        botnet_types = ['ddos_botnet', 'spam_botnet', 'proxy_botnet']
        tags.extend(random.sample(botnet_types, k=random.randint(1, 2)))
    
    # Generate a threat actor
    threat_actors = [
        {"name": "APT29", "alias": "Cozy Bear", "sponsor": "Russia"},
        {"name": "APT28", "alias": "Fancy Bear", "sponsor": "Russia"},
        {"name": "Lazarus Group", "alias": "HIDDEN COBRA", "sponsor": "North Korea"},
        {"name": "APT41", "alias": "BARIUM", "sponsor": "China"},
        {"name": "FIN7", "alias": "Carbanak", "sponsor": "Criminal"},
        {"name": "Conti", "alias": "Wizard Spider", "sponsor": "Criminal"}
    ]
    
    actor = random.choice(threat_actors)
    
    # Create sample data
    sample = {
        "ip": ip,
        "category": category,
        "tags": tags,
        "creation_date": creation_date.isoformat(),
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "ports": ports,
        "threat_actor": actor,
        "confidence": random.choice(["Low", "Medium", "High"]),
        "ttp_ids": []
    }
    
    # Add TTPs based on category
    if category == 'scanner':
        sample["ttp_ids"] = ["T1595", "T1590"]  # Active Scanning, Gather Victim Network Information
    elif category == 'c2':
        sample["ttp_ids"] = ["T1071", "T1573"]  # Application Layer Protocol, Encrypted Channel
    else:  # botnet
        sample["ttp_ids"] = ["T1498", "T1566"]  # Network Denial of Service, Phishing
    
    return sample

def generate_ip_samples_file(output_dir, count=5):
    """Generate multiple IP samples and save to a JSON file"""
    samples = []
    for _ in range(count):
        samples.append(generate_malicious_ip_sample())
    
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "simulated_malicious_ips.json")
    
    with open(output_file, 'w') as f:
        json.dump(samples, f, indent=2)
    
    print(f"Generated {count} simulated malicious IP samples in {output_file}")
    
    # Also create a simple text file with just the IPs for easy testing
    text_file = os.path.join(output_dir, "ip_samples.txt")
    with open(text_file, 'w') as f:
        f.write("# Generated malicious IP samples\n")
        for sample in samples:
            f.write(f"{sample['ip']}  # {sample['category']} - {', '.join(sample['tags'])}\n")
        
        # Add some legitimate IPs for comparison
        f.write("\n# Legitimate IPs for comparison\n")
        f.write("8.8.8.8         # Google DNS\n")
        f.write("1.1.1.1         # Cloudflare DNS\n")
        f.write("172.217.1.174   # Google\n")
        
        # Add some private IPs
        f.write("\n# Private IPs\n")
        f.write("192.168.1.1     # Common private router IP\n")
        f.write("10.0.0.1        # Internal network IP\n")
    
    print(f"Generated IP list for testing in {text_file}")
    return text_file

if __name__ == "__main__":
    # Get the samples directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(current_dir) != 'samples':
        # If run from elsewhere, find the samples dir
        samples_dir = os.path.join(os.path.dirname(os.path.dirname(current_dir)), 'samples')
    else:
        samples_dir = current_dir
    
    # Generate samples
    generate_ip_samples_file(samples_dir, count=5)