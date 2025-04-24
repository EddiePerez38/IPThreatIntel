# src/utils.py
import os
import json
import hashlib
import ipaddress
import socket
import whois
import dns.resolver
import requests
import time
from datetime import datetime
import geoip2.database
from typing import Dict, List, Any, Union, Optional, Tuple

# Path to the GeoIP database file
# You'll need to download this from MaxMind: https://dev.maxmind.com/geoip/geoip2/geolite2/
GEOIP_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                            "data", "GeoLite2-City.mmdb")

def validate_ip(ip_address: str) -> bool:
    """Validate if the string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def get_ip_info(ip_address: str) -> Dict[str, Any]:
    """Get basic information about an IP address"""
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format"}
    
    info = {}
    info['ip'] = ip_address
    
    # Determine IP type
    ip_obj = ipaddress.ip_address(ip_address)
    info['ip_type'] = "IPv4" if ip_obj.version == 4 else "IPv6"
    info['is_private'] = ip_obj.is_private
    info['is_global'] = ip_obj.is_global
    info['is_multicast'] = ip_obj.is_multicast
    
    # DNS lookup
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        info['hostname'] = hostname
    except (socket.herror, socket.gaierror):
        info['hostname'] = None
    
    # Hash the IP for referencing
    info['ip_hash'] = hashlib.md5(ip_address.encode()).hexdigest()
    
    return info

def get_geo_location(ip_address: str) -> Dict[str, Any]:
    """Get geolocation data for an IP address"""
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format"}
    
    geo_info = {}
    
    # Skip geolocation for private IPs
    ip_obj = ipaddress.ip_address(ip_address)
    if ip_obj.is_private:
        geo_info['error'] = "Private IP - geolocation not applicable"
        return geo_info
    
    try:
        if os.path.exists(GEOIP_DB_PATH):
            with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                response = reader.city(ip_address)
                
                geo_info['country'] = response.country.name
                geo_info['country_code'] = response.country.iso_code
                geo_info['city'] = response.city.name
                geo_info['latitude'] = response.location.latitude
                geo_info['longitude'] = response.location.longitude
                geo_info['timezone'] = response.location.time_zone
                
                # Get ASN info if available
                try:
                    with geoip2.database.Reader(GEOIP_DB_PATH.replace('City', 'ASN')) as asn_reader:
                        asn_response = asn_reader.asn(ip_address)
                        geo_info['asn'] = asn_response.autonomous_system_number
                        geo_info['asn_org'] = asn_response.autonomous_system_organization
                except:
                    geo_info['asn'] = None
                    geo_info['asn_org'] = None
        else:
            # Fallback to IP-API if local GeoIP database is not available
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_info['country'] = data.get('country')
                geo_info['country_code'] = data.get('countryCode')
                geo_info['city'] = data.get('city')
                geo_info['latitude'] = data.get('lat')
                geo_info['longitude'] = data.get('lon')
                geo_info['timezone'] = data.get('timezone')
                geo_info['asn'] = data.get('as')
                geo_info['asn_org'] = data.get('isp')
    except Exception as e:
        geo_info['error'] = str(e)
    
    return geo_info

def get_whois_info(ip_address: str) -> Dict[str, Any]:
    """Get WHOIS information for an IP address"""
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format"}
    
    # Skip WHOIS for private IPs
    ip_obj = ipaddress.ip_address(ip_address)
    if ip_obj.is_private:
        return {"error": "Private IP - WHOIS not applicable"}
    
    whois_info = {}
    
    try:
        w = whois.whois(ip_address)
        whois_info['registrar'] = w.registrar
        whois_info['creation_date'] = w.creation_date.isoformat() if w.creation_date and not isinstance(w.creation_date, list) else None
        whois_info['expiration_date'] = w.expiration_date.isoformat() if w.expiration_date and not isinstance(w.expiration_date, list) else None
        whois_info['updated_date'] = w.updated_date.isoformat() if w.updated_date and not isinstance(w.updated_date, list) else None
        whois_info['name_servers'] = w.name_servers
        whois_info['status'] = w.status
        whois_info['emails'] = w.emails
        whois_info['org'] = w.org
    except Exception as e:
        whois_info['error'] = str(e)
        
    return whois_info

def get_reverse_dns(ip_address: str) -> Dict[str, Any]:
    """Get reverse DNS information for an IP address"""
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format"}
    
    reverse_dns = {}
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            reverse_dns['error'] = "Private IP - reverse DNS may not be applicable"
            return reverse_dns
            
        # Perform reverse DNS lookup
        try:
            reverse_dns['ptr_record'] = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            reverse_dns['ptr_record'] = None
        
        # Get all DNS records
        if reverse_dns['ptr_record']:
            try:
                dns_records = {'A': [], 'MX': [], 'TXT': [], 'NS': []}
                
                # Get A records
                try:
                    answers = dns.resolver.resolve(reverse_dns['ptr_record'], 'A')
                    dns_records['A'] = [answer.to_text() for answer in answers]
                except:
                    pass
                    
                # Get MX records
                try:
                    answers = dns.resolver.resolve(reverse_dns['ptr_record'], 'MX')
                    dns_records['MX'] = [answer.to_text() for answer in answers]
                except:
                    pass
                    
                # Get TXT records
                try:
                    answers = dns.resolver.resolve(reverse_dns['ptr_record'], 'TXT')
                    dns_records['TXT'] = [answer.to_text() for answer in answers]
                except:
                    pass
                    
                # Get NS records
                try:
                    answers = dns.resolver.resolve(reverse_dns['ptr_record'], 'NS')
                    dns_records['NS'] = [answer.to_text() for answer in answers]
                except:
                    pass
                
                reverse_dns['dns_records'] = dns_records
            except Exception as e:
                reverse_dns['dns_records_error'] = str(e)
    except Exception as e:
        reverse_dns['error'] = str(e)
    
    return reverse_dns

def check_reputation(ip_address: str) -> Dict[str, Any]:
    """Check reputation of an IP address using public services"""
    if not validate_ip(ip_address):
        return {"error": "Invalid IP address format"}
    
    # Skip reputation check for private IPs
    ip_obj = ipaddress.ip_address(ip_address)
    if ip_obj.is_private:
        return {"error": "Private IP - reputation checks not applicable"}
    
    reputation = {}
    reputation['blacklisted'] = False
    reputation['suspicious'] = False
    reputation['reports'] = []
    
    try:
        # AbuseIPDB API (limited to 1000 queries per day in free tier)
        # You need to sign up for an API key at https://www.abuseipdb.com/
        ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
        if ABUSEIPDB_API_KEY:
            try:
                headers = {
                    'Key': ABUSEIPDB_API_KEY,
                    'Accept': 'application/json',
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90,
                    'verbose': True
                }
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    reputation['abuseipdb_score'] = data.get('abuseConfidenceScore')
                    reputation['abuseipdb_reports'] = data.get('totalReports')
                    
                    if reputation['abuseipdb_score'] > 0:
                        reputation['suspicious'] = True
                        reputation['reports'].append({
                            'source': 'AbuseIPDB',
                            'score': reputation['abuseipdb_score'],
                            'total_reports': reputation['abuseipdb_reports']
                        })
                    
                    # If score is high, mark as blacklisted
                    if reputation['abuseipdb_score'] > 50:
                        reputation['blacklisted'] = True
            except Exception as e:
                reputation['abuseipdb_error'] = str(e)
                
        # VirusTotal API (limited to 500 queries per day in free tier)
        # You need to sign up for an API key at https://www.virustotal.com/
        VT_API_KEY = os.environ.get('VT_API_KEY')
        if VT_API_KEY:
            try:
                headers = {
                    'x-apikey': VT_API_KEY
                }
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    attributes = data.get('attributes', {})
                    stats = attributes.get('last_analysis_stats', {})
                    
                    reputation['virustotal_malicious'] = stats.get('malicious', 0)
                    reputation['virustotal_suspicious'] = stats.get('suspicious', 0)
                    
                    if reputation['virustotal_malicious'] > 0 or reputation['virustotal_suspicious'] > 0:
                        reputation['suspicious'] = True
                        reputation['reports'].append({
                            'source': 'VirusTotal',
                            'malicious': reputation['virustotal_malicious'],
                            'suspicious': reputation['virustotal_suspicious']
                        })
                    
                    # If multiple engines detect as malicious, mark as blacklisted
                    if reputation['virustotal_malicious'] > 2:
                        reputation['blacklisted'] = True
            except Exception as e:
                reputation['virustotal_error'] = str(e)
        
        # If no API keys are set, use a simple IP check against Project Honey Pot
        if not ABUSEIPDB_API_KEY and not VT_API_KEY:
            try:
                # Project Honey Pot check
                octets = ip_address.split('.')
                if len(octets) == 4:  # IPv4 only
                    reversed_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}"
                    try:
                        socket.gethostbyname(f"{reversed_ip}.dnsbl.httpbl.org")
                        reputation['blacklisted'] = True
                        reputation['suspicious'] = True
                        reputation['reports'].append({
                            'source': 'Project Honey Pot',
                            'details': 'IP found in blocklist'
                        })
                    except:
                        pass
            except Exception as e:
                reputation['honeypot_error'] = str(e)
    except Exception as e:
        reputation['error'] = str(e)
    
    return reputation

# Updates to utils.py

def calculate_threat_score(ip_info, geo_info, whois_info, reputation, reverse_dns, ai_analysis):
    """Calculate threat score based on IP characteristics and reputation"""
    score = 0.0
    max_score = 100.0
    
    # Start with a base score of 0
    
    # Check IP type and scope
    ip_obj = ipaddress.ip_address(ip_info['ip'])
    if ip_obj.is_private:
        # Private IPs are less likely to be malicious in terms of external threats
        score += 10
    
    # Calculate reputation score component (0-50 points) - HIGHEST WEIGHT
    reputation_score = 0
    if reputation.get('blacklisted', False):
        reputation_score += 30
    if reputation.get('suspicious', False):
        reputation_score += 10
    if reputation.get('abuseipdb_score'):
        # AbuseIPDB score is 0-100, scale to 0-10
        reputation_score += min(10, reputation.get('abuseipdb_score') / 10)
    if reputation.get('virustotal_malicious'):
        # VirusTotal malicious count, scale appropriately
        reputation_score += min(10, reputation.get('virustotal_malicious') * 2)
    
    # Cap reputation score at 50
    reputation_score = min(50, reputation_score)
    score += reputation_score
    
    # Location risk (0-15 points)
    location_score = 0
    # Some countries are known for hosting more malicious activities
    high_risk_countries = ['RU', 'CN', 'KP', 'IR']  # Example list
    medium_risk_countries = ['UA', 'RO', 'BG', 'ID', 'IN', 'BR']  # Example list
    
    if geo_info.get('country_code') in high_risk_countries:
        location_score += 15
    elif geo_info.get('country_code') in medium_risk_countries:
        location_score += 7
    
    score += location_score
    
    # DNS patterns (0-15 points)
    dns_score = 0
    if reverse_dns.get('ptr_record') is None:
        dns_score += 5  # No reverse DNS is suspicious but common
    elif reverse_dns.get('ptr_record'):
        ptr = reverse_dns.get('ptr_record', '').lower()
        # Check for suspicious patterns in PTR record
        suspicious_patterns = ['dynamic', 'unknown', 'unverified', 'customer', 'host']
        for pattern in suspicious_patterns:
            if pattern in ptr:
                dns_score += 3
                break
    
    # Cap DNS score at 15
    dns_score = min(15, dns_score)
    score += dns_score
    
    # WHOIS timing patterns (0-15 points)
    whois_score = 0
    # Recently registered domains are higher risk
    if whois_info.get('creation_date') and 'error' not in whois_info:
        try:
            creation_date = datetime.fromisoformat(whois_info.get('creation_date'))
            now = datetime.now()
            age_days = (now - creation_date).days
            if age_days < 30:
                whois_score += 15
            elif age_days < 90:
                whois_score += 10
            elif age_days < 180:
                whois_score += 5
        except:
            pass
    
    # Cap WHOIS score at 15
    whois_score = min(15, whois_score)
    score += whois_score
    
    # AI analysis component (0-15 points) - IMPROVED ANALYSIS
    ai_score = 0
    try:
        # Parse the AI analysis for risk indicators
        ai_text = ai_analysis.lower()
        
        # First check for explicit benign indicators that would reduce score
        if 'no clear malicious indicators' in ai_text or 'no indication of' in ai_text or 'benign' in ai_text:
            ai_score = 0
        # Then check for explicit malicious indicators
        elif 'high risk' in ai_text or 'malicious' in ai_text or 'threat actor' in ai_text:
            ai_score += 15
        elif 'medium risk' in ai_text or 'suspicious' in ai_text or 'potentially malicious' in ai_text:
            ai_score += 10
        elif 'low risk' in ai_text:
            ai_score += 5
            
        # Look for mentions of specific threats - only if not already marked as benign
        if ai_score > 0:
            threat_indicators = ['botnet', 'c2', 'command and control', 'ransomware', 'malware', 'phishing', 'scan']
            threat_count = 0
            for indicator in threat_indicators:
                if indicator in ai_text:
                    threat_count += 1
            
            # Add points based on the number of threat indicators found
            ai_score += min(5, threat_count * 2)  # Max 5 additional points
        
        # Cap AI score at 15
        ai_score = min(15, ai_score)
    except:
        ai_score = 0
    
    score += ai_score
    
    # Ensure final score is between 0 and 100
    final_score = max(0, min(max_score, score))
    
    # Determine severity level
    severity = get_severity_from_score(final_score)
    
    # Generate a scoring vector for transparency
    vector = f"SCORE:1.0/REP:{reputation_score}/LOC:{location_score}/DNS:{dns_score}/WHOIS:{whois_score}/AI:{ai_score}"
    
    return {
        "base_score": round(final_score, 1),
        "vector": vector, 
        "severity": severity
    }

def get_threat_actors(ip_info, ttps, reputation, ai_analysis):
    """Attempt to associate IP with threat actors based on TTPs and characteristics"""
    threat_actors = []
    
    # Associate with threat actors based on TTPs
    ttp_ids = [ttp['id'] for ttp in ttps]
    
    # APT mappings (simplified example)
    if "T1071" in ttp_ids and "T1095" in ttp_ids:  # Command and Control patterns
        geo_info = ip_info.get('geo_info', {})
        if geo_info.get('country_code') == 'RU':
            threat_actors.append({
                "name": "APT29",
                "alias": "Cozy Bear",
                "sponsor": "Russia",
                "confidence": "Low",
                "reference": "https://attack.mitre.org/groups/G0016/"
            })
    
    if "T1566" in ttp_ids and "T1204" in ttp_ids:  # Phishing and User Execution
        geo_info = ip_info.get('geo_info', {})
        if geo_info.get('country_code') == 'IR':
            threat_actors.append({
                "name": "APT35",
                "alias": "Charming Kitten",
                "sponsor": "Iran",
                "confidence": "Low",
                "reference": "https://attack.mitre.org/groups/G0107/"
            })
    
    # Check AI analysis for threat actor mentions - IMPROVED DETECTION
    # Only include if the actor is EXPLICITLY mentioned, not just as a word
    ai_text = ai_analysis.lower()
    
    actor_keywords = {
        # Format: keyword: actor info
        # Use more specific phrases to avoid false positives
        "apt29 group": {"name": "APT29", "alias": "Cozy Bear", "sponsor": "Russia"},
        "cozy bear group": {"name": "APT29", "alias": "Cozy Bear", "sponsor": "Russia"},
        "apt28 group": {"name": "APT28", "alias": "Fancy Bear", "sponsor": "Russia"},
        "fancy bear group": {"name": "APT28", "alias": "Fancy Bear", "sponsor": "Russia"},
        "lazarus group": {"name": "Lazarus Group", "alias": "HIDDEN COBRA", "sponsor": "North Korea"},
        "apt41 group": {"name": "APT41", "alias": "BARIUM", "sponsor": "China"},
        "fin7 group": {"name": "FIN7", "alias": "Carbanak", "sponsor": "Criminal"},
        "conti ransomware": {"name": "Conti", "alias": "Wizard Spider", "sponsor": "Criminal"},
        "wizard spider": {"name": "Conti", "alias": "Wizard Spider", "sponsor": "Criminal"}
    }
    
    # Check for negation phrases that would indicate the actor is NOT associated
    negation_phrases = [
        "no indication of",
        "not associated with",
        "unlikely to be",
        "no evidence of",
        "does not appear to be",
        "not linked to"
    ]
    
    # Only include threat actor if explicitly mentioned and not negated
    for keyword, actor_info in actor_keywords.items():
        if keyword in ai_text:
            # Check if the keyword is negated
            is_negated = any(neg_phrase in ai_text[max(0, ai_text.find(keyword)-50):ai_text.find(keyword)] 
                            for neg_phrase in negation_phrases)
            
            if not is_negated and not any(actor['name'] == actor_info['name'] for actor in threat_actors):
                threat_actors.append({
                    "name": actor_info['name'],
                    "alias": actor_info['alias'],
                    "sponsor": actor_info['sponsor'],
                    "confidence": "Low",
                    "note": "Identified through AI analysis",
                    "reference": f"https://attack.mitre.org/groups/{actor_info['name']}/"
                })
    
    return threat_actors

def get_severity_from_score(score):
    """Convert threat score to severity rating"""
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"

def map_to_tactics(ip_info, reputation, ai_analysis):
    """Map IP characteristics to MITRE ATT&CK TTPs"""
    ttps = []
    
    # Network scanning (T1595)
    if any('scan' in report.get('details', '').lower() for report in reputation.get('reports', [])):
        ttps.append({
            "id": "T1595",
            "name": "Active Scanning",
            "url": "https://attack.mitre.org/techniques/T1595/",
            "confidence": "Medium"
        })
    
    # Command and Control (T1071)
    if any('c2' in report.get('details', '').lower() or 'command' in report.get('details', '').lower() 
          for report in reputation.get('reports', [])) or 'command and control' in ai_analysis.lower():
        ttps.append({
            "id": "T1071",
            "name": "Application Layer Protocol",
            "url": "https://attack.mitre.org/techniques/T1071/",
            "confidence": "Medium"
        })
    
    # Phishing (T1566)
    if any('phish' in report.get('details', '').lower() for report in reputation.get('reports', [])) or 'phishing' in ai_analysis.lower():
        ttps.append({
            "id": "T1566",
            "name": "Phishing",
            "url": "https://attack.mitre.org/techniques/T1566/",
            "confidence": "Medium"
        })
    
    # DDoS (T1498)
    if any('ddos' in report.get('details', '').lower() or 'dos' in report.get('details', '').lower() 
          for report in reputation.get('reports', [])) or 'denial of service' in ai_analysis.lower():
        ttps.append({
            "id": "T1498",
            "name": "Network Denial of Service",
            "url": "https://attack.mitre.org/techniques/T1498/",
            "confidence": "Medium"
        })
    
    # Brute Force (T1110)
    if any('brute' in report.get('details', '').lower() or 'bruteforce' in report.get('details', '').lower() 
          for report in reputation.get('reports', [])) or 'brute force' in ai_analysis.lower():
        ttps.append({
            "id": "T1110",
            "name": "Brute Force",
            "url": "https://attack.mitre.org/techniques/T1110/",
            "confidence": "Medium"
        })
    
    return ttps

def get_threat_actors(ip_info, ttps, reputation, ai_analysis):
    """Attempt to associate IP with threat actors based on TTPs and characteristics"""
    threat_actors = []
    
    # Associate with threat actors based on TTPs
    ttp_ids = [ttp['id'] for ttp in ttps]
    
    # APT mappings (simplified example)
    if "T1071" in ttp_ids and "T1095" in ttp_ids:  # Command and Control patterns
        geo_info = ip_info.get('geo_info', {})
        if geo_info.get('country_code') == 'RU':
            threat_actors.append({
                "name": "APT29",
                "alias": "Cozy Bear",
                "sponsor": "Russia",
                "confidence": "Low",
                "reference": "https://attack.mitre.org/groups/G0016/"
            })
    
    if "T1566" in ttp_ids and "T1204" in ttp_ids:  # Phishing and User Execution
        geo_info = ip_info.get('geo_info', {})
        if geo_info.get('country_code') == 'IR':
            threat_actors.append({
                "name": "APT35",
                "alias": "Charming Kitten",
                "sponsor": "Iran",
                "confidence": "Low",
                "reference": "https://attack.mitre.org/groups/G0107/"
            })
    
    # Check AI analysis for threat actor mentions
    actor_keywords = {
        "apt29": {"name": "APT29", "alias": "Cozy Bear", "sponsor": "Russia"},
        "cozy bear": {"name": "APT29", "alias": "Cozy Bear", "sponsor": "Russia"},
        "apt28": {"name": "APT28", "alias": "Fancy Bear", "sponsor": "Russia"},
        "fancy bear": {"name": "APT28", "alias": "Fancy Bear", "sponsor": "Russia"},
        "lazarus": {"name": "Lazarus Group", "alias": "HIDDEN COBRA", "sponsor": "North Korea"},
        "apt41": {"name": "APT41", "alias": "BARIUM", "sponsor": "China"},
        "fin7": {"name": "FIN7", "alias": "Carbanak", "sponsor": "Criminal"},
        "conti": {"name": "Conti", "alias": "Wizard Spider", "sponsor": "Criminal"}
    }
    
    for keyword, actor_info in actor_keywords.items():
        if keyword in ai_analysis.lower():
            # Check if this actor is already in our list
            if not any(actor['name'] == actor_info['name'] for actor in threat_actors):
                threat_actors.append({
                    "name": actor_info['name'],
                    "alias": actor_info['alias'],
                    "sponsor": actor_info['sponsor'],
                    "confidence": "Low",
                    "note": "Identified through AI analysis",
                    "reference": f"https://attack.mitre.org/groups/{actor_info['name']}/"
                })
    
    return threat_actors

def get_recommendation(threat_score, is_blacklisted):
    """Generate recommendation based on threat score"""
    severity = get_severity_from_score(threat_score)
    
    if severity == "CRITICAL" or is_blacklisted:
        return "URGENT: Block this IP address immediately. Add to blocklists across all network devices. Alert security team for investigation. Check for existing connections from this IP in logs."
    elif severity == "HIGH":
        return "HIGH PRIORITY: Block this IP on external-facing systems. Investigate any recent connections from this IP address. Monitor for suspicious activity."
    elif severity == "MEDIUM":
        return "MEDIUM PRIORITY: Consider blocking this IP or implementing additional scrutiny. Monitor for suspicious activities from this IP address."
    else:
        return "LOW PRIORITY: No immediate action required. Add to watchlist for future monitoring if repeated suspicious activity occurs."