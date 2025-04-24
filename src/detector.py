# src/detector.py
import os
import json
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Any, Union, Optional
from utils import (
    validate_ip,
    get_ip_info,
    get_geo_location,
    get_whois_info,
    get_reverse_dns,
    check_reputation,
    calculate_threat_score,
    map_to_tactics,
    get_threat_actors,
    get_recommendation
)

class IPThreatIntelligence:
    def __init__(self, model_name="llama3.2"):
        self.model_name = model_name
        
    def _query_ollama(self, prompt):
        """Query the Ollama model using subprocess"""
        cmd = ["ollama", "run", self.model_name, prompt]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error querying Ollama: {e}")
            print(f"Error output: {e.stderr}")
            return f"Error: {e}"
    
    # Update to detector.py - Improved AI Prompting

    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Analyze an IP address for threat intelligence"""
        if not validate_ip(ip_address):
            return {"error": "Invalid IP address format"}
        
        # Get basic IP info
        ip_info = get_ip_info(ip_address)
        
        # Get geolocation
        geo_info = get_geo_location(ip_address)
        
        # Get WHOIS information
        whois_info = get_whois_info(ip_address)
        
        # Get reverse DNS information
        reverse_dns = get_reverse_dns(ip_address)
        
        # Check reputation
        reputation = check_reputation(ip_address)
        
        # Create improved prompt for AI analysis
        prompt = f"""
        You are a cybersecurity threat intelligence analyst evaluating an IP address. 
        Provide a professional security assessment based on the data below.
        
        IP Information:
        - Address: {ip_address}
        - Type: {ip_info.get('ip_type')}
        - Private: {ip_info.get('is_private')}
        - Hostname: {ip_info.get('hostname')}
        
        Geolocation:
        - Country: {geo_info.get('country')}
        - City: {geo_info.get('city')}
        - ASN: {geo_info.get('asn')}
        - ASN Org: {geo_info.get('asn_org')}
        
        WHOIS Information:
        - Organization: {whois_info.get('org')}
        - Registrar: {whois_info.get('registrar')}
        
        Reputation:
        - Blacklisted: {reputation.get('blacklisted')}
        - Suspicious: {reputation.get('suspicious')}
        - Reports: {', '.join([str(r.get('source', '')) for r in reputation.get('reports', [])])}
        
        Reverse DNS:
        - PTR Record: {reverse_dns.get('ptr_record')}
        
        Based on this information, provide a structured analysis with these sections:
        
        ## Threat Assessment
        [Explicitly state if this IP appears benign, suspicious, or clearly malicious, and explain why]
        
        ## Potential Activities
        [Describe what legitimate or malicious activities this IP might be involved in]
        
        ## Threat Actor Attribution
        [Only if there are strong indicators, identify any potential threat actors or groups that might be associated]
        
        ## Security Recommendations
        [Provide recommendations for handling this IP]
        
        Be specific and factual. Only mention threat actors if there are actual indicators linking to them.
        If there is no evidence of malicious activity, clearly state that the IP appears benign.
        """
        
        # Get AI analysis
        ai_analysis = self._query_ollama(prompt)
        
        # Calculate threat score
        threat_score = calculate_threat_score(
            ip_info, 
            geo_info, 
            whois_info, 
            reputation, 
            reverse_dns, 
            ai_analysis
        )
        
        # Map to MITRE ATT&CK TTPs
        ttps = map_to_tactics(ip_info, reputation, ai_analysis)
        
        # Get threat actors
        actors = get_threat_actors(ip_info, ttps, reputation, ai_analysis)
        
        # Get recommendation
        recommendation = get_recommendation(threat_score['base_score'], reputation.get('blacklisted', False))
        
        # Compile final result
        result = {
            "timestamp": datetime.now().isoformat(),
            "ip_info": ip_info,
            "geo_info": geo_info,
            "whois_info": whois_info,
            "reverse_dns": reverse_dns,
            "reputation": reputation,
            "threat_score": threat_score,
            "ttps": ttps,
            "threat_actors": actors,
            "recommendation": recommendation,
            "ai_analysis": ai_analysis
        }
        
        return result
    
    def save_analysis(self, analysis_result, output_file=None):
        """Save analysis to JSON file"""
        if output_file is None:
            # Generate filename based on the analyzed IP
            ip_address = analysis_result['ip_info']['ip']
            sanitized_ip = ip_address.replace(':', '_').replace('.', '-')
            output_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                "output", 
                f"ip_analysis_{sanitized_ip}_{int(time.time())}.json"
            )
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(analysis_result, f, indent=2)
        
        return output_file

def main():
    """Main entry point for the IP Threat Intelligence"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AI-Powered IP Threat Intelligence Tool")
    parser.add_argument("ip_address", help="IP address to analyze")
    parser.add_argument("--model", default="llama3.2", help="Ollama model to use")
    parser.add_argument("--output", help="Output file path (optional)")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed output")
    
    args = parser.parse_args()
    
    detector = IPThreatIntelligence(model_name=args.model)
    result = detector.analyze_ip(args.ip_address)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    output_path = detector.save_analysis(result, args.output)
    print(f"Analysis saved to: {output_path}")
    
    if not args.quiet:
        # Print summary to console
        print("\n=== IP THREAT INTELLIGENCE SUMMARY ===")
        print(f"IP Address: {result['ip_info']['ip']}")
        print(f"Type: {result['ip_info']['ip_type']}")
        print(f"Location: {result['geo_info'].get('city', 'Unknown')}, {result['geo_info'].get('country', 'Unknown')}")
        print(f"ASN: {result['geo_info'].get('asn_org', 'Unknown')}")
        print(f"Reputation: {'Blacklisted' if result['reputation'].get('blacklisted') else 'Not Blacklisted'}")
        print(f"Threat Score: {result['threat_score']['base_score']} ({result['threat_score']['severity']})")
        print(f"Recommendation: {result['recommendation']}")
        
        if result['ttps']:
            print("\nPotential TTPs:")
            for ttp in result['ttps']:
                print(f"- {ttp['name']} ({ttp['id']})")
        
        if result['threat_actors']:
            print("\nPotential Threat Actors:")
            for actor in result['threat_actors']:
                print(f"- {actor['name']} ({actor['alias']})")
        
        print("\nAI Analysis:")
        print(result['ai_analysis'][:500] + "..." if len(result['ai_analysis']) > 500 else result['ai_analysis'])
        print("\nFor full details, see the JSON output file.")

if __name__ == "__main__":
    main()