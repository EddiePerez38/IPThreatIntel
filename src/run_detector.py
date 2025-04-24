# src/run_detector.py
import os
import json
from detector import IPThreatIntelligence
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

def main():
    """Demo script for the IP Threat Intelligence tool"""
    # Initialize rich console for better output formatting
    console = Console()
    
    # Sample IPs to analyze (we'll read these from the samples file)
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples",
        "ip_samples.txt"
    )
    
    # Create samples directory if it doesn't exist
    os.makedirs(os.path.dirname(sample_path), exist_ok=True)
    
    # Check if sample file exists, if not create it with example IPs
    if not os.path.exists(sample_path):
        # Create a sample file with different types of IPs
        with open(sample_path, 'w') as f:
            f.write("# Known suspicious/malicious IPs for testing\n")
            f.write("185.143.223.19  # Known scanner\n")
            f.write("45.95.168.17    # Potential C2 server\n\n")
            f.write("# Common legitimate IPs for comparison\n")
            f.write("8.8.8.8         # Google DNS\n")
            f.write("1.1.1.1         # Cloudflare DNS\n\n")
            f.write("# Private IP examples\n")
            f.write("192.168.1.1     # Common private router IP\n")
            f.write("10.0.0.1        # Internal network IP\n")
    
    # Load IPs from the sample file
    test_ips = []
    with open(sample_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract IP address (ignore comments)
                ip = line.split('#')[0].strip()
                test_ips.append(ip)
    
    console.print(Panel.fit("IP Threat Intelligence Demo", style="bold blue"))
    console.print(f"Found [green]{len(test_ips)}[/green] IPs to analyze in the sample file\n")
    
    # Initialize the detector
    detector = IPThreatIntelligence(model_name="llama3.2")
    
    # Create a table for results summary
    table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
    table.add_column("IP Address", style="dim")
    table.add_column("Type")
    table.add_column("Location")
    table.add_column("Threat Score", justify="right")
    table.add_column("Severity")
    
    # Analyze each IP
    results = []
    for ip in test_ips:
        console.print(f"Analyzing IP: [cyan]{ip}[/cyan]")
        
        # Analyze the IP
        result = detector.analyze_ip(ip)
        results.append(result)
        
        # Save the analysis
        output_path = detector.save_analysis(result)
        console.print(f"Analysis saved to: [green]{output_path}[/green]")
        
        # Add to summary table
        severity = result.get('threat_score', {}).get('severity', 'UNKNOWN')
        severity_color = {
            'LOW': 'green',
            'MEDIUM': 'yellow',
            'HIGH': 'red',
            'CRITICAL': 'red bold',
            'UNKNOWN': 'dim'
        }.get(severity, 'dim')
        
        table.add_row(
            result['ip_info']['ip'],
            result['ip_info']['ip_type'],
            f"{result['geo_info'].get('city', 'Unknown')}, {result['geo_info'].get('country', 'Unknown')}",
            str(result.get('threat_score', {}).get('base_score', 'N/A')),
            f"[{severity_color}]{severity}[/{severity_color}]"
        )
        
        console.print()
    
    # Print summary table
    console.print("\n[bold]IP Analysis Summary:[/bold]")
    console.print(table)
    
    # Print detailed report for the highest threat IP
    if results:
        highest_threat = max(results, key=lambda x: x.get('threat_score', {}).get('base_score', 0))
        console.print("\n[bold]Detailed Report for Highest Threat IP:[/bold]")
        console.print(Panel.fit(
            f"IP: [bold]{highest_threat['ip_info']['ip']}[/bold]\n"
            f"Score: [bold red]{highest_threat['threat_score']['base_score']}[/bold red] "
            f"({highest_threat['threat_score']['severity']})\n\n"
            f"[bold]Recommendation:[/bold]\n{highest_threat['recommendation']}\n\n"
            f"[bold]AI Analysis:[/bold]\n{highest_threat['ai_analysis'][:500]}...",
            title="Threat Details",
            border_style="red"
        ))
    
    console.print("\n[bold green]Demo complete![/bold green] Results have been saved to the output directory.")

if __name__ == "__main__":
    main()