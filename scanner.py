import subprocess
import requests
import os
import json

def is_nmap_installed():
    """
    Check if Nmap is installed and available in PATH.
    """ 
    try:
        subprocess.run(['nmap', '-version'], capture_output=True, text=True, check=True)
        return True
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"Unexpected error while checking Nmap: {e}")
        return False

def run_nmap_scan(target):
    """
    Run an nmap scan on the target host and return open ports.
    """
    try:
        print(f"Scanning {target} for open ports...")
        result = subprocess.run(['nmap', '-sV', '-T4', target], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Nmap: {e}")
    except FileNotFoundError:
        print("Nmap is not installed or not in PATH.")
    except Exception as e:
        print(f"Error: {e}")
    return None

def check_cve_vulnerabilities(service):
    """
    Check CVEs for a specific service using a public vulnerability API.
    """
    print(f"Checking vulnerabilities for {service}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={service}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            cves = response.json().get('result', {}).get('CVE_Items', [])
            for cve in cves:
                print(f"CVE ID: {cve['cve']['CVE_data_meta']['ID']}")
                print(f"Description: {cve['cve']['description']['description_data'][0]['value']}")
                print("="*50)
        else:
            print(f"Failed to fetch CVE data. HTTP Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error fetching CVE data: {e}")

def scan_target(target):
    """
    Perform a vulnerability scan on the given target.
    """
    if not is_nmap_installed():
        print("Nmap is not installed or not in PATH. Please install Nmap and try again.")
        return

    nmap_results = run_nmap_scan(target)
    if nmap_results:
        print("\n=== Nmap Scan Results ===")
        print(nmap_results)
        services = extract_services_from_nmap(nmap_results)
        for service in services:
            check_cve_vulnerabilities(service)
    else:
        print("Failed to get nmap results.")

def extract_services_from_nmap(nmap_output):
    """
    Extract services from nmap output for further analysis.
    """
    services = []
    lines = nmap_output.split("\n")
    for line in lines:
        if "open" in line:
            parts = line.split()
            if len(parts) > 2:
                service = parts[-1]
                services.append(service)
    return services

if __name__ == "__main__":
    print("=== Vulnerability Scanning Tool ===")
    target = input("Enter the target (IP or domain): ").strip()
    scan_target(target)
