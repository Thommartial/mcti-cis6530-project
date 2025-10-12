# python 34_G0086_TEMPVeles_Russia.py

import requests
import csv
import os
from typing import List, Set, Dict, Any

# ==============================================================================
# 1. Configuration and Constants
# ==============================================================================

# 🔑 API Key: Your provided MalwareBazaar Auth-Key.
MALWAREBAZAAR_API_KEY = "INSERT_YOUR_API_KEY"
API_URL = "https://mb-api.abuse.ch/api/v1/" 
MAX_SAMPLES_PER_QUERY = 1000  # Max limit per tag query is 1000

# ==============================================================================
# 2. Extracted Input Data (TEMP.Veles / G0086)
# ==============================================================================

# Input data extracted from the document (34_G0086_TEMPVeles_Russia.docx)
APT_GROUP_INFO = {
    "name": "TEMP.Veles",
    "mitre_id": "G0086", 
    "search_tags": [
        # Primary Identifiers
        "TEMPVeles", "G0086", "XENOTIME", "ATK91",
        
        # Associated Malware and Tools
        "TRITON", "TRISIS", "CATRUNNER", "WMImplant", "cryptcat"
    ]
}

# ==============================================================================
# 3. Core Functions
# ==============================================================================

def get_hashes_for_tag(tag: str, limit: int) -> Set[str]:
    """
    Queries MalwareBazaar for a given tag and returns a set of unique SHA256 hashes.
    """
    unique_hashes = set()
    
    data = {
        "query": "get_taginfo",
        "tag": tag,
        "limit": limit
    }
    
    headers = {
        'API-Key': MALWAREBAZAAR_API_KEY,
        'Accept': 'application/json'
    }
    
    print(f"[*] Querying for tag: {tag}...")
    
    try:
        response = requests.post(API_URL, data=data, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        if result['query_status'] == 'ok':
            for sample in result.get('data', []):
                hash_value = sample.get('sha256_hash')
                if hash_value:
                    unique_hashes.add(hash_value)
            print(f"  [+] Found {len(unique_hashes)} hashes for tag '{tag}'.")
            
        elif result['query_status'] == 'no_results':
            print(f"  [-] No hashes found for tag '{tag}'.")
        else:
            print(f"  [!] MalwareBazaar error for tag '{tag}': {result.get('query_status')}")

    except requests.exceptions.HTTPError as errh:
        print(f"  [CRITICAL] HTTP Error for tag '{tag}': {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"  [CRITICAL] Connection Error for tag '{tag}': {errc}")
    except requests.exceptions.Timeout as errt:
        print(f"  [CRITICAL] Timeout Error for tag '{tag}': {errt}")
    except requests.exceptions.RequestException as err:
        print(f"  [CRITICAL] An unexpected Request Error occurred for tag '{tag}': {err}")
    except Exception as e:
        print(f"  [CRITICAL] An unexpected Error occurred for tag '{tag}': {e}")
        
    return unique_hashes


def get_hashes_for_group(group_info: Dict[str, Any]) -> Set[str]:
    """
    Iterates through all search tags for the APT group and returns a combined set of unique hashes.
    """
    all_hashes = set()
    print(f"[*] Starting hash collection for APT Group: {group_info['name']} ({group_info['mitre_id']})")
    print(f"[*] Search Tags: {', '.join(group_info['search_tags'])}")

    for tag in group_info['search_tags']:
        hashes = get_hashes_for_tag(tag, MAX_SAMPLES_PER_QUERY)
        all_hashes.update(hashes)
        
    print(f"\n[SUMMARY] Total unique hashes collected for {group_info['name']}: {len(all_hashes)} hashes")
    return all_hashes


def write_hashes_to_csv(group_info: Dict[str, str], hashes: Set[str]):
    """
    Creates a CSV file: {APTGroupName}_{MitreID}_SHA256.csv
    """
    name_clean = group_info["name"].replace(" ", "_")
    mitre_id_clean = group_info["mitre_id"].replace(" ", "_")
    filename = f"{name_clean}_{mitre_id_clean}_SHA256.csv"
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['SHA256_Hash']) 
            
            for h in sorted(list(hashes)): 
                csv_writer.writerow([h])
                
        print(f"\n[SUCCESS] Successfully saved {len(hashes)} unique SHA256 hashes to: {os.path.abspath(filename)}")
        
    except Exception as e:
        print(f"[CRITICAL] Failed to write CSV file '{filename}': {e}")


# ==============================================================================
# 4. Main Execution
# ==============================================================================

if __name__ == "__main__":
    
    # Step 1: Gather all unique hashes
    unique_hashes = get_hashes_for_group(APT_GROUP_INFO)
    
    if unique_hashes:
        # Step 2: Write the hashes to the CSV file
        write_hashes_to_csv(APT_GROUP_INFO, unique_hashes)
    else:
        print("[INFO] No unique hashes were collected. Skipping CSV creation.")