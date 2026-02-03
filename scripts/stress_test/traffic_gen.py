import requests
import concurrent.futures
import time
import random
import logging
import csv
import sys
import os

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

DATASET_FILE = "traffic_urls.csv"

# Real browser User-Agent to prevent servers from blocking us just because we are a script
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def load_urls_from_csv(filepath):
    """
    Reads the CSV and returns a list of targets.
    Expects CSV columns: 'original_url', 'label'
    """
    if not os.path.exists(filepath):
        logger.error(f"CRITICAL: {filepath} not found inside container.")
        sys.exit(1)

    targets = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                url = row.get('original_url', '').strip()
                label = row.get('label', '').strip().lower()
                
                if not url:
                    continue

                # Ensure URL has schema
                if not url.startswith("http"):
                    url = "http://" + url

                # Map labels to Test Types
                u_type = "GOOD" if label == "benign" else "BAD"
                
                targets.append({
                    "url": url,
                    "type": u_type,
                    "label": label
                })
                
        logger.info(f"Loaded {len(targets)} URLs from {filepath}")
        return targets
    except Exception as e:
        logger.error(f"Error reading CSV: {e}")
        sys.exit(1)

def make_request(target):
    url = target['url']
    u_type = target['type']
    original_label = target['label']
    
    start = time.time()
    result = "UNKNOWN"
    mechanism = "NONE" # NONE, RST, TIMEOUT, HTTP
    
    try:
        # Timeout:
        # 3 seconds is enough for a handshake. 
        # If firewall drops silently, this will raise ConnectTimeout.
        resp = requests.get(url, headers=HEADERS, timeout=3)
        
        # If we reach here, the traffic PASSED.
        duration = (time.time() - start) * 1000
        result = f"ALLOWED ({resp.status_code})"
        mechanism = "HTTP"
        
    except requests.exceptions.ConnectTimeout:
        # Case 1: Silent Drop (NFQUEUE DROP without RST)
        duration = (time.time() - start) * 1000
        result = "BLOCKED (Silent Drop)"
        mechanism = "TIMEOUT"

    except requests.exceptions.ReadTimeout:
        # Case 2: Server accepted connection but didn't send data
        # Rare for firewalling, usually a server issue
        duration = (time.time() - start) * 1000
        result = "BLOCKED (Read Timeout)"
        mechanism = "TIMEOUT"
        
    except requests.exceptions.ConnectionError as e:
        # Case 3: Connection Refused / Reset (The TCP RST Injection)
        duration = (time.time() - start) * 1000
        err_str = str(e).lower()
        
        if "refused" in err_str or "reset" in err_str:
             # This confirms your 'SendTCPReset' code worked
            result = "BLOCKED (TCP Reset)"
            mechanism = "RST"
        else:
            # Could be DNS failure (NameResolutionError) or other network issue
            result = "ERROR (Network/DNS)"
            mechanism = "ERROR"
            
    except Exception as e:
        duration = 0
        result = f"ERROR: {str(e)[:20]}"
        mechanism = "ERROR"

    return result, duration, u_type, url, original_label, mechanism

def run_stress_test(concurrency=10, loops=1):
    all_targets = load_urls_from_csv(DATASET_FILE)
    if not all_targets:
        return

    logger.info(f"🚀 Starting Stress Test: {concurrency} threads, {loops} loops")
    
    # Statistics
    stats = {
        "tp": 0, # Malware Blocked (Success)
        "tn": 0, # Benign Allowed (Success)
        "fp": 0, # Benign Blocked (False Positive)
        "fn": 0, # Malware Allowed (False Negative)
        "mech_rst": 0,     # How many blocks were via TCP Reset
        "mech_timeout": 0, # How many blocks were via Timeout
    }

    total_requests = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        for i in range(loops):
            random.shuffle(all_targets)
            
            # Process simpler chunks
            subset = all_targets[:100] 
            
            logger.info(f"--- Loop {i+1}/{loops} (Sending {len(subset)} requests) ---")

            futures = {executor.submit(make_request, t): t for t in subset}

            for future in concurrent.futures.as_completed(futures):
                res, ms, u_type, url, label, mech = future.result()
                total_requests += 1
                
                is_blocked = "BLOCKED" in res
                
                # Icon Logic & Stat Counting
                icon = "❓"
                
                if u_type == "BAD":
                    if is_blocked:
                        stats['tp'] += 1
                        icon = "🛡️ " # Shield = Protected
                    else:
                        stats['fn'] += 1
                        icon = "❌ " # X = Failure/Danger
                else: # GOOD
                    if is_blocked:
                        stats['fp'] += 1
                        icon = "⚠️ " # Warning = Annoyance
                    else:
                        stats['tn'] += 1
                        icon = "✅ " # Check = Good

                # Mechanism Tracking
                if mech == "RST":
                    stats['mech_rst'] += 1
                elif mech == "TIMEOUT":
                    stats['mech_timeout'] += 1

                # Pad output for readability
                logger.info(f"[{icon}] {label[:8].upper():<8} | {ms:4.0f}ms | {res:<25} | {url}")

    # Final Report
    logger.info("\n" + "=" * 40)
    logger.info(f"TEST COMPLETE. Total Requests: {total_requests}")
    logger.info("-" * 40)
    logger.info(f"🛡️  True Positives  (Malware Blocked): {stats['tp']}")
    logger.info(f"✅  True Negatives  (Benign Allowed):  {stats['tn']}")
    logger.info(f"❌  False Negatives (Malware Missed):  {stats['fn']}")
    logger.info(f"⚠️   False Positives (Benign Blocked):  {stats['fp']}")
    logger.info("-" * 40)
    logger.info("BLOCK MECHANISMS:")
    logger.info(f"⚡ TCP Resets (Active Rejection):      {stats['mech_rst']}")
    logger.info(f"⏳ Timeouts (Silent Drops):            {stats['mech_timeout']}")
    logger.info("=" * 40)

if __name__ == "__main__":
    run_stress_test()