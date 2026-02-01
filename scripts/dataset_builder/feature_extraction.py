import os
import re
import pandas as pd
from bs4 import BeautifulSoup
import warnings

# Suppress BS4 warnings for malformed HTML
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

# Configuration
DATA_DIR = "./data"
OUTPUT_CSV = "features_dataset_with_url.csv"

# Keywords Lists
KW_MALWARE = ["verify", "account", "suspended", "confirm", "security", "urgent", "update", "locked"]
KW_ADWARE = ["winner", "spin", "bonus", "casino", "prize", "jackpot", "bet", "dating", "girls"]
KW_CRYPTO = ["bitcoin", "crypto", "wallet", "mining", "invest"]
KW_ACTION = ["download", "play", "install", "stream", "free"]

def count_keywords(text, keywords):
    count = 0
    text_lower = text.lower()
    for kw in keywords:
        count += text_lower.count(kw)
    return count

def extract_from_file(filepath, label):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text(" ", strip=True)
        html_len = len(content)
        text_len = len(text_content)

        # 1. SCRIPTS & OBFUSCATION
        scripts = soup.find_all('script')
        script_content = "".join([s.get_text() for s in scripts])
        
        # Regex for common obfuscation/execution patterns
        count_eval = len(re.findall(r'eval\s*\(', script_content))
        count_unescape = len(re.findall(r'unescape\s*\(', script_content))
        count_doc_write = len(re.findall(r'document\.write', script_content))
        count_window_loc = len(re.findall(r'window\.location', script_content))

        # 2. HTML STRUCTURE
        iframes = soup.find_all('iframe')
        forms = soup.find_all('form')
        inputs = soup.find_all('input')
        
        # Hidden Elements
        hidden_elements = soup.find_all(style=re.compile(r'(display:\s*none|visibility:\s*hidden)', re.IGNORECASE))
        hidden_inputs = soup.find_all('input', type="hidden")

        # Password fields
        password_inputs = soup.find_all('input', type="password")

        # 3. META DATA
        meta_tags = soup.find_all('meta')
        title = soup.title.string if soup.title else ""
        
        # 4. LINKS
        all_links = soup.find_all('a', href=True)
        external_links = [l for l in all_links if l['href'].startswith('http')]

        # 5. KEYWORD ANALYSIS
        features = {
            'filename': os.path.basename(filepath),
            'label_class': label,
            
            'html_len': html_len,
            'text_len': text_len,
            'text_ratio': text_len / html_len if html_len > 0 else 0,
            'has_title': 1 if title else 0,
            'title_len': len(title) if title else 0,
            'num_meta_tags': len(meta_tags),
            
            'num_script_tags': len(scripts),
            'script_len': len(script_content),
            'count_eval': count_eval,
            'count_unescape': count_unescape,
            'count_doc_write': count_doc_write,
            'count_redirect': count_window_loc,
            
            'num_iframes': len(iframes),
            'num_forms': len(forms),
            'num_inputs': len(inputs),
            'num_hidden_tags': len(hidden_elements) + len(hidden_inputs),
            'num_password_inputs': len(password_inputs),
            'num_external_links': len(external_links),
            
            'kw_malware': count_keywords(text_content, KW_MALWARE),
            'kw_adware': count_keywords(text_content, KW_ADWARE),
            'kw_crypto': count_keywords(text_content, KW_CRYPTO),
            'kw_action': count_keywords(text_content, KW_ACTION),
        }
        
        return features

    except Exception as e:
        return None

def main():
    data = []
    
    categories = {
        'malware': 'malware',
        'malicious': 'malware',
        'adware': 'adware',
        'benign': 'benign'
    }

    print("Starting Feature Extraction...")
    
    for folder_name, label_class in categories.items():
        folder_path = os.path.join(DATA_DIR, folder_name)
        
        if not os.path.exists(folder_path):
            continue
            
        files = os.listdir(folder_path)
        print(f"Processing {folder_name} ({len(files)} files)...")
        
        for file in files:
            file_path = os.path.join(folder_path, file)
            if not file.endswith('.html'):
                continue
                
            features = extract_from_file(file_path, label_class)
            if features:
                data.append(features)

    df_html = pd.DataFrame(data)
    
    # Check if we have data before proceeding
    if df_html.empty:
        print("No HTML files processed. Exiting.")
        return

    df_html['file_hash'] = df_html['filename'].str.replace('.html', '', regex=False)

    # 2. Load URL Metadata
    metadata_path = os.path.join(DATA_DIR, "dataset_metadata.csv")
    if os.path.exists(metadata_path):
        print("Loading Metadata...")
        df_meta = pd.read_csv(metadata_path)
        
        # 3. MERGE
        df_final = pd.merge(df_html, df_meta, on='file_hash', how='inner')
        
        # --- FIX: SANITIZE DATA BEFORE PROCESSING ---
        # Fill NaN values with empty strings/zeros to prevent "float has no len()" error
        df_final['path'] = df_final['path'].fillna("").astype(str)
        df_final['domain'] = df_final['domain'].fillna("").astype(str)
        df_final['protocol'] = df_final['protocol'].fillna("").astype(str)
        # --------------------------------------------

        # 4. Feature Engineering on URL
        df_final['is_https'] = df_final['protocol'].apply(lambda x: 1 if x == 'https' else 0)
        df_final['domain_len'] = df_final['domain'].apply(len)
        df_final['path_len'] = df_final['path'].apply(len)
        df_final['domain_digits'] = df_final['domain'].apply(lambda x: sum(c.isdigit() for c in x))

        # Drop raw text columns
        drop_cols = ['original_url', 'protocol', 'domain', 'path', 'query', 'file_hash', 'filename', 'label_y']
        df_final.drop(columns=[c for c in drop_cols if c in df_final.columns], inplace=True)
        
        # Rename label_x
        if 'label_class_x' in df_final.columns:
            df_final.rename(columns={'label_class_x': 'label_class'}, inplace=True)
        
        # --- ADD TARGET COLUMNS FOR TRAINING ---
        df_final['target_malware'] = df_final['label_class'].apply(lambda x: 1 if x == 'malware' else 0)
        df_final['target_adware'] = df_final['label_class'].apply(lambda x: 1 if x == 'adware' else 0)

        print(f"Features merged. Final shape: {df_final.shape}")
        
        # Save
        output_path = os.path.join(DATA_DIR, OUTPUT_CSV)
        df_final.to_csv(output_path, index=False)
        print(f"Success! Saved to {output_path}")
        
    else:
        print("Metadata file not found! Training on HTML features only.")

if __name__ == "__main__":
    main()