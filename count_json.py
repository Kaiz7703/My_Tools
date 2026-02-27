import json
import os
import glob

def count_payloads(folder_path):
    total = 0
    files = glob.glob(os.path.join(folder_path, '*.json'))
    
    print(f"Found {len(files)} JSON files in {folder_path}")
    
    for file in files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                count = len(data)
                total += count
                print(f" - {os.path.basename(file)}: {count:,} requests")
        except Exception as e:
            print(f"Error reading {file}: {e}")
            
    print("-" * 30)
    print(f"TOTAL REQUESTS: {total:,}")

count_payloads('D:/VCS/My_Tools/waf-efficacy-tool/Data/Legitimate')
