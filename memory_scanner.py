#!/usr/bin/env python3
import re
import os

def scan_for_patterns(data, patterns):
    findings = []
    for pattern_name, pattern in patterns.items():
        matches = re.finditer(pattern, data)
        for match in matches:
            findings.append({
                'type': pattern_name,
                'offset': match.start(),
                'data': match.group().hex() if isinstance(match.group(), bytes) else match.group()
            })
    return findings

def analyze_memory_dump(file_path):
    patterns = {
        'ip_address': rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'email': rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': rb'https?://[^\s<>"]+|www\.[^\s<>"]+',
        'hex_string': rb'[0-9a-fA-F]{8,}',
        'executable': rb'MZ|ELF'
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        results = scan_for_patterns(content, patterns)
        return results
        
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    target_file = input("Enter memory dump path: ").strip()
    
    if not os.path.exists(target_file):
        print("File not found")
        return
        
    findings = analyze_memory_dump(target_file)
    
    print(f"\nScanning: {target_file}")
    print("=" * 50)
    
    for finding in findings[:20]:
        print(f"{finding['type']}: {finding['data']}")

if __name__ == "__main__":
    main()
