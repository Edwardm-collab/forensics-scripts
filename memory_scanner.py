#!/usr/bin/env python3
import re
import os
import mmap  
import contextlib 

def scan_for_patterns(data, patterns):
    """
    This function doesn't need any changes.
    It will scan any data-like object (bytes or mmap)
    that supports the regex interface.
    """
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
            
            with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as content:
                
                results = scan_for_patterns(content, patterns)
                return results
        
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    target_file = input("Enter memory dump path: ").strip()
    
    if not os.path.exists(target_file):
        print("File not found")
        return
        
    print(f"\nScanning: {target_file} (Memory-Efficient Mode)")
    print("=" * 50)
    
    findings = analyze_memory_dump(target_file)

    if isinstance(findings, str):
        print(findings)
        return
    for finding in findings[:20]:
        if isinstance(finding['data'], bytes):
            print(f"{finding['type']}: {finding['data'].decode('utf-8', 'ignore')}")
        else:
            print(f"{finding['type']}: {finding['data']}")

if __name__ == "__main__":
    main()
