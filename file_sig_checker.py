#!/usr/bin/env python3

import struct

def check_file_signature(filename):
    signatures = {
        b"\x89PNG\r\n\x1a\n": "PNG Image",
        b"\xff\xd8\xff": "JPEG Image", 
        b"\x25PDF": "PDF Document",
        b"\x4d\x5a": "Windows Executable",
        b"\x7fELF": "ELF Executable",
        b"\x50\x4b\x03\x04": "ZIP Archive",
        b"\x47\x49\x46\x38": "GIF Image",
        b"\x52\x61\x72\x21": "RAR Archive"
    }
    
    try:
        with open(filename, "rb") as f:
            header = f.read(8)
            
            for signature, file_type in signatures.items():
                if header.startswith(signature):
                    return f"✅ {file_type}"
            
            return f"❌ Unknown | Hex: {header.hex()}"
            
    except FileNotFoundError:
        return "❌ File not found"
    except PermissionError:
        return "❌ Permission denied"

def main():
    print("🔍 File Signature Forensic Tool")
    print("=" * 40)
    
    filename = input("Enter file path: ").strip()
    result = check_file_signature(filename)
    print(f"\nResult: {result}")

if __name__ == "__main__":
    main()
