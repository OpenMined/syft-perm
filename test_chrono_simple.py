#!/usr/bin/env python3
"""Simple test to check chronological IDs by creating a file and checking the widget."""

import time
import requests
from pathlib import Path
from datetime import datetime

# Create a test file
test_dir = Path.home() / "SyftBox" / "datasites" / "liamtrask@gmail.com"
test_filename = f"chrono_test_{int(time.time())}.txt"
test_path = test_dir / test_filename

print(f"Creating test file: {test_path}")
test_path.write_text(f"Test file created at {datetime.now()}")

print("Waiting 3 seconds for WebSocket update...")
time.sleep(3)

print("\nFetching widget HTML to check...")
try:
    response = requests.get("http://localhost:8005/files-widget")
    html = response.text
    
    # Look for console.log statements that show chronological IDs
    import re
    
    # Find all console.log statements about chronological IDs
    console_logs = re.findall(r"console\.log\('\[WebSocket\][^']*chronological[^']*'[^)]*\);", html)
    if console_logs:
        print("\nFound WebSocket chronological ID logging:")
        for log in console_logs:
            print(f"  {log}")
    
    # Check if our test file appears in the initial data
    if test_filename in html:
        print(f"\n✓ Test file {test_filename} found in widget HTML")
    else:
        print(f"\n✗ Test file {test_filename} NOT found in widget HTML (might need more time)")
        
except Exception as e:
    print(f"Error fetching widget: {e}")

print("\nTo see live updates:")
print("1. Open http://localhost:8005/files-widget in a browser")
print("2. Open the browser console (F12)")
print("3. Create a new file in ~/SyftBox/datasites/liamtrask@gmail.com/")
print("4. Watch for '[WebSocket]' messages in the console")