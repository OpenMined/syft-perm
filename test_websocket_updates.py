#!/usr/bin/env python3
"""Test WebSocket file updates to verify chronological IDs work correctly."""

import time
import json
import asyncio
import websockets
from pathlib import Path
from datetime import datetime

# Test configuration
WEBSOCKET_URL = "ws://localhost:8005/ws/file-updates"
TEST_DIR = Path.home() / "SyftBox" / "datasites" / "liamtrask@gmail.com"

async def test_websocket_updates():
    """Test that WebSocket updates work correctly."""
    print("Connecting to WebSocket...")
    
    # Track received messages
    received_messages = []
    
    async with websockets.connect(WEBSOCKET_URL) as websocket:
        print("Connected! Creating test file...")
        
        # Create a test file
        test_filename = f"websocket_test_{int(time.time())}.txt"
        test_path = TEST_DIR / test_filename
        
        # Set up message listener
        async def listen():
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    if message != "pong":
                        data = json.loads(message)
                        received_messages.append(data)
                        print(f"\nReceived WebSocket message:")
                        print(f"  Action: {data['action']}")
                        print(f"  File: {data['file']['name']}")
                        print(f"  Path: {data['file']['path']}")
                        if test_filename in data['file']['name']:
                            return data
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    print(f"Error receiving message: {e}")
                    break
        
        # Start listening
        listen_task = asyncio.create_task(listen())
        
        # Wait a bit then create the file
        await asyncio.sleep(1)
        print(f"\nCreating file: {test_path}")
        test_path.write_text(f"Test file created at {datetime.now()}")
        
        # Wait for the message
        try:
            result = await asyncio.wait_for(listen_task, timeout=10.0)
            print(f"\nSuccess! File update received for our test file")
            return result
        except asyncio.TimeoutError:
            print("\nTimeout! No WebSocket message received for our file")
            print(f"Received {len(received_messages)} other messages")
            return None

async def check_widget_state():
    """Check the current state of the widget by looking at the HTML."""
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        async with session.get("http://localhost:8005/files-widget") as response:
            html = await response.text()
            
            # Look for chronological IDs in the HTML
            import re
            chrono_pattern = r'chronologicalIds\[fileKey\] = (\d+);'
            matches = re.findall(chrono_pattern, html)
            if matches:
                max_id = max(int(m) for m in matches)
                print(f"\nCurrent max chronological ID in widget: {max_id}")
                return max_id
            else:
                print("\nNo chronological IDs found in widget HTML")
                return -1

async def main():
    """Run the full test."""
    print("=== WebSocket File Update Test ===\n")
    
    # Check current state
    print("1. Checking current widget state...")
    max_id = await check_widget_state()
    
    # Test WebSocket
    print("\n2. Testing WebSocket file creation...")
    result = await test_websocket_updates()
    
    if result:
        print("\n3. Checking what the widget should show:")
        print(f"   Expected chronological ID for new file: {max_id + 1}")
        print(f"   File details from WebSocket: {json.dumps(result['file'], indent=2)}")
    
    print("\n=== Test Complete ===")
    print("\nTo verify in browser:")
    print("1. Open http://localhost:8005/files-widget")
    print("2. Check if the new test file appears at the top")
    print(f"3. Verify its chronological ID is {max_id + 1}")

if __name__ == "__main__":
    asyncio.run(main())