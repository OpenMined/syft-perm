#!/usr/bin/env python3
import asyncio
import websockets
import json
import time

async def test_websocket():
    uri = "ws://localhost:8005/ws/file-updates"
    print(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected! Waiting for file updates...")
            
            # Send a ping to test
            await websocket.send("ping")
            
            # Listen for messages
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    if message == "pong":
                        print("Received pong")
                    else:
                        data = json.loads(message)
                        print(f"File update: {data['action']} - {data['file']['path']}")
                except asyncio.TimeoutError:
                    print(".", end="", flush=True)
                except Exception as e:
                    print(f"Error: {e}")
                    break
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket())