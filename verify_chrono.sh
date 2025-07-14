#!/bin/bash

echo "=== Verifying Chronological IDs are Working Correctly ==="
echo ""
echo "Chronological IDs should be:"
echo "- 0 for the oldest file"
echo "- Incrementing for newer files"
echo "- New files should get max_id + 1"
echo ""

# Create a test file
TIMESTAMP=$(date +%s)
TEST_FILE="$HOME/SyftBox/datasites/liamtrask@gmail.com/verify_chrono_${TIMESTAMP}.txt"
echo "Creating test file: verify_chrono_${TIMESTAMP}.txt"
echo "Test content $(date)" > "$TEST_FILE"

echo ""
echo "Instructions to verify:"
echo "1. Open http://localhost:8005/files-widget"
echo "2. Look at the # column"
echo "3. The oldest files should have low numbers (0, 1, 2...)"
echo "4. The newest files should have high numbers"
echo "5. The file we just created (verify_chrono_${TIMESTAMP}.txt) should have the highest number"
echo "6. Open browser console (F12) to see the WebSocket messages"
echo ""
echo "In the console, you should see:"
echo "[WebSocket] Current chronological IDs count: [large number] Max ID: [highest ID]"
echo "[WebSocket] Assigned chronological ID [highest ID + 1] to verify_chrono_${TIMESTAMP}.txt"