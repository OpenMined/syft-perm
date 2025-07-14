#!/bin/bash

echo "=== Final Test for Chronological IDs ==="
echo ""

# Create a test file with a unique name
TIMESTAMP=$(date +%s)
TEST_FILE="$HOME/SyftBox/datasites/liamtrask@gmail.com/final_test_${TIMESTAMP}.txt"
echo "1. Creating test file: final_test_${TIMESTAMP}.txt"
echo "Test content $(date)" > "$TEST_FILE"

echo ""
echo "2. File created. The WebSocket should pick this up..."
echo ""
echo "3. To verify the fix is working:"
echo "   - Open http://localhost:8005/files-widget in a browser"
echo "   - Open the browser console (F12)"
echo "   - You should see messages like:"
echo "     [WebSocket] File created: ..."
echo "     [WebSocket] Current chronological IDs count: XXXX Max ID: YYYY"
echo "     [WebSocket] Assigned chronological ID ZZZZ to final_test_${TIMESTAMP}.txt"
echo ""
echo "   - The new file should appear at the top with ID = (highest existing ID + 1)"
echo "   - NOT with ID = 0"
echo ""
echo "4. Create another test file to see IDs increment:"

sleep 2
TIMESTAMP2=$(date +%s)
TEST_FILE2="$HOME/SyftBox/datasites/liamtrask@gmail.com/final_test_${TIMESTAMP2}.txt"
echo "   Creating: final_test_${TIMESTAMP2}.txt"
echo "Test content $(date)" > "$TEST_FILE2"

echo ""
echo "Both files should have incrementing chronological IDs, not 0!"
echo ""
echo "Open http://localhost:8005/files-widget and check the # column"