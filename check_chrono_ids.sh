#!/bin/bash

echo "=== Checking Chronological IDs in Widget ==="
echo ""

# Create a test file
TEST_FILE="~/SyftBox/datasites/liamtrask@gmail.com/chrono_test_$(date +%s).txt"
echo "Creating test file: $TEST_FILE"
echo "Test content $(date)" > $(eval echo $TEST_FILE)

echo ""
echo "Waiting 2 seconds for WebSocket update..."
sleep 2

echo ""
echo "Checking widget HTML for chronological IDs..."
echo ""

# Get the widget HTML and look for chronological ID assignments
echo "Sample of chronological ID assignments in JavaScript:"
curl -s http://localhost:8005/files-widget | grep -A2 -B2 "chronologicalIds\[fileKey\]" | head -20

echo ""
echo "Checking for the newest files in the table:"
curl -s http://localhost:8005/files-widget | grep -A5 "<tbody" | grep -A10 "<tr" | head -30

echo ""
echo "Done!"