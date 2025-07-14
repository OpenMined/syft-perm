#!/usr/bin/env python3
"""Example Python file for testing syntax highlighting."""

import os
import sys
from typing import List, Dict, Optional

class TestClass:
    """A test class for syntax highlighting."""
    
    def __init__(self, name: str):
        self.name = name
        self.count = 0
    
    def process_data(self, data: List[Dict[str, any]]) -> Optional[str]:
        """Process some data and return a result."""
        result = []
        
        for item in data:
            if "value" in item:
                # Process the value
                value = item["value"]
                if isinstance(value, str):
                    result.append(value.upper())
                elif isinstance(value, (int, float)):
                    result.append(str(value * 2))
        
        return ", ".join(result) if result else None

def main():
    """Main function."""
    test = TestClass("example")
    sample_data = [
        {"value": "hello"},
        {"value": 42},
        {"value": "world"},
        {"other": "ignored"}
    ]
    
    result = test.process_data(sample_data)
    print(f"Result: {result}")

if __name__ == "__main__":
    main()