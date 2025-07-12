package main

import (
	"fmt"
	"github.com/bmatcuk/doublestar/v4"
)

func main() {
	// Test cases to verify wildcard behavior
	tests := []struct {
		pattern string
		path    string
		description string
	}{
		// Original test cases
		{"*.txt", "child/child.txt", "Single wildcard with nested path"},
		{"*.txt", "child.txt", "Single wildcard with direct file"},
		{"**/*.txt", "child/child.txt", "Double wildcard with nested path"},
		{"*/*.txt", "child/child.txt", "Single wildcard pattern with nested"},
		
		// Complex patterns with multiple ** segments
		{"src/**/docs/**/test/*.py", "src/main/docs/api/test/test_api.py", "Multiple ** - deep nesting match"},
		{"src/**/docs/**/test/*.py", "src/legacy/docs/test/basic.py", "Multiple ** - missing middle segment"},
		{"src/**/test/*.py", "src/main/docs/api/test/test_api.py", "Single ** - deep nesting match"},
		
		// Additional edge cases for comprehensive testing
		{"src/**/docs/**/test/*.py", "src/docs/test/file.py", "Multiple ** - minimal path"},
		{"src/**/docs/**/test/*.py", "src/main/other/docs/nested/test/script.py", "Multiple ** - very deep nesting"},
		{"src/**/test/*.py", "src/test/simple.py", "Single ** - minimal path"},
	}

	fmt.Println("Testing doublestar pattern matching:")
	fmt.Println("===================================")
	
	for i, test := range tests {
		match, err := doublestar.Match(test.pattern, test.path)
		if err != nil {
			fmt.Printf("Test %d Error: %v\n", i+1, err)
			continue
		}
		fmt.Printf("Test %d: %s\n", i+1, test.description)
		fmt.Printf("  Pattern: %s\n", test.pattern)
		fmt.Printf("  Path:    %s\n", test.path)
		fmt.Printf("  Match:   %v\n\n", match)
	}
}