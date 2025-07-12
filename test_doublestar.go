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
	}{
		{"*.txt", "child/child.txt"},
		{"*.txt", "child.txt"},
		{"**/*.txt", "child/child.txt"},
		{"*/*.txt", "child/child.txt"},
	}

	fmt.Println("Testing doublestar pattern matching:")
	fmt.Println("===================================")
	
	for _, test := range tests {
		match, err := doublestar.Match(test.pattern, test.path)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		fmt.Printf("Pattern: %-12s Path: %-16s Match: %v\n", 
			test.pattern, test.path, match)
	}
}