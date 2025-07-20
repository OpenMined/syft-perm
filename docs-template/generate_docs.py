#!/usr/bin/env python3
"""
Simple documentation generator for syft-x libraries.
Replaces placeholders in template files with values from a configuration file.
"""

import json
import os
import re
import shutil
from pathlib import Path
from typing import Dict, Any, List


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file."""
    with open(config_path, 'r') as f:
        return json.load(f)


def process_template(template: str, config: Dict[str, Any]) -> str:
    """Process a template string, replacing placeholders with config values."""
    
    # Handle simple placeholders like {{LIBRARY_NAME}}
    for key, value in config.items():
        if isinstance(value, (str, int, float)):
            template = template.replace(f"{{{{{key}}}}}", str(value))
    
    # Handle conditional blocks like {{#HAS_PARAMS}}...{{/HAS_PARAMS}}
    def process_conditionals(text: str, data: Dict[str, Any]) -> str:
        # Pattern for conditional blocks
        pattern = r'{{#(\w+)}}(.*?){{/\1}}'
        
        def replace_conditional(match):
            condition = match.group(1)
            content = match.group(2)
            
            # Check if condition is true in data
            if condition in data and data[condition]:
                return content
            else:
                return ''
        
        return re.sub(pattern, replace_conditional, text, flags=re.DOTALL)
    
    # Handle repeated blocks like {{#API_EXAMPLES}}...{{/API_EXAMPLES}}
    def process_loops(text: str, data: Dict[str, Any]) -> str:
        # Pattern for loop blocks
        pattern = r'{{#(\w+)}}(.*?){{/\1}}'
        
        def replace_loop(match):
            loop_var = match.group(1)
            loop_content = match.group(2)
            
            if loop_var in data and isinstance(data[loop_var], list):
                results = []
                for item in data[loop_var]:
                    # Process each item in the loop
                    item_content = loop_content
                    
                    # Replace placeholders within this iteration
                    if isinstance(item, dict):
                        for key, value in item.items():
                            if isinstance(value, (str, int, float)):
                                item_content = item_content.replace(f"{{{{{key}}}}}", str(value))
                        
                        # Process nested conditionals
                        item_content = process_conditionals(item_content, item)
                        
                        # Process nested loops
                        item_content = process_loops(item_content, item)
                    
                    results.append(item_content)
                
                return ''.join(results)
            else:
                # If it's not a loop variable, treat it as a conditional
                return process_conditionals(text, data)
        
        # Process from innermost to outermost
        while re.search(pattern, text, flags=re.DOTALL):
            text = re.sub(pattern, replace_loop, text, flags=re.DOTALL)
        
        return text
    
    # Process loops and conditionals for each major section
    if 'homepage' in config:
        template = process_loops(template, config['homepage'])
        template = process_conditionals(template, config['homepage'])
    
    if 'quickstart' in config:
        template = process_loops(template, config['quickstart'])
        template = process_conditionals(template, config['quickstart'])
    
    if 'core_concept' in config:
        template = process_loops(template, config['core_concept'])
        template = process_conditionals(template, config['core_concept'])
    
    if 'api' in config:
        template = process_loops(template, config['api'])
        template = process_conditionals(template, config['api'])
    
    return template


def generate_docs(config_path: str, template_dir: str, output_dir: str):
    """Generate documentation from templates and configuration."""
    
    # Load configuration
    config = load_config(config_path)
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Copy static assets
    for asset_dir in ['css', 'js', 'images']:
        src = Path(template_dir) / asset_dir
        dst = output_path / asset_dir
        if src.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
    
    # Process HTML templates
    template_files = [
        'index.html',
        'quickstart.html',
        'core-concept.html',
        'api/index.html'
    ]
    
    for template_file in template_files:
        template_path = Path(template_dir) / template_file
        if template_path.exists():
            # Read template
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            # Process template
            processed_content = process_template(template_content, config)
            
            # Determine output path
            if template_file == 'core-concept.html' and 'CORE_CONCEPT_PAGE' in config:
                # Rename core-concept.html to the actual concept page name
                output_file = output_path / f"{config['CORE_CONCEPT_PAGE']}.html"
            else:
                output_file = output_path / template_file
            
            # Create directory if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write processed content
            with open(output_file, 'w') as f:
                f.write(processed_content)
            
            print(f"Generated: {output_file}")
    
    print(f"\nDocumentation generated in: {output_dir}")
    print("\nNext steps:")
    print("1. Add your images/videos to the images/ folder")
    print("2. Review and customize the generated content")
    print("3. Test locally: python -m http.server 8000")
    print("4. Deploy to GitHub Pages or your hosting service")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate syft-x documentation from templates')
    parser.add_argument('config', help='Path to configuration JSON file')
    parser.add_argument('--template-dir', default='.', help='Path to template directory (default: current directory)')
    parser.add_argument('--output-dir', default='./docs', help='Path to output directory (default: ./docs)')
    
    args = parser.parse_args()
    
    generate_docs(args.config, args.template_dir, args.output_dir)


if __name__ == '__main__':
    main()