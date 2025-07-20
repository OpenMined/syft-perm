# Syft-X Documentation Template

This is a generic documentation template for creating professional documentation websites for syft-<x> libraries in the OpenMined ecosystem.

## Quick Start

1. Copy the entire `docs-template` folder to your project
2. Find and replace all placeholder values (see below)
3. Add your own images/videos to the `images/` folder
4. Deploy to GitHub Pages or any static hosting service

## Template Structure

```
docs-template/
├── index.html          # Main landing page
├── quickstart.html     # Quick start guide
├── core-concept.html   # Core concept explainer (rename as needed)
├── api/
│   └── index.html     # API reference
├── css/
│   └── style.css      # All styles (OpenMined branded)
├── js/
│   └── main.js        # Interactive features
└── images/
    └── syftbox-logo.svg  # SyftBox logo
```

## Placeholder Values to Replace

### Global Placeholders (used across multiple files)

| Placeholder | Description | Example |
|------------|-------------|---------|
| `{{LIBRARY_NAME}}` | Your library name | `syft-perm` |
| `{{LIBRARY_TAGLINE}}` | Short tagline for browser title | `Syft Permissions Made Simpler` |
| `{{PACKAGE_NAME}}` | PyPI package name | `syft-perm` |
| `{{GITHUB_REPO_NAME}}` | GitHub repository name | `syft-perm` |
| `{{CORE_CONCEPT_PAGE}}` | Filename for core concept page | `permission-reasons` |
| `{{CORE_CONCEPT_TITLE}}` | Navigation title for core concept | `Permission Reasons` |
| `{{HUBSPOT_FORM_ID}}` | HubSpot form ID for newsletter | `b7a08fdc-0fb5-4938-99e8-4a09e7bbc09e` |

### Homepage (index.html) Placeholders

#### Hero Section
- `{{HERO_TITLE}}` - Main headline (e.g., "Syft Permissions Made Simpler")
- `{{HERO_SUBTITLE}}` - Subheadline (e.g., "A friendlier way to manage who can access what in SyftBox")

#### Problem/Solution Comparison
- `{{PROBLEM_LABEL}}` - Label for "before" code (e.g., "🔍 SEE permissions clearly")
- `{{PROBLEM_CODE_EXAMPLE}}` - Code showing the problem/current state
- `{{SOLUTION_LABEL}}` - Label for "after" code (e.g., "🎯 SET permissions simply")
- `{{SOLUTION_CODE_EXAMPLE}}` - Code showing your solution

#### Installation
- `{{INSTALL_NOTE}}` - Note under install command (e.g., "Works with your existing SyftBox setup • No configuration needed")

#### Why Section
- `{{WHY_SUBTITLE}}` - Explanation of why you built this
- `{{VALUE_PROP_1_TITLE}}`, `{{VALUE_PROP_1_DESC}}` - First value proposition
- `{{VALUE_PROP_2_TITLE}}`, `{{VALUE_PROP_2_DESC}}` - Second value proposition
- `{{VALUE_PROP_3_TITLE}}`, `{{VALUE_PROP_3_DESC}}` - Third value proposition

#### Demo Section
- `{{DEMO_SUBTITLE}}` - Description of demo (e.g., "Interactive widgets that make permission management a breeze")
- `{{DEMO_VIDEO_WEBM}}`, `{{DEMO_VIDEO_MP4}}`, `{{DEMO_FALLBACK_GIF}}` - Video files
- `{{DEMO_IMAGE}}` - Static image alternative

#### API Examples
Use the `{{#API_EXAMPLES}}...{{/API_EXAMPLES}}` block to repeat examples:
- `{{EXAMPLE_TITLE}}` - Section title (e.g., "Opening Files & Folders")
- `{{EXAMPLE_CODE}}` - Code example
- `{{EXAMPLE_NOTE}}`, `{{EXAMPLE_LINK}}`, `{{EXAMPLE_LINK_TEXT}}` - Optional link to more info

#### Feature Cards
Use the `{{#FEATURES}}...{{/FEATURES}}` block to repeat features:
- `{{FEATURE_ICON}}` - Emoji or icon
- `{{FEATURE_TITLE}}` - Feature name
- `{{FEATURE_DESC}}` - Feature description

#### Real Example
- `{{REAL_EXAMPLE_TITLE}}` - Section title (e.g., "Under the Hood")
- `{{REAL_EXAMPLE_SUBTITLE}}` - Section description
- `{{REAL_EXAMPLE_CODE}}` - Full code example

#### Tutorial Links
- `{{TUTORIAL_URL}}` - Link to tutorial (optional)
- `{{TUTORIAL_TEXT}}` - Button text for tutorial

### Quick Start Page (quickstart.html)

- `{{QUICKSTART_TITLE}}` - Page title (e.g., "1-Minute Quick Start")
- `{{QUICKSTART_SUBTITLE}}` - Page subtitle

Use the `{{#QUICKSTART_STEPS}}...{{/QUICKSTART_STEPS}}` block to define steps:
- `{{STEP_NUMBER}}` - Step number (2, 3, 4, etc.)
- `{{STEP_TITLE}}` - Step title
- `{{STEP_DESC}}` - Step description (optional)
- `{{STEP_CODE}}` - Code for this step
- `{{#ALT_BG}}` - Add this for alternating background

Next Steps section:
- `{{NEXT_STEPS_TITLE}}` - Section title (e.g., "You're Ready! 🎉")
- `{{NEXT_STEPS_DESC}}` - Section description

Use `{{#NEXT_LINKS}}...{{/NEXT_LINKS}}` for links:
- `{{LINK_ICON}}` - Icon/emoji
- `{{LINK_TITLE}}` - Link title
- `{{LINK_DESC}}` - Link description
- `{{LINK_URL}}` - Link URL
- `{{LINK_STYLE}}` - Button style (btn-primary or btn-secondary)
- `{{LINK_BUTTON_TEXT}}` - Button text

### Core Concept Page (core-concept.html)

- `{{CORE_CONCEPT_HERO_TITLE}}` - Page title
- `{{CORE_CONCEPT_HERO_SUBTITLE}}` - Page subtitle
- `{{INTRO_TITLE}}` - Introduction section title
- `{{INTRO_PARAGRAPH_1}}`, `{{INTRO_PARAGRAPH_2}}` - Introduction paragraphs

Use `{{#CONTENT_SECTIONS}}...{{/CONTENT_SECTIONS}}` for main content:
- `{{SECTION_TITLE}}` - Section title
- `{{SECTION_SUBTITLE}}` - Section subtitle (optional)
- `{{#ALT_BG}}` - For alternating backgrounds

Within sections, use `{{#SECTION_ITEMS}}...{{/SECTION_ITEMS}}`:
- `{{ITEM_TITLE}}` - Item title
- `{{ITEM_DESC}}` - Item description
- `{{ITEM_CODE}}` - Code example
- `{{CODE_LANG}}` - Language for syntax highlighting (python, yaml, etc.)
- `{{NOTE_TYPE}}` - Note style (info, warning, success)
- `{{NOTE_LABEL}}` - Note label (Note, Warning, etc.)
- `{{NOTE_TEXT}}` - Note content

Summary section:
- `{{SUMMARY_TITLE}}` - Summary title
- `{{SUMMARY_SUBTITLE}}` - Summary subtitle

Use `{{#SUMMARY_POINTS}}...{{/SUMMARY_POINTS}}`:
- `{{POINT_ICON}}` - Icon/emoji
- `{{POINT_TEXT}}` - Summary point text

### API Reference (api/index.html)

Use `{{#API_MODULES}}...{{/API_MODULES}}` for modules:
- `{{MODULE_ID}}` - HTML ID for navigation
- `{{MODULE_NAME}}` - Module name
- `{{MODULE_DESC}}` - Short description for TOC
- `{{MODULE_DESCRIPTION}}` - Full description

Within modules, use `{{#MODULE_FUNCTIONS}}...{{/MODULE_FUNCTIONS}}`:
- `{{FUNCTION_SIGNATURE}}` - Full function signature
- `{{FUNCTION_DESC}}` - Function description
- `{{#HAS_PARAMS}}` - Conditional for parameters
- `{{PARAM_NAME}}`, `{{PARAM_TYPE}}`, `{{PARAM_DESC}}` - Parameter details
- `{{#HAS_RETURNS}}` - Conditional for return value
- `{{RETURN_TYPE}}`, `{{RETURN_DESC}}` - Return details
- `{{#HAS_EXAMPLE}}` - Conditional for example
- `{{EXAMPLE_CODE}}` - Example code
- `{{#HAS_NOTE}}` - Conditional for notes
- `{{NOTE_TYPE}}`, `{{NOTE_LABEL}}`, `{{NOTE_TEXT}}` - Note details

## Customization Tips

### Adding New Pages

1. Copy `core-concept.html` as a starting point
2. Update the navigation in all pages
3. Follow the same structure and styling patterns

### Changing Colors

Edit the CSS variables in `style.css`:
```css
:root {
    --color-primary: #4B5563;      /* Main brand color */
    --color-secondary: #10B981;    /* Accent color */
    --color-accent: #3B82F6;       /* Secondary accent */
}
```

### Adding Features

The template supports:
- Video demos (WebM/MP4 with GIF fallback)
- Static image demos
- Code syntax highlighting (Python, YAML)
- Copy-to-clipboard buttons
- Smooth scrolling
- Responsive design
- HubSpot form integration

### Images and Videos

Place all media files in the `images/` folder:
- Use WebM + MP4 for best video compatibility
- Provide GIF fallbacks for email/older browsers
- Keep file sizes reasonable for web performance

## Example Usage

Here's how syft-perm uses this template:

1. **Library Name**: syft-perm
2. **Core Concept**: Permission Reasons
3. **Value Props**: 
   - Works with SyftBox
   - Lowers learning curve
   - Speeds development
4. **API Sections**:
   - Opening files
   - Granting permissions
   - Checking permissions
   - Revoking permissions

## Deployment

1. Replace all placeholders
2. Add your content and images
3. Test locally with a simple HTTP server:
   ```bash
   python -m http.server 8000
   ```
4. Deploy to GitHub Pages or any static hosting

## Best Practices

- Keep the same professional tone and structure
- Use emojis sparingly and consistently
- Provide real, working code examples
- Include both simple and advanced examples
- Make sure all links work
- Test on mobile devices

## Need Help?

- Check the original syft-perm docs for reference
- Join the OpenMined community for support
- Keep the OpenMined branding consistent