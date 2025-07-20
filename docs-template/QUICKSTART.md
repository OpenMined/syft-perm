# Quick Start Guide for Syft-X Documentation Template

## 1. Copy the Template

```bash
cp -r docs-template /path/to/your/syft-x-project/docs
cd /path/to/your/syft-x-project/docs
```

## 2. Create Your Configuration

Create a `config.json` file based on `example-config.json`:

```bash
cp example-config.json config.json
# Edit config.json with your library's information
```

## 3. Generate Documentation

Option A: Using the Python script (recommended)
```bash
python generate_docs.py config.json --output-dir ../docs-output
```

Option B: Manual replacement
- Open each HTML file
- Find and replace all `{{PLACEHOLDER}}` values
- Save the files

## 4. Add Your Assets

- Add your logo to `images/` (keep syftbox-logo.svg)
- Add demo videos/GIFs to `images/`
- Add any screenshots to `images/`

## 5. Test Locally

```bash
cd ../docs-output
python -m http.server 8000
# Open http://localhost:8000
```

## 6. Deploy

For GitHub Pages:
```bash
git add docs-output
git commit -m "Add documentation"
git push
# Enable GitHub Pages in repository settings
```

## Common Customizations

### Change Colors
Edit `css/style.css`:
```css
:root {
    --color-primary: #YourColor;
    --color-secondary: #YourAccent;
}
```

### Add Pages
1. Copy `core-concept.html` as template
2. Update navigation in all HTML files
3. Add to your config.json

### Remove Sections
Simply delete the relevant section from the HTML files.

## Tips

- Keep descriptions concise and benefit-focused
- Use real, working code examples
- Include both simple and advanced examples
- Test on mobile devices
- Maintain OpenMined brand consistency