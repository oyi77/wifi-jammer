# GitHub Pages Documentation

This directory contains the GitHub Pages site for WiFi Jammer.

## Structure

```
docs/
├── index.html              # Homepage
├── usage.html              # Usage guide
├── contribute.html         # Contribution guidelines
├── troubleshooting.html    # Troubleshooting guide
├── demo.html               # Demo page with TUI & GUI examples
├── assets/
│   ├── css/
│   │   └── style.css      # Main stylesheet
│   ├── js/
│   │   └── main.js        # Interactive features
│   └── images/
│       ├── README.md      # Image requirements
│       ├── tui-screenshot.png    # TUI screenshot (add this)
│       └── gui-screenshot.png    # GUI screenshot (add this)
└── _config.yml             # GitHub Pages config
```

## Deployment

### Option 1: Manual Configuration (Recommended)

1. Push the `docs/` folder to your repository
2. Go to repository Settings → Pages
3. Under "Source", select "Deploy from a branch"
4. Select branch: `main` (or your default branch)
5. Select folder: `/docs`
6. Click Save
7. Your site will be available at `https://oyi77.github.io/wifi-jammer/`

### Option 2: GitHub Actions (Automatic)

The repository includes a GitHub Actions workflow (`.github/workflows/pages.yml`) that automatically deploys the site when changes are pushed to the `docs/` directory.

To enable:
1. Go to repository Settings → Pages
2. Under "Source", select "GitHub Actions"
3. The workflow will automatically deploy on push to `main` branch

## Adding Screenshots

1. Capture screenshots of the TUI and GUI interfaces
2. Save them as:
   - `docs/assets/images/tui-screenshot.png`
   - `docs/assets/images/gui-screenshot.png`
3. The HTML pages will automatically display them

See `assets/images/README.md` for more details.

## Local Testing

To test the site locally before deploying:

```bash
# Using Python's built-in server
cd docs
python3 -m http.server 8000

# Or using Node.js http-server
npx http-server docs -p 8000
```

Then open `http://localhost:8000` in your browser.

## Customization

- **Styling:** Edit `assets/css/style.css`
- **JavaScript:** Edit `assets/js/main.js`
- **Content:** Edit the HTML files directly
- **Theme:** Modify CSS variables in `style.css` (`:root` section)

## Notes

- All pages use relative paths, so they work both locally and on GitHub Pages
- The site is fully responsive and mobile-friendly
- Code blocks have copy-to-clipboard functionality
- Expandable sections for better content organization

